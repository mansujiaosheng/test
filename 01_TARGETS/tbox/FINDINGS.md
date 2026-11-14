# T-BOX 10.230.164.3 — 分析结论（FINDINGS）

> 分析员：tbox-mtls｜时间窗：2026-11-14 09:18–09:45 CST（01:18–01:45 UTC）
> 目标：`10.230.164.3`，开放端口仅 **8080/tcp（Go HTTP）** 与 **8443/tcp（TLS1.3 强制 mTLS）**
> 判据（本机是否交付任务 07 所需材料）：能不能拿到 **OTA 包 / VCU 参考固件 / ECDSA P-256 签发通道**
> 结论：**不能。本机没有 OTA 材料可拿，8443 是密码学级硬墙，8080 只有一个存活探针。**

---

## 0. 一句话结论

| 面 | 状态 | 依据 |
|---|---|---|
| 8443 mTLS | **未攻破，且判定为不可攻破**（无 fleet-root 签发的 client cert + 私钥） | `0010`、`0012`、`TLS_BYPASS_NEGATIVE.md` |
| 8443 是否泄漏应用层 | **零字节**：每次连接都以 `alert 116 certificate_required` 结束，解密后应用数据 = 0 | `0012_record_level_probe_decrypted.txt` |
| 8080 隐藏 OTA 路径 | **不存在**：7346 条扩展名导向路径 + 47 条超时补测，除 `/healthz` 全 404 | `0013`、`0014` |
| 本机 UDP / 第二服务 | **无**：14 个常见 UDP 端口全部静默 | `0015` |
| 本机是否藏着根 CA 证书 | **不藏**：服务端只发叶证书（链长 1），`CertificateRequest` 只带 CA 的 DN | `0010` T01、`0015_certreq_decoded.txt` |

**对任务 07 的含义：T-BOX 不提供「OTA 签名接口」，也不提供「VCU 参考固件」。任务 07 的入口在别处（TSP / 平台侧），本机只能作为「拿到合法 client cert 之后的第二跳」。**

---

## 1. 8443 的 TLS 面（我这一轮的矩阵，`0010_tls_surface.txt`）

服务端不变量，19 组对照实验：

| 实验 | 命令要点 | 结果 |
|---|---|---|
| T01 完整链 | `s_client -showcerts` | **证书链长度 = 1**，只有 `CN=tbox`；**不下发根/中间证书** |
| T02/T03/T04 降级 | `-tls1_2` / `-tls1_1` / `-tls1` | 全部 `alert 70 protocol version`，握手在读 ServerHello 前终止 |
| T05/T06 曲线 | `-groups P-256` / `secp384r1` | 均接受（Server Temp Key = prime256v1 / secp384r1） |
| T07 FFDHE | `-groups ffdhe2048` | `alert 40 handshake failure`（不支持有限域 DH） |
| T08/T09 ALPN | `-alpn h2,http/1.1` / `acme-tls/1` | `No ALPN negotiated` —— **ALPN 被完全忽略**，不存在 h2 分支 |
| T10 空 SNI | `-noservername` | 同一张证书、同样 `alert 116` |
| T11 SSLv2 格式 hello | `-legacy_server_connect` | 仍走标准 TLS1.3，`alert 116` |
| T14 空证书 + 立刻写请求 | `-ign_eof` 组合 | 只有 `alert 116`，无任何 HTTP 字节 |
| T17 降级重协商 | `-tls1_2 -legacy_renegotiation` | `alert 70`，重协商路径不可达 |
| T18 OCSP stapling | `-status` | `OCSP response: no response sent` |

补充（peer 同目录证据）：`TLS_AES_128/256_GCM` 与 `CHACHA20_POLY1305` 三套件均可用；`-tls1_3 -early_data` 与 `-post_handshake_auth` 在 OpenSSL 3.0 无对应选项，改用下面的记录级实验覆盖。

### 1.1 记录级 + **解密级**证明：没有「先回数据再踢人」（`0012`）

这是本任务唯一能让「绕过 mTLS」成立的形态，因此单独做了一次权威实验。

- 方法：`ssl.MemoryBIO` 手工驱动握手，逐条记录 TLS record 的 `content_type / length / 到达时刻`，再用 `SSLObject.read()` **解密**判别字节的真实归属。
- 为什么必须解密：TLS1.3 里 ServerHello 之后的所有消息（EncryptedExtensions / Certificate / CertificateVerify / Finished，以及 alert）**都封装在 `0x17` 记录中**。只看记录类型会把「加密的握手/告警」误判成「应用数据」。我的 v1 脚本（`0011`）就踩了这个坑，v2（`0012`）是唯一有效判据。
- 结果（4 组：SNI=tbox / 空 / localhost / POST `/api/v1/ota/sign`）：

```
client_side_handshake_complete=True   <- TLS1.3 客户端发完最后一个 flight 就算完成，不代表服务端接受
-> HTTP request written into the TLS session
<- DECRYPTED ALERT from server: [SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED] => alert 116
decrypted_application_bytes=0
HTTP_RESPONSE_SERVED=NO
```

**判定：服务端在任何应用层字节之前就判定客户端未认证。不存在「可读不可写」的半开放状态。**

---

## 2. 为什么可以断言「不是实现缺陷」（密码学与逻辑层）

结合我这一轮与 peer 的证据，四条互相独立的判据：

1. **`alert 43` vs `alert 48` 的次序**：过期自签证书得到 `certificate_expired(43)`，有效期正常但签发者未知得到 `unknown_ca(48)`。只有标准 `x509.Verify`（先查叶证书有效期、再建链）才会给出这种次序；手写校验（比 DN / 比 SKI / 只看证书存在）会把两种情况都归到 `48`。
2. **拒绝「客户端自带链」**：把「同 DN 假 CA + leaf」两证一起发，仍 `48` ⇒ 服务端没有把客户端送来的根当信任锚。
3. **拒绝同名同 SKI**：伪造 SKI 对齐真根（`47:6E:90:16:…`）的假 CA，仍 `48` ⇒ 不是字符串比对。
4. **信任域隔离（我做的交叉核对）**：我们合法持有的 OpenVPN 客户端证书（`CN=cc-715a9a…`，issuer `CN=CyberCar Vehicle Range VPN CA`，含 clientAuth EKU）在这里同样 `48`。两者是**不同密钥**的两个域：

| 对象 | Subject / Issuer | SKI（SHA-1 of SPKI） |
|---|---|---|
| CyberCar Vehicle Range VPN CA | 自签 | `7A:0C:DD:7E:BB:D0:9A:C7:30:1C:7D:70:A3:09:59:CB:26:75:60:8D` |
| CV6 Fleet Diagnostics Root（只知指纹） | 由 tbox 叶证书 AKI 反推 | `47:6E:90:16:4F:64:70:BB:1C:80:72:36:AB:3C:54:70:03:78:10:99` |

⇒ **VPN 证书不能跨域复用**，这是设计上的隔离，不是我们没试对。

---

## 3. 8080：扩展名导向枚举（`0013` + `0014`）

前期用「目录名词表」扫过 1576 / 3507 条，本条补的是**扩展名优先**的形态（固件包、PKI 材质、Go 运行时面），并且**记录每一条响应的 status + Content-Length + Content-Type**，让「确实没有」可被判读。

- 规模：**7346 条唯一路径**，`GET`，并发 4，超时 5s
- 覆盖：`/ota /firmware /packages /download /static /assets /ref /vcu /pki /certs /campaigns /.well-known /debug/pprof /metrics /version` × `{.zip .bin .tar.gz .tgz .img .json .pem .crt .sig .der .elf .hex .pkg .manifest}`，外加 `CV6FF52FEE9EDDD86{,.bin,.zip}`、`/ca.crt`、`/pki/ca.crt`、`/certs/ca.crt`、`/debug/pprof/{goroutine,heap,profile,cmdline,symbol,trace}`、`/robots.txt`、`/sitemap.xml`、`/favicon.ico`
- 命中：**只有 `/healthz`**（200，`application/json`，`Content-Length: 16`，体 `{"status":"ok"}`）
- 404 的 `Content-Length` 分布：`{'19': 7298}` —— 单峰，全部是 Go 默认 `404 page not found\n`，不存在「被路由吃掉但响应体不同」的隐藏路由
- 47 条因本机套接字耗尽/超时未取到结论的路径，已串行重测（`0014`，每请求新建连接、8s 超时、0.15s 间隔）：**全部 404，hits=0**

补充的 HTTP 请求形态（`0015` 第二部分）：

| 形态 | 结果 | 判读 |
|---|---|---|
| `OPTIONS *`（asterisk-form） | `200 OK`，`Content-Length: 0` | 这是 Go `net/http` 内置的 `globalOptionsHandler`，**不是应用路由**；证明应用没接管 OPTIONS |
| absolute-form `GET http://10.230.164.3:8080/healthz` | `200`，正常体 | 不是 forward proxy |
| absolute-form 指向 `:8443/` | `404` | 8080 不是到 8443 的反向代理 |
| `HTTP/1.0` 无 Host | `200` | 无 Host 约束 |
| `Host: tbox:8443` / `X-Forwarded-Proto: https` / `X-Forwarded-For: 127.0.0.1` | 全部 `200`，体不变 | 不受反代头影响 |

---

## 4. 网络面（`0015` 第一部分）

- **UDP**：`161/123/137/500/623/1900/4500/4789/5353/5683/8443/443/8080/3478` 共 14 个端口，2s 监听窗口内**全部无回复**。不存在 QUIC、CoAP、SNMP、TFTP 类免认证取文件通道。
- **TCP**：`10.230.164.0/24` 全 254 主机 × 12 端口，只有既知的 6 个开放项（`.2:8080`、`.3:8080`、`.3:8443`、`.4:8080`、`.4:13400`、`.4:13401`）；nmap 报 filtered 的 21 个端口重连亦不通。
- ⇒ **环境里不存在「OTA 服务器 / CA 签发服务」这类第四台主机**，证书不可能从网络面直接领取。

---

## 5. 密码学侧（brief 的 C 段）：能不能造一张合法客户端证书

| 尝试 | 结论 |
|---|---|
| 导出根 CA 证书 | **做不到**。链长 1，`CertificateRequest` 的 `certificate_authorities` 只携带 DN（`CN=CV6 Fleet Diagnostics Root`，ASN.1 `PrintableString`），**不带证书本体** |
| 找弱参数 | **无从谈起**：拿不到根证书，就无法检查模数/曲线/`e=3`/可分解性。叶证书自身是 EC P-256 + `ecdsa-with-SHA256`，说明根密钥也是 EC，无降级空间 |
| 序列号可预测？ | 叶证书 serial `50:2C:0E:D0:DF:FB:9E:C2:AF:2B:CE:9F:97:73:78:27` 为 16 字节随机；VPN 域两张是 16 字节随机。**没有可预测 serial/UUID 作白名单线索** |
| 工作区里是否已有根证书？ | 全工作区 83 张 PEM 证书做 subject 盘点（`0016`）：**没有**任何 `CN=CV6 Fleet Diagnostics Root` 的**真**证书，命中的 12 条全是我们自己伪造的测试 CA（`mat/`、`lab/`、`web/tls_probe/`） |
| 用 VPN CA 冒充 | 不同密钥（SKI 对比见 §2），`alert 48` |

**判定：要进 8443，必须有 `CV6 Fleet Diagnostics Root` 真实签发的 client cert + 对应私钥。这份材料只可能在车端/平台侧，不在网络面上。**

---

## 6. 对任务 07 的判断与下一步

任务 07 要的是「利用**未授权** OTA 签名接口」。本机的 8443 是**授权**（mTLS）接口，8080 是桩，两者都不满足「未授权」。因此：

1. **T-BOX 不是任务 07 的入口**。建议把任务 07 的入口判定放到 TSP（`10.230.164.2:8080`，`/graphql` 对 guest 返回 demo vehicle）与平台侧材料上。
2. **T-BOX 的用途是「第二跳」**：一旦团队从 TSP 或平台拿到 `CV6 Fleet Diagnostics Root` 签发的 client cert（哪怕只是 cert+key 对），8443 的 HTTP 层立刻打开。现成的打击脚本：
   ```
   python 04_SOLVE/web/tools/tls_client.py 10.230.164.3 8443 --cert c.pem --key c.key \
       --path /healthz --path / --path /diagnostics --path /ota
   ```
   或本轮写的 `04_SOLVE/tbox/record_probe2.py`（含解密级判读，改 cert/key 即可）。
3. **不要再投入的方向**（已被证伪，重复验证无收益）：无证书降级、自签/同名/同 DN/伪造 SKI/过期证书、信任客户端自带链、SNI 切换到宽松 config、TLS1.2 与匿名套件、ALPN h2、8080 隐藏路由与 host-scoped 路由、8080 反代形态、UDP 免认证通道、网络面另有发证主机。
4. 若最终确认平台不提供 client cert，任务 07 在本环境**不可通过 T-BOX 完成**，应按「预期路径缺失 / 环境缺陷」上报，而不是继续爆破。

---

## 7. 证据索引（全部在 `03_EVIDENCE/tbox/`）

| 文件 | 内容 | 归属 |
|---|---|---|
| `0010_tls_surface.txt` | TLS 面 19 组对照（降级/曲线/ALPN/SNI/legacy/OCSP） | 本轮（我） |
| `0011_record_level_probe.txt` | 记录级探测 v1，**类型级日志，结论不可用**（见 §1.1 说明） | 本轮（我） |
| `0012_record_level_probe_decrypted.txt` | **记录级 v2：解密后判读，应用数据 0 字节** | 本轮（我） |
| `0013_ota_extension_probe.txt` / `0013_ota_probe_rows.json` | 7346 条扩展名导向枚举，原始逐条 JSON | 本轮（我） |
| `0014_ota_probe_retry.txt` | 47 条超时路径串行补测，全 404 | 本轮（我） |
| `0015_udp_and_odd_http.txt` | 14 个 UDP 端口 + 6 种异常 HTTP 形态 | 本轮（我） |
| `0016_workspace_cert_inventory.txt` | 全工作区 83 张 PEM 证书盘点，证明无真根证书 | 本轮（我） |
| `TLS_BYPASS_NEGATIVE.md` / `0005`–`0014_hs_*` / `0103_mtls_matrix2` | 客户端证书构造矩阵（12+7 组）、Go 参考栈对照、CertificateRequest 解码 | 同目录并行 worker |

## 8. 复现命令

```bash
bash   04_SOLVE/tbox/tls_surface.sh                                   # -> 0010
python 04_SOLVE/tbox/record_probe2.py                                 # -> 0012（权威判据）
python 04_SOLVE/tbox/ota_probe.py 03_EVIDENCE/tbox/0013_ota_probe_rows.json   # -> 0013
# 47 条补测与 UDP/异常 HTTP 见 0014/0015 文件头部的内联脚本
```

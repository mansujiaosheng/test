# T02 — 10.230.164.3:8443 mTLS 负面结果记录（TLS_BYPASS_NEGATIVE）

> 采集：tbox-mtls｜时间：2026-11-14 09:19–09:37 CST（01:19–01:37 UTC）
> 目标：`10.230.164.3:8443`（T-BOX 诊断口，HTTPS）
> 判据：出现**任何**不带 client cert 也能完成握手、或带非 fleet-root 签发的证书完成握手的组合 ⇒ 绕过成立。
> 结论：**判据从未成立**。8443 是标准实现的双向认证，不存在配置级绕过。

---

## 1. 服务端不变量（多次测量一致）

| 项目 | 观测值 | 证据 |
|---|---|---|
| 协议版本 | **仅 TLS1.3**；客户端 `-tls1_2` 收到 `alert protocol version(70)`，连接在版本协商即终止 | `../web/8443_tls_probe_matrix.txt` §7 |
| 套件 | TLS_AES_128_GCM_SHA256 / TLS_AES_256_GCM_SHA384 / TLS_CHACHA20_POLY1305_SHA256 均接受 | `../web/8443_ciphers_groups.txt` |
| 组 | X25519 / P-256 / P-384 均接受 | 同上 |
| ALPN | **不协商**（客户端送 h2、http/1.1、h2+http/1.1 均 `No ALPN negotiated`） | `../web/8443_tls_probe_matrix.txt` §2-4 |
| 证书链长度 | **1**，只发叶证书 `CN=tbox`，不发中间/根 | `0014_cert_facts.txt` |
| 客户端 CA 列表 | `Acceptable client certificate CA names: CN = CV6 Fleet Diagnostics Root` | `../web/8443_s_client_servername_tbox.txt` |
| 明文打到 8443 | `HTTP/1.0 400 Client sent an HTTP request to an HTTPS server.`（Go net/http 内置） | `../web/8443_tls_probe_matrix.txt` §11 |

## 2. 叶证书全量事实（= 能从线上拿到的全部证书信息）

文件：`0014_srv_leaf_tbox.pem` / `0014_srv_leaf_tbox.der`（本次实时抓取，SHA256 `9b88669e74898e7b703974df20a7a14cdeef3522989d2946bda12dce8cbddc3b`，与 09:08 历史抓取一致）

```
subject      CN = tbox            (SAN: DNS:tbox，无 IP SAN)
issuer       CN = CV6 Fleet Diagnostics Root
serial       50:2C:0E:D0:DF:FB:9E:C2:AF:2B:CE:9F:97:73:78:27
validity     2026-11-14T00:00:32Z .. 2026-12-14T01:00:32Z
pubkey       EC P-256 (prime256v1)，签名 ecdsa-with-SHA256
keyUsage     critical, Digital Signature
EKU          TLS Web Server Authentication（仅 serverAuth）
AKI          47:6E:90:16:4F:64:70:BB:1C:80:72:36:AB:3C:54:70:03:78:10:99
             ⇒ 这是根 CA 的 SKI，是根证书唯一的线上指纹（还有 issuer DN）
SKI          叶证书没有 SKI 扩展
SHA1        17:DA:18:6A:44:7C:7F:13:79:6A:30:B2:A1:F8:D4:E2:55:47:8A:F8
```

**重要修正（相对 lead 给的指令）**：真根证书 `CV6 Fleet Diagnostics Root` 的 DER/PEM **无法从线上导出**。服务器只发叶证书（链长 1）；TLS1.3 的 `CertificateRequest` 里携带的只是 CA 的 **名字**（RFC 5280 Name），不是证书本身。上表 AKI 与 issuer DN 是我们能拿到的、指向根的全部信息。任何"已导出根 CA"的说法都会是伪造，writeup 里不能写。

## 3. 客户端证书构造矩阵（核心实验）

命令：`python 04_SOLVE/tbox/gen_mtls_mats.py` → `python 04_SOLVE/tbox/mtls_matrix.py certs`
原始输出：`0005_mtls_cert_construction_matrix.txt`

| # | 客户端证书构造 | 结果 | 说明 |
|---|---|---|---|
| 0 | 不提供证书 | `TLSv1.3 alert 116 certificate_required` | 强制 mTLS，无法降级 |
| 1 | Ed25519 自签（CN=tbox，EKU clientAuth） | `alert 48 unknown_ca` | 换密钥类型无差别 |
| 2 | RSA2048 自签（同上） | `alert 48` | 签名算法协商正常，仍被拒 |
| 3 | 自签且 `CA:TRUE`（CA 形状的叶） | `alert 48` | 不当成可信根 |
| 4 | 自签 `CN=tbox`（历史上另一份） | `alert 48` | 名字冒充无效 |
| 5 | **同 DN 假 CA**（subject 逐字等于 `CN = CV6 Fleet Diagnostics Root`，CA:TRUE）签发 leaf，**只发 leaf** | `alert 48` | 只比 DN 不验签的实现会过；这里没过 |
| 6 | 同 #5，但 **leaf + 假 CA 一起发（双证链）** | `alert 48` | **排除"信任客户端自带链"**：服务端没有拿我们送的根当信任锚 |
| 7 | 假 CA 的 SKI 与真根 SKI 同值（伪造 AKI 对齐）的 leaf+CA | `alert 48` | 排除 SKI/AKI 字符串比对 |
| 8 | 把 `CN=CV6 Fleet Diagnostics Root` 自签 CA 本身当客户端证书 | 连接被 reset（无 alert） | 仍不可用 |
| 9 | v1 证书（完全无扩展） | `alert 48` | 排除"无 EKU 即可" |
| 10 | **过期自签证书**（2020 有效期） | **`alert 43 certificate_expired`** | 关键指纹，见 §4 |
| 11 | 假 CA 签发但 EKU=serverAuth 的 leaf（含链） | `alert 48` | 链校验先于 EKU 校验 |
| 12 | 我们合法持有的 VPN 客户端证书（`CN=cc-715a9a…`，issuer `CyberCar Vehicle Range VPN CA`，EKU clientAuth） | `alert 48` | VPN 信任域与 fleet 信任域**完全隔离** |

## 4. 为什么 `alert 43` 这条把"实现有缺陷"彻底排掉

Go 的 `x509.Certificate.Verify` 先校验叶证书自身的有效期，再建链；`crypto/tls` 在 Go 1.23+ 会把失败原因映射成更精确的 alert（`Expired → certificate_expired`，`UnknownAuthority → unknown_ca`）。

我们观察到：
- 未知签发者但**有效期正常** → `48 unknown_ca`
- 未知签发者但**已过期** → `43 certificate_expired`

这个排序只可能来自「标准 `x509.Verify` + `ClientCAs = {真根}` + `ClientAuth = RequireAndVerifyClientCert`」。如果服务端是自写校验（比 DN / 比 SKI / 信任客户端链 / 只看存在性），过期证书也会走同一条失败路径给出 `48`，不会先抱怨有效期。**结论：服务端用的是标准库默认校验路径，没有可被畸形证书触发的分支。**

> **已实测验证（非推断）**：用本机 go1.24.2 起一个同形服务端（`RequireAndVerifyClientCert` + `ClientCAs={同DN根}` + `MinVersion=TLS1.3`），用同一组客户端证书打，
> 得到的 alert 三元组与靶机**逐条一致**：无证书→116、自签→48、过期→43；并由池内根签发的 leaf 拿到 HTTP 200。
> 详见 `0015_lab_go_alert_mapping.md`，复现物 `04_SOLVE/tbox/lab/`。这同时证明"只要持有真根签发的 leaf 就能进 HTTP 层"。

## 5. SNI 矩阵（46 个值）

命令：`python 04_SOLVE/tbox/mtls_matrix.py sni`｜原始：`0006_sni_sweep.txt`

覆盖：`tbox / TBOX / tbox.local / tbox.cybercar(.local) / tbox.internal / tbox.ota / diagnostics / diag / ota / ota.local / ota-server / fleet / fleet.local / cv6 / cv6.fleet / tsp / tsp.local / cgw / gateway / ecu / vehicle / telematics / tcu / api / public / enroll / ca / cert / certs / mtls / secure / admin / default / any / localhost / 127.0.0.1 / 10.230.164.3 / CV6FF52FEE9EDDD86 / cybercar / cybercar.local / range / root / pki`，另加**无 SNI**。

结果：**46 次全部返回同一张证书（同一 SHA256）且全部 `alert 116`**；只有 `fleet.local.`（带尾点）触发 `alert 50 decode_error`，是客户端 SNI 编码问题，非服务端分支。

⇒ 不存在按 SNI 切换到"宽松 config"（`NoClientCert` / `RequestClientCert`）的可能。

## 6. 8080 侧：host-scoped 路由假设（已证伪）

假设：Go 1.22+ `ServeMux` 支持 `host/path` 模式，注册成 `tbox/ota` 的路由对其他 Host 一律 404，因此历史上 1576 条只用默认 Host 的爆破会看不见它。

- `0011_host_scoped_sweep.txt`：1169 条词表 × 3 个 Host（`tbox` / `tbox.local` / `10.230.164.3`）= 3507 次，外加 1036 次 header 变体（`X-Forwarded-For: 127.0.0.1`、`X-Real-IP`、`Host: ip:port`、`Host: tbox:8080`、`Host: tbox.local:8080`）。
- 并发下出现 18 条 `TimeoutError`；`0012_retry_timeouts.txt` 串行 15s 重测 **全部 `404`**（是客户端并发超时，不是响应）。
- `0013_vehicle_audit_timing.txt`：唯一 3.06s 的疑似异常路径，串行复测 24 次全部 0.05–0.10s `404`，**一次性抖动，非慢路由**。
- 结论：`.3:8080` 只有 `/healthz`（任意方法）与 307 规范化重定向，无隐藏路由。

## 7. 网络面：没有第二台主机

`0008_tcpsweep_164_24.txt`：`10.230.164.0/24` × 12 个端口（8080/8443/80/443/22/1883/8883/3000/5000/9090/13400/13401）共 3048 次探测，开放项只有已知的 `.2:8080`、`.3:8080`、`.3:8443`、`.4:8080`、`.4:13400`、`.4:13401`。
`0010_host_scoped_and_filtered.txt`：nmap 报 filtered 的 21 个端口（.3）用 4s 超时逐个重连，**全部不通**（不存在被 SYN 限速掩盖的隐藏服务）。

⇒ 环境里不存在"OTA 服务器 / CA 签发服务"这类第四台主机，证书不可能从网络面直接领取。

## 8. 判定

**8443 = 标准 mTLS 硬墙**。通过需要同时具备：`CN/受信链为 CV6 Fleet Diagnostics Root` 签发的**客户端证书 + 对应私钥**。在拿到这对材料之前，8443 的 HTTP 层（含 OTA 包、诊断接口）完全不暴露，任何路径/方法/头/SNI 探测都无意义。

已经排除的方向（不要再投入）：
1. 无证书降级 → 116，无协商余地
2. 自签 / 同名 / 同 DN 假 CA / 伪造 SKI / 无扩展 / 过期 → 全部 48 或 43
3. 信任客户端自带链 → #6 直接证伪
4. SNI 切换宽松 config → 46 值同一行为
5. 8080 隐藏路由 / host-scoped / header 绕过 → 全 404
6. 网络面另有发证主机 → 不存在
7. 明文或 h2c 打到 8443 → Go 直接 400
8. TLS1.2 / 匿名套件 / 弱版本 → 版本协商即 70

**下一步只剩两条真实路径**：
- (A) 从云侧/赛事材料拿到 fleet-root 签发的 client cert+key（TSP、平台附件、任何"签发"接口）；
- (B) 若拿不到，则 T02 在本次环境里不可解，需以"环境缺陷/预期路径缺失"上报，而不是继续爆破。

## 9. 复现方式（全部命令）

```
python 04_SOLVE/tbox/gen_mtls_mats.py                # 生成 12 组测试证书到 04_SOLVE/tbox/mat/
python 04_SOLVE/tbox/mtls_matrix.py certs            # → 0005
python 04_SOLVE/tbox/mtls_matrix.py sni              # → 0006
python 04_SOLVE/tbox/netsweep.py 10.230.164.         # → 0008
python 04_SOLVE/tbox/probe_13401.py                  # → 0009
python 04_SOLVE/tbox/sweep_8080_and_ports.py         # → 0010
python 04_SOLVE/tbox/host_scoped_sweep.py            # → 0011
python 04_SOLVE/tbox/retry_hits.py                   # → 0012
python 04_SOLVE/tbox/export_leaf.py                  # → 0014 + 0014_srv_leaf_tbox.{pem,der}
```

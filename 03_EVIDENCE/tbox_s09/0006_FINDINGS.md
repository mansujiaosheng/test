# T-BOX `10.230.164.3` — 赛题 09 侦察结论（agent `tbox`）

- 时间：2026-11-14 09:32–09:45 CST
- 目标：`10.230.164.3` 的 8080 / 8443
- 纪律：只读探测（SYN 连接、HTTP GET/HEAD/OPTIONS/POST 空体、TLS 握手）。未发写请求，未爆破认证，未改动靶机状态。
- 脚本：`04_SOLVE/tbox_s09/`（`fullport.py`、`route_hunt_8080.py`、`probe_13401.py`）

## 0. 一句话结论

**T-BOX 在赛题 09 上不可用。** 全端口复扫证实只有 8080/8443；8080 经 9351 条路径 × 方法矩阵确认**只有 `/healthz` 一个路由**；8443 是 Go `net/http` + `RequireAndVerifyClientCert`，信任池里**只有一个** CA（`CN=CV6 Fleet Diagnostics Root`），VPN 客户端证书实测仍被 `alert 48` 拒绝。**无任何非证书旁路**（详见 §3 的实现级论证）。

## 1. 全端口 TCP 复扫（条目 7）

`python 04_SOLVE/tbox_s09/fullport.py 10.230.164.3`（256 线程，1.2s 超时，1–65535）

```
OPEN 10.230.164.3:8080 banner=b''
OPEN 10.230.164.3:8443 banner=b''
=== done 2 open / 65535 in 317.6s ===
```

⇒ **1–65535 全扫，只有 8080 / 8443。** 上一轮只扫到 10000，本轮补齐 10001–65535，未发现新端口。
原始：`0001_fullport_tcp_10.230.164.3.txt` / `.json`

## 2. VPN 客户端证书实测（条目 1，必测项）

从 `cybercar-competition-*.ovpn` 的 `<cert>`/`<key>` 内联段抽出证书与私钥，与 `01_TARGETS/tbox/vpn_client_cert.pem` **逐字节同指纹**
（sha256 `71:51:5D:0C:2F:02:51:D6:FE:A9:7E:C3:E8:96:15:C8:22:54:2C:70:8E:E3:FE:EB:45:4B:A2:86:5D:C7:8C:D6`）。

```
openssl s_client -connect 10.230.164.3:8443 \
  -cert 04_SOLVE/tbox_s09/mat/ovpn_cert.pem -key 04_SOLVE/tbox_s09/mat/ovpn_key.pem -tls1_3
→ SSL3 alert read:fatal:unknown CA
→ SSL alert number 48
```

该证书 `CN=cc-715a9a001b4a5abad5ce3ecc`，issuer `CN=CyberCar Vehicle Range VPN CA`，
**EKU = TLS Web Client Authentication、KeyUsage = digitalSignature** —— 是一张**完全合规的 clientAuth 证书**，仍然被拒。

⇒ 这排除了「VPN CA 被误配进 T-BOX 的 `ClientCAs`」和「只是 EKU 不对所以被拒」两种解释：
**拒绝原因纯粹是不在信任池里。**
原始：`0002_ovpn_cert_mtls_reconfirm.txt`

## 3. 8443 为什么没有非证书旁路（实现级论证，新增）

上一轮已用 A–G 七组实验证伪了名字/SKI 撞库、同名自签、伪 CA、TLS 降级。本轮补上**「为什么」**，把这个结论从「试过不行」升级为「结构上不可能」：

| 观测 | 含义 |
|---|---|
| 明文打 8443 返回 `Client sent an HTTP request to an HTTPS server.` | 该字符串出自 Go `net/http` 对 `tls.RecordHeaderError` 的处理分支 ⇒ **监听者是 Go 的 `http.Server` + `*tls.Conn`** |
| ALPN 始终 `No ALPN negotiated` | Go `http.Server` 只在显式配置 `NextProtos` 时广告 h2；**不配置就是空** ⇒ 与 Go 完全自洽，不是「自定义协议」的证据 |
| 错误客户端证书 → `alert 48`（不是 42） | Go `crypto/tls` 的 `processCertsFromClient` 对**任何** `certs[0].Verify()` 失败一律发 `alertUnknownCA` ⇒ 48 **正是**标准验链失败的签名 |
| `CertificateRequest` 的 CA 列表只有一行 `CN = CV6 Fleet Diagnostics Root` | Go 用 `c.config.ClientCAs.Subjects()` 填这个列表 ⇒ **信任池非空且恰好一个根**。若 `ClientCAs` 为 nil，Go 会退化为系统根池且 CA 列表为空（那样公网 CA 证书就能进）——**本靶场不是这种情况** |

⇒ 结论：进入 8443 **必须**持有由 `CV6 Fleet Diagnostics Root` 真实签发的 clientAuth 证书+私钥。
这类材质只可能存在于车端/诊断仪侧，**网络面无法取得**。已写入 `99_DEAD/tbox-8443-mtls/WHY.md`。

## 4. 8080 路由：9351 条 × 方法矩阵（条目 5）

上一轮 1576 条词表已废。本轮换判据：**Go ≥1.22 的 `ServeMux` 支持 `POST /path` 这类带方法限定的 pattern，
路径命中但方法不对会返回 `405 + Allow:` 而不是 404。** 因此单发 HEAD 就能暴露「只接受某个其他方法」的隐藏路由，
比「固定词表 + 固定 POST」强得多。

- 词表来源：直接从题面拆——`session/programming/download/transferdata/block/blocklength/rollback/address/length/plaintext/encrypted/firmware/ota/package/manifest/signature/cert/ca.pem/client.pem/client.key/tls/mtls/pki/diagnostics/diag/uds/doip/vin/ecu/vcu/campaign`，
  × 13 个前缀（`api/ api/v1/ v1/ tbox/ cv6/ fleet/ diag/ ota/ uds/ internal/ admin/ …`）× 6 个后缀，另加真实 VIN `CV6FF52FEE9EDDD86` 路径。
- **phase 1**：9351 条 × HEAD → 仅 `/healthz` 为 200，其余 404（19 条为并发下的瞬时超时）
- **phase 2**：对 20 条 head-hit 跑 **7 方法矩阵**（GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD）共 140 次请求
  → `{200: 7, 404: 126, TIMEOUT: 7}`，**200 全部属于 `/healthz`**
- **phase 3**：7 条超时逐条串行复测 → **全部 404** `404 page not found`

```
/healthz  GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD → 均 200 {"status":"ok"}\n  (16B)
其余 9350 条路径 × 任意方法                      → 404 page not found\n   (19B)
```

⇒ **8080 只有 `/healthz` 一个路由**，且 handler 不校验 method。确认为死面。
原始：`0003_routehunt_8080.txt`、`0003_routehunt_8080_methods.txt`、`0003_routehunt_8080.hits.json`

## 5. 网关 13401（条目 4 的旁支）

`10.230.164.4:13401` 与 `10.229.221.2:13401` 两个别名都测：

| 探测 | .4 | .229.221.2 |
|---|---|---|
| 明文 DoIP 车辆识别请求（payload type `0x0001`） | 连接成功、**回 0 字节** | `ConnectionResetError 10054` |
| TLS 握手 | `SSLEOFError: UNEXPECTED_EOF_WHILE_READING` | 同 |

⇒ 13401 **既不是 TLS 也不是 DoIP**，是收到字节即关闭的哑端口/诱饵。与 cgw 的观察一致，排除「13401 是 DoIP-over-TLS 并能吐证书链」。
原始：`0004_gateway_13401_probe.txt`

## 6. 给其他 agent 的移交线索

1. **CGW DoIP 里有两个异常目标地址**（读 `03_EVIDENCE/cgw/1318_lascan_0000_ffff.jsonl` 得到）：
   `0x1000`(src `0x1000`) 和 **`0xE442`(src `0x1220`)** 回的是 `7F3E11`（serviceNotSupported），
   而其余 65409 个地址回 `7F3E31`（requestOutOfRange）。**`7F 3E 11` 与 `7F 3E 31` 是两种不同的否定语义**——
   前者意味着「该地址上真有实体在应答，只是不支持 0x3E」，后者才是「没有这个地址」。
   建议 cgw 对 `0xE442`（源地址 `0x1220`）直接发 `10 02`（Programming Session）与 `34`（RequestDownload）而不是 `3E 00`。
   注：`0xE4xx` 在 UDS 寻址惯例里常被分配给 telematics/T-BOX 类节点。
2. **赛题 09 的 (地址, 明文长度, 加密包长度, rollback) → TransferData 块长度**，形状上最贴合 **UDS `34` RequestDownload → `74` 响应里的 `maxNumberOfBlockLength`**
   （0x74 响应第 1 字节是 lengthFormatIdentifier，其后就是 maxNumberOfBlockLength），而不是 HTTP JSON。
   建议 lead 按 UDS 语义推进，而不是继续在 Web 面找。
3. T-BOX 侧无需再投入：8080 单路由、8443 需真证书、13401 哑端口、无第 3 个端口。

## 7. 未做 / 做不到的面（明确记录）

- 未取得 `CV6 Fleet Diagnostics Root` 的根证书本体（只能从叶证书的 AKID 反推出其 SKI `47:6E:90:16:…:99`），**无法伪造**。
- 未做 `10.224.0.0/12` 全网段扫描找 PKI 主机（约 100 万地址，超出时间盒；且已知存活主机集合只有 5 个 IP）。
- 未尝试通过 CGW 13400 用 UDS `22F1xx` 读 T-BOX 证书（需先解决目标地址问题，见 §6 移交项 1）。

# 任务 03 WP：TLS 1.3 双向证书认证与诊断票据

## 0. 一句话

工程包里已经带了**能通过 T-BOX 8443 强 mTLS 的完整客户端证书三件套**（CA / client / client-key），用它建立 TLS1.3 会话后 POST 一个空请求到 `/api/v1/diag/session`，就能拿到一张 **40 字节、TTL 精确 600 秒**的诊断票据。

---

## 1. 8443 的证书墙长什么样

`10.225.139.3:8443` 是 **TLS1.3-only 的强制客户端证书**端点：

| 项 | 观测值 |
|---|---|
| 协议 | TLS 1.3 only（送 TLS1.2 → `alert protocol version (70)`） |
| ALPN | **完全不协商**（送 `h2` / `http/1.1` 都 `No ALPN negotiated`） |
| 服务端 leaf | `CN=tbox`，EC issuer `CN=CV6 Fleet Diagnostics Root`，EC P-256，EKU=**仅 serverAuth**，SAN `DNS:tbox`，只发叶证书不带链 |
| CertificateRequest | `Acceptable client certificate CA names = CN=CV6 Fleet Diagnostics Root` |
| 无客户端证书 | `alert certificate_required (116)` |
| 自签 / 伪造 CA | `alert unknown ca (48)` |
| 过期 / 未生效证书 | `alert 43`（43 先于 48 判） |
| SNI | 空 SNI / 错 SNI 返回同一张证书 |
| 握手之后 | 明文打会得 Go 的 `Client sent an HTTP request to an HTTPS server.` ⇒ 是 Go net/http |

**为什么硬闯不通**（这是任务 03 的前置结论，也给后续留下判据）：

- 服务端**真验签名链**，不是比 DN/指纹：伪造的 CA 若 subject DER 与真 CA 逐字节相同（含照抄当轮 SKI），签出的 leaf 仍被 `alert 48`。
- **CA 每轮换钥**：leaf AKI 从 `476E9016…781099` 变成 `6591B3ED…D5120A`，但 CertificateRequest 里 CA 的 DN DER 逐字节相同——所以拿上一轮的材质过不了这一轮。
- **ticket 时序被堵死**：服务端 flight 是 `CertificateRequest → Certificate → CertificateVerify → Finished →（客户端空 Certificate）→ alert`，**全程没有 NewSessionTicket**；`-sess_out` 不产生文件、`-reconnect` 5 次 0 次 Reused。Go 源码里只要索取客户端证书，ticket 只在 `processCertsFromClient` 成功之后才发 ⇒ 「先拿 ticket 再靠恢复跳过 mTLS」无起点。
- 工作区 125 张证书 / 70 把私钥、能配对的 61 组**全部实际出示**给活靶机：48×48、43×5，**通过 0 次**。

⇒ **唯一的钥匙就在工程包里**（任务 01→02 的产物）。

---

## 2. 用工程包的证书建 mTLS

工程包里的三件套：

| 文件 | 内容 |
|---|---|
| `diagnostics/ca.pem` | `CN=CV6 Fleet Diagnostics Root` 自签根（有效期 1 年） |
| `diagnostics/client.pem` | `CN=CV6 Engineering Diagnostic Client`，**EKU=clientAuth**，issuer = 上述根 |
| `diagnostics/client-key.pem` | EC P-256 私钥，与 client.pem 公钥匹配（MD5 一致） |

```bash
openssl s_client -connect 10.225.139.3:8443 \
  -cert diagnostics/client.pem -key diagnostics/client-key.pem \
  -CAfile diagnostics/ca.pem -servername tbox
```

```
depth=0 CN = tbox
verify return:1
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256
Verify return code: 0 (ok)          ✅
Post-Handshake New Session Ticket arrived
```

**关键约束：证书是每次下载工程包时由 Fleet Root 现签的**（subject/serial 固定 `CN=CV6 Engineering Diagnostic Client` / `5EDD0F6A2FD8A173DE7319628F7DEA1E`，但**每次公钥不同**）。
⇒ 想用 8443 就必须**当场重下工程包**，不能跨轮复用材料。

> **踩过的坑**：Windows 自带的 curl 走 schannel 后端，加载不了 PEM 私钥（`Failed to import cert file … 0x80092002`）。
> 一律用 `openssl s_client` 或 Python `ssl.SSLContext`；`curl --cert` 在这台机器上不可靠。

---

## 3. 找到签发端点

8443 全站只有一个真实路由。发现方式是利用 Go 的 405 oracle：

```
默认 NotFound = 19 字节  "404 page not found\n"
已注册但方法错 = 31 字节  {"error":"method not allowed"}\n
```

三轮扫描（1587 + 1773 + 带 Host 限定）只命中一条：

```
GET  /api/v1/diag/session  ->  405 {"error":"method not allowed"}
```

---

## 4. 取票据

```python
import ssl, socket, json

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.load_cert_chain("diagnostics/client.pem", "diagnostics/client-key.pem")

s = ctx.wrap_socket(socket.create_connection(("10.225.139.3", 8443), timeout=10),
                    server_hostname="tbox")
s.sendall(b"POST /api/v1/diag/session HTTP/1.1\r\n"
          b"Host: tbox\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
body = b""
while True:
    d = s.recv(4096)
    if not d: break
    body += d
print(body.partition(b"\r\n\r\n")[2])
```

响应（200，130 字节）：

```json
{
  "cgwEndpoint": "cgw:13400",
  "diagnosticTicket": "9Uk3xp3BW6JP6dzEpEEAVgAAAABq998qRy54gjF-lG2PGBDTj-aZww",
  "logicalAddress": "0xE442"
}
```

- **请求体不需要任何内容**：`{}` / `{"vin":...}` / `{"campaignId":...}` 结果完全一致 ⇒ 服务端忽略 body。
- `GET` 同一个 URL 回 405——正是这个 405 把它暴露出来的。
- **没有挑战-签名流程**：一次 POST 直接出票，私钥只用于 mTLS 握手本身。

---

## 5. 票据结构解剖

`diagnosticTicket` 是 **base64url 无填充**，长度 54 或 64 字符（因前导零位数不同），解码后恒 **40 字节**：

```
nonce(16) ‖ exp_u64be(8) ‖ tag(16)
```

以样本 `9Uk3xp3BW6JP6dzEpEEAVgAAAABq998qRy54gjF-lG2PGBDTj-aZww` 为例：

```
raw   = f54937c69dc15ba24fe9dcc4a4410056 00000000 6af7df2a 472e7882317e946d8f1810d38fe699c3
        └──────── nonce(16) ────────┘ └─ exp ─┘ └───────────── tag(16) ─────────────┘

nonce = f54937c69dc15ba24fe9dcc4a4410056
exp   = 1794629418   (= 2026-11-14 03:30:18 UTC，发证后精确 +600 s)
tag   = 472e7882317e946d8f1810d38fe699c3
```

**TTL 精确 600 秒**：5 张连续取样的「发证时刻 → exp」差值全部 600。

### 5.1 绑定维度

| 试验 | 结果 |
|---|---|
| body 里塞 VIN / campaignId | 输出不变 |
| 换 VIN / 换 campaign | 输出不变 |
| `?cn=` / `?subject=` / `?serial=` | 无效（TBS 不可控） |
| 换一张客户端证书重取 | 票据变，但 **`logicalAddress` 恒为 `0xE442`** |

⇒ 绑定维度是「客户端证书 + LA `0xE442`」，**不是 VIN、不是 campaign**。

### 5.2 tag 无法本地验证（这是任务 04 的关键前提）

评估 **102,982 条候选，0 命中**：

- key 35 种：unwrap 出的 32 B、派生 KEK、packageKey、firmwareCredential、`fw[0x2000:0x2010]`、`fw[0x2020:0x2028]`、wrapped blob 40 B 及 `[:8]`/`[8:]`、`"CV6-TBOX-KEK"`，各自 sha256/`[:16]`/`[:32]`
- msg 11 种：`nonce`、`exp`、`nonce‖exp`、`exp‖nonce`、`nonce‖b"E442"`、`b"E442"‖nonce`、`nonce‖exp‖b"E442"` …
- 构造：HMAC-SHA1/256/512、SHA256(k‖m)、AES-ECB/CBC、**AES-GCM tag**（IV=nonce[:12]、AAD/明文各 3 组合）、**AES-CMAC**、**CBC-MAC**、固件 `hash8` 的 8/16 B 组合
- 结构性探测：`tag1^tag2` 与 `nonce1^nonce2`/`exp1^exp2` 无关系；`tag^nonce` 无结构；不是流密码 XOR

⇒ **tag 是 8443 服务端用一把不在固件里的密钥算的**，客户端拿不到验证材料。
⇒ 推论（后来被任务 04 证实）：**"票据绑定"不可能是"本地验 tag 后放行"，票据必须原样送进车端。**

---

## 6. 这个票据后来怎么用的（跨任务闭环）

票据的 `cgwEndpoint` / `logicalAddress` 字段已经指明了去向：

```json
{"cgwEndpoint":"cgw:13400", "logicalAddress":"0xE442"}
```

任务 04 里它被**原样（base64url 字符串本身，ASCII）写进 UDS DID `F1A1`**，回 `6E F1A1`，随后 `27 01` 才能拿到 seed。

> **这是整条链最容易踩的一个坑**：送**解码后的 40 字节二进制**会恒回 `7F 2E 35`（invalidKey），
> 必须送 **54/64 字符的 ASCII 字符串原文**。详见任务 04 WP。

---

## 7. 交付物

| 路径 | 内容 |
|---|---|
| `04_SOLVE/ticket/mtls_client.py` | Python ssl 实现的可复用 mTLS HTTP/1.1 客户端 |
| `04_SOLVE/ticket/ticket.py` | `issue()` / `describe()`（`b64d()` 处理无填充 base64url） |
| `03_EVIDENCE/ticket/0201_route_sweep_get.json` | 1587 路径扫描全表 |
| `03_EVIDENCE/ticket/0202_route_sweep_get_r2.json` | 第二轮 1773 路径 |
| `03_EVIDENCE/ticket/0203_ticket_sample.json` | 票据样本 + 布局 |
| `03_EVIDENCE/tbox-mtls/FINDINGS.md` | 证书墙的完整证伪报告（32 种证书形状 × 10 项 TLS 技巧 × 61 组实材） |

复现：`python 04_SOLVE/ticket/mtls_client.py POST /api/v1/diag/session`

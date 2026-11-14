# T-BOX 支线 NOTES（10.230.164.3）

> 归属：tbox-hunter。写域 `03_EVIDENCE/tbox/**`、`04_SOLVE/tbox/**`、`01_TARGETS/tbox/**`。
> 最后更新：2026-11-14 09:50 (Asia/Shanghai) ／ 服务器时间与本地一致（Date 为 GMT+0，本地 +8）。

---

## 0. 一句话结论

**8443 的 mTLS 是真正的密码学墙：必须持有由 `CN=CV6 Fleet Diagnostics Root` 私钥签发的
客户端证书 + 对应私钥，才可能握手成功。** 该私钥在本轮可触及的网络面上**不存在**；
8080 面只有 `/healthz` 一条路由，已用方法矩阵与非 HTTP 协议面确认，无旁路。
⇒ 本轮 T-BOX 支线**未取得 flag / 诊断票据**，阻塞点是"证书材质来源"，不是"技术手段不够"。

---

## 1. 已证实（有原始输出支撑）

### 1.1 8080 = 最朴素的 Go `net/http` + ServeMux，只有 `/healthz`

| 事实 | 证据 |
|---|---|
| `GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS/TRACE/CONNECT /healthz` **全部 200**，body 恒为 `{"status":"ok"}\n`（16B） | `0020_8080_method_matrix_and_h2.txt` |
| `OPTIONS *`（asterisk-form）→ `200`、`Content-Length: 0` | 同上；这是 Go `http.Server` 的**默认通用 OPTIONS 处理器**（`DisableGeneralOptionsHandler=false`），不是应用路由 |
| 绝对 URI 形式（`GET http://10.230.164.3:8443/`）→ 404 | 同上 |
| `CONNECT 10.230.164.3:8443` → 404 ⇒ **8080 不是正向代理**，无法借它隧道到 8443 | 同上 |
| h2c prior-knowledge preface → `400`；请求行写 `HTTP/2.0` → `505 HTTP Version Not Supported: unsupported protocol version` ⇒ 无 h2c/gRPC 旁路 | 同上 |
| 向 8080 发 TLS ClientHello → 连接直接关闭无响应 | 同上 |
| WebSocket upgrade 到 `/healthz` → 仍 200 普通 JSON，不升级 | 同上 |
| 其余路径一律 `404 page not found`（19B，sha `b16e15764b8bc06c`），含 `/diag /diagnostics /status /ota /tbox /certs /ca.crt /vehicles/<VIN> /v1/diag /api/healthz` | `0018_…`、`0019_…` |

**「代理注入客户端身份头 → Go 应用信任该头」假设：已证伪。**
对 36 个身份头名（`X-SSL-Client-DN/-Cert/-Verify`、`X-Forwarded-Client-Cert`、
`X-Client-DN`、`X-Authenticated-User`、`X-Tbox-Identity`、`Ssl-Client-Dn` …）× 7 个取值
（`CN=tbox` / `CN=CV6 Fleet Diagnostics Root` / VIN / `1` / `SUCCESS` …）遍历 `/healthz` 与 `/`，
**逐字节与基线完全一致（0 差异）**。
过程中出现过单次 `/status` 超时，复测 6/6 全 404（带/不带头各 6 次）⇒ 瞬态噪声，**不是**信号。
证据：`0018_ident_header_trust_battery.txt`、`0019_status_timeout_repro.txt`。

### 1.2 8443 = Go 家族的 TLS1.3 + 强制客户端证书，真验签

| 事实 | 证据 |
|---|---|
| 明文打到 8443 → `HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n` | `0014_plaintext_and_dns.txt` |
| 该 400 是 Go `net/http` 的专属文案（无任何响应头、句尾带 `\n`），⇒ HTTP 层是 Go | 同上 |
| **`certificate_authorities` 扩展里只有一个 DN，且只有 CN 一个 RDN**，值为 `CV6 Fleet Diagnostics Root`，**编码为 PrintableString(0x13)** | `0015_certreq_decoded.txt`、`0016_certreq_ca_dn.txt` |
| CA DN 的完整 DER（39B）：`3025312330210603550403131a43563620466c65657420446961676e6f737469637320526f6f74` | 同上 |
| CertificateRequest 的扩展集合 = `status_request(0)` + `signed_certificate_timestamp(0)` + `signature_algorithms(7 个)` + `signature_algorithms_cert(12 个)` + `certificate_authorities(1)` | `0015_…` |
| 证书请求**没有** O/OU/C/ST/L，CA 是手工用 `-subj "/CN=CV6 Fleet Diagnostics Root"` 造的极简 CA | `0016_…` |

**握手失败点的精确刻画（`-state -msg` 逐消息）：**

```
Server flight : ServerHello → EncryptedExtensions → CertificateRequest → Certificate → CertificateVerify → Finished
Client flight : Certificate → [CertificateVerify] → Finished
Server alert  : 在客户端 Finished **之后**才发出
```

- **不带客户端证书** → 客户端发 `Certificate`（长度 `0008`＝空证书列表）+ `Finished`，
  服务器随后回 `<<< TLS 1.3, Alert [length 0002], fatal certificate_required`（116）。
  证据 `0009_hs_nocert.txt`。
- **带自签证书** → 客户端发 `Certificate(0125)` + `CertificateVerify(0048)` + `Finished(0024)`，
  服务器随后回 `<<< TLS 1.3, Alert [length 0002], fatal unknown_ca`（48）。
  证据 `0010_hs_selfsigned.txt`。
- 两种失败都发生在**整个客户端 flight 处理完**之后，即服务器完整收到了我们的证书与
  CertificateVerify 签名，**完成了"链构建"这一步**才拒绝 ⇒ 这是**链校验失败**，
  不是"看到证书就拒"的其他校验。

### 1.3 校验语义对照实验（本地可控对照，用来锚定 alert 含义）

本机 `go 1.24.2` 起了对照服务（`RequireAndVerifyClientCert` + 自建 CA，`04_SOLVE/tbox/gostack/`）：

| 场景 | 本地 Go 1.24.2 参照服务 | 目标 8443 |
|---|---|---|
| 不带客户端证书 | `alert 116 certificate_required` | `alert 116 certificate_required` ✅ 一致 |
| 自签客户端证书 | `alert 48 unknown_ca` | `alert 48 unknown_ca` ✅ 一致 |
| CertificateRequest 扩展 | `status_request(0)` + `SCT(0)` + `signature_algorithms(12)` + `CA` | `status_request(0)` + `SCT(0)` + `sig_alg(7)` + `sig_alg_cert(12)` + `CA` |

**这条对照推翻了我原先"alert 48 ⇒ 不是 Go"的判断**：Go 1.24.2 在客户端证书链校验失败时
**确实**发 48。所以 alert 码不能用来排除 Go。
唯一差异是目标多发了 `signature_algorithms_cert(0x0032)` 且把 TLS1.3 算法集单列 ——
本地 `openssl s_server 3.0.15` 的布局（单个 `signature_algorithms`、16 个算法、无 0x0032、
无 status_request/SCT）与目标**也不一致**。⇒ 目标大概率是**比 1.24.2 更新的 Go**（或在
`crypto/tls` 上做了该扩展的新版本），不是 OpenSSL 反代。此点为**推测**，见 §2。

### 1.4 排他性：不是"只比 DN"

`03_EVIDENCE/tbox/0005_mtls_cert_construction_matrix.txt` 已给 9 组构造，全部 48：
Ed25519/RSA2048/自签 CA:TRUE、**复刻 issuer DN 的伪 CA 签发叶**（带/不带链）、
**把 SKI 伪造成真根的 SKI 再签**、v1 无扩展、无 EKU 叶 —— 一律 `unknown ca`。
⇒ 服务器用**真实的根公钥做签名验证**，不是 DN/SKI 字符串比对。
（此前 `v6_root_as_client.pem` 唯一的 `ConnectionResetError` 已确认是瞬态，非语义差异。）

### 1.5 其它入口均为死路

- **内网 DNS 不存在**：本机 resolver 是家用路由器 `router.ctc`(fe80::5)。
  `nslookup tbox / tsp / cgw / fleet / ota / signing / pki` 全部 NXDOMAIN。
  ovpn 里**没有** `dhcp-option DNS`，只有 `route 10.224.0.0 255.240.0.0`。
  证据 `0014_plaintext_and_dns.txt`。
- **VPN CA ≠ 车队 CA**：ovpn `<ca>` 是 `CN=CyberCar Vehicle Range VPN CA`，与
  `CN=CV6 Fleet Diagnostics Root` 无关；且 ovpn 只给客户端证书，**不含该 CA 私钥**，
  签不出新证书。我方 VPN 叶证书（`CN=cc-715a9a001b4a5abad5ce3ecc`，EKU=clientAuth）
  打到 8443 仍是 48。
- **TSP `/graphql` 是桩**（本轮单次只读复核）：`POST {"query":"{ __typename }"}` →
  `{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}`，
  连 `__typename` 都不解析。证据 `0021_tsp_graphql_single_readonly.txt`。

---

## 2. 推测（未证实，标注依据）

1. **8443 的 TLS 终结者是 Go（版本 > 1.24.2）**。
   依据：明文 400 文案是 Go 独有；alert 116/48 与本地 Go 1.24.2 对照一致；
   `status_request`+`SCT` 空扩展也是 Go 1.24.2 会发的。唯一反证是多出的 `0x0032`。
   → 若成立，则**不存在**"OpenSSL 反代 → Go 后端"的分层，也就没有"绕过反代直连后端"的路。
2. **CA 私钥在题目容器/镜像里，网络不可达**。依据：8080 无任何文件路由（1576 条词表 +
   本轮方法矩阵/协议面），8443 不提供带链响应，全靶场网段无文件服务。
3. **该 CA 是"极简手工 CA"**（只有一个 CN、PrintableString 编码），说明是
   `openssl req -x509 -subj "/CN=CV6 Fleet Diagnostics Root"` 一类脚本现场生成，
   很可能随容器启动生成在某个挂载目录里。→ 这正是"拿到就能进"的唯一钥匙。

---

## 3. 未验证 / 需要别人接手的

| 项 | 为什么没做 | 建议 |
|---|---|---|
| 从车端 ECU 取 T-BOX 配置证书 | 属 cgw 支线（DoIP/UDS），且我禁止碰 13400 | **最高优先级**：对 7E0/7E1 两条诊断 ID 做 `22` DID 全量扫（F1xx / F18x / F19x，尤其 `F1A3`/`F1A4`/`F1A5`/`F1AD`/`F1C0` 一类"ECU 序列号/证书/指纹"位），以及 `31 01` routine 里偏"读/导出配置"的子功能。T-BOX 的 factory cert 通常就存在这类 DID 里。 |
| 8443 拿到证书后的路由枚举 | 无证书，握手进不去 | `04_SOLVE/tbox/tbox_client.py --cert c.pem --key k.key --methods` 已备好，握手成功即自动列出非 404 路由与 body |
| 伪造 CA 私钥 | ECDSA P-256 不可行 | 放弃；仅一个已知签名样本（叶证书签名），无 nonce 复用证据，无法恢复私钥 |
| 高位 filtered 端口（2929/6295/10324…） | 防火墙 drop，源地址受限 | 若后续能从别的网段（如经 .4 转发）访问再试 |

---

## 4. 交付物 / 证据索引

**本轮新增证据（`03_EVIDENCE/tbox/`）**

| 文件 | 内容 |
|---|---|
| `0009_hs_nocert.txt` | 无证书 `-state -msg` 全量：CertificateRequest 十六进制、握手点、alert 116 位置 |
| `0010_hs_selfsigned.txt` | 自签证书全量：客户端 flight 完整、alert 48 位置 |
| `0011_hs_rootdn_selfca.txt` | CN 伪装成根 DN 的自签 CA 作为客户端证书 |
| `0012_hs_fakeca_chain.txt` | 伪 CA（DN+SKI 同真根）签发叶 + 带链 |
| `0013_hs_nocert_pha.txt` | PHA 变体（`-post_handshake_auth` 参数在 3.0.15 不存在，记录为无效实验） |
| `0014_plaintext_and_dns.txt` | 8443 明文 400、内网 DNS 全 NXDOMAIN |
| `0015_certreq_decoded.txt` | CertificateRequest 逐扩展解码（含 CA DN DER） |
| `0016_certreq_ca_dn.txt` | CA DN 的最小 DER 解析 + 重建比对（差异仅在 UTF8String vs PrintableString） |
| `0017_go_reference_stack_control.txt` | 本地 Go 1.24.2 对照服务：alert 116/48 与扩展布局 |
| `0018_ident_header_trust_battery.txt` | 36×7 身份头遍历（含末尾更正段） |
| `0019_status_timeout_repro.txt` | `/status` 超时复测，判定瞬态 |
| `0020_8080_method_matrix_and_h2.txt` | 方法矩阵 / OPTIONS * / 绝对 URI / CONNECT / h2c / WS / TLS-to-8080 |
| `0021_tsp_graphql_single_readonly.txt` | TSP GraphQL 单次只读复核 |

**脚本（`04_SOLVE/tbox/`，本轮新增）**

| 文件 | 用途 |
|---|---|
| `capture_handshake.sh` | 一次跑完 5 组 `-state -msg` 握手抓取 |
| `decode_certreq.py` | 从 `-msg` 十六进制里解出 CertificateRequest 结构与 CA DN |
| `dn_parse.py` | 极简 DER RDNSequence 解析 + 重建比对 |
| `probe_ident_headers.py` | 身份头信任遍历（已证伪） |
| `tbox_client.py` | **拿到证书即可开火**：握手自检 + 方法矩阵 + 40 条路由探测 |
| `gostack/` | Go 1.24.2 参照服务（`main.go` + 自制 PKI + `openssl.cnf`，因为本机 Miniconda openssl 缺 openssl.cnf） |

---

## 5. 坑 / 注意事项（给后来者）

1. **本机 Miniconda 的 openssl 3.0.15 没有 `openssl.cnf`**，`req/x509` 会报
   `fopen(C:\Program Files\Common Files\ssl/openssl.cnf)` 失败。必须显式 `-config` 传自己的 cnf。
2. **MSYS bash 会把 `-subj "/CN=xxx"` 里的 `/CN=...` 当路径转换掉**，导致静默失败。
   需要 `export MSYS2_ARG_CONV_EXCL='*'`。
3. `openssl s_client -msg` 的十六进制行**不一定有 `0000 - ` 偏移前缀**（本机就是纯空格缩进且 CRLF），
   解析脚本要两种都吃。
4. **`alert 48` 不能用来判断"服务端不是 Go"** —— Go 1.24.2 实测就发 48。
5. **本机 127.0.0.1:9443 有一个非我启动的监听（PID 19312）**，会回一张自签
   `CN=localhost`、却要求 `CV6 Fleet Diagnostics Root` 客户端证书的怪响应。
   疑似历史会话留下的本地 mock。**做对照实验前务必换端口/先 netstat 确认**，否则会得出错误结论
   （本轮就差点被它误导）。
6. `OPTIONS *` 的 200 是 Go 默认处理器，**不要**当成"发现了新路由"。

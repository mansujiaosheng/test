# T-BOX 内网 mTLS 端口 — round-2 复验结论：不可进入（含机制级证据）

> 分析员：tbox-mtls｜时间：2026-11-14 09:43–10:05 CST（01:43–02:05 UTC）
> round-2 目标：**10.225.139.3:8443**（round-1 的 10.230.164.3 已随靶机重启作废）
> 判据：能否拿到一次「客户端证书被接受」的 TLS 握手；拿到后 HTTP 层能访问什么
> 写作用域：`03_EVIDENCE/tbox-mtls/`、`04_SOLVE/tbox-mtls/`、`01_TARGETS/tbox-mtls/`

---

## 0. 一句话结论

**在新环境上重跑了 32 种客户端证书形状 + 10 项 TLS 技巧 + 全工作区 61 组 key/cert 的实际出示，握手完成次数 = 0。
8443 仍是 Go `crypto/tls` 的 `RequireAndVerifyClientCert` + 单一 `ClientCAs`（池里只有 `CN=CV6 Fleet Diagnostics Root`）；
round-2 只换了 CA 的**密钥**（DN 逐字节未变），本机不存在任何被该 CA 签发过的 leaf+key。
不持有「当轮 CV6 root 签发的 clientAuth 证书 + 对应私钥」，就不存在第二条进入路径。**

拿不到材质不是「没找对形状」，而是**验证的是签名链**：DN、SKI、AKI、EKU、SAN、有效期窗口、曲线、链序全部被逐项证伪（§2），
且 Go 的代码路径决定了这些字段**根本没有参与判定的机会**（§4）。

---

## 1. 环境变更与重验：地址变了、CA 换钥了、信任结构没变

| 事实 | round-1（10.230.164.3） | round-2（10.225.139.3） | 证据 |
|---|---|---|---|
| 服务端 leaf subject / issuer | `CN=tbox` / `CN=CV6 Fleet Diagnostics Root` | 同 | `0107_new_leaf_facts.txt` |
| leaf serial | `502C0ED0DFFB9EC2AF2BCE9F97737827` | `FE7B39240E873E2F286DB4A739E0C40F` | 同上 |
| leaf 有效期 | 11-14 00:00:32Z ~ 12-14 01:00:32Z | **11-14 00:51:20Z ~ 12-14 01:51:20Z** | 同上 |
| leaf AKI（= root SKI 代理） | `476E9016…781099` | **`6591B3ED6CB02B421B6446F962EF85DECAD5120A`** | 同上 |
| 服务端下发链长 | 1（只有 leaf） | **1（只有 leaf）** | `0105`/`0109` K10 |
| CertificateRequest 的 CA 列表 | 1 个 DN，DER=`302531233021…526f6f74` | **同一 DN，DER 逐字节相同**（PrintableString） | `0105_new_env_chain_and_msg.txt:105-112` |
| 无证书 | alert **116** | alert **116** | `0104_matrix_run.txt` A00/T02–T08 |
| 自签证书 | alert **48** | alert **48** | 同上 A01–A13 |
| 过期证书 | alert 43 | alert 43 | 同上 A04 |
| 未生效证书 | —（round-1 未单测） | **alert 43（不是 42）** | 同上 A05 |

两个直接推论：

1. **CA 每轮重生成密钥**（同名不同钥）。上一轮即使某处泄露过一张 CV6 证书，现在也已作废；反之本轮材质同样不能跨轮复用。
2. **`ClientCAs` 非空且只有一个根**（CR 的 `certificate_authorities` 恰好一行）。这排除了最经典的一类配置错误：
   `ClientCAs=nil` → Go 退化为**系统根池** → 任何公网 CA 签发的 clientAuth 证书即可进入。本靶场不是这种形态。
3. 「未生效」与「已过期」都回 **43**（不区分方向），且有效期判定发生在「找不到签发者(48)」之前；
   这与本地 Go 1.24.2 镜像的逐例复现一致（同一 `RequireAndVerifyClientCert` 配置下 116/48/43 三元组完全吻合，
   见 `03_EVIDENCE/tbox/0015_lab_go_alert_mapping.md`）——即服务端校验器就是 Go 标准库的 `x509.Verify`，
   不存在「自写比较字段」那种可被名字/字段撞开的实现。

---

## 2. 证书校验矩阵（32 例，全部失败）

材料由 `04_SOLVE/tbox-mtls/make_matrix.py` 用 `cryptography 43.0.3` 现造（可精确控制 DN 字符串类型、SKI/AKI、
nameConstraints、certificatePolicies、有效期、曲线、RSA/Ed25519），每例一条 TCP 连接、`ssl.PROTOCOL_TLS_CLIENT`、
`CERT_NONE`，逐例记录 alert。

| # | 形状 | 结果 |
|---|---|---|
| A00 | 不出示证书 | **116** `certificate_required` |
| A01 | 自签 EC P-256 `CN=tbox` + EKU=clientAuth + SAN=DNS:tbox | 48 |
| A02 | 自签 RSA-2048 | 48 |
| A03 | 自签 secp384r1 | 48 |
| A04 | 自签但 notAfter=2020 | **43** `certificate_expired` |
| A05 | 自签但 notBefore=2027-06 | **43**（未生效也归入 expired，见 §1 第 3 条） |
| A06 | 自签、无 EKU 扩展 | 48 |
| A07 | 自签、EKU=serverAuth（错 EKU） | 48 |
| A08 | 自签、无 SAN | 48 |
| A09 | 自签、**空 subject** | 48 |
| A10 | 自签但 CA:TRUE + keyCertSign（「当 CA 用」） | 48 |
| A11 | 自签、`CN=CV6 Fleet Diagnostics Root` | 48 |
| A12 | 自签、**AKI 照抄当轮 root SKI** `6591B3ED…` | 48 |
| A13 | 自签 Ed25519 | 48 |
| B01 | 假 CA（同 DN，PrintableString）+ 其签发的 leaf，leaf 在前 | 48 |
| B03 | 假 CA（同 DN + **SKI 照抄** `6591B3ED…`）+ leaf | 48 |
| B04 | 假 CA（同 DN + nameConstraints `permitted DNS:.tbox`）+ leaf | 48 |
| B05 | 假 CA（同 DN + certificatePolicies）+ leaf | 48 |
| B06 | 假 CA（同 DN，RSA-2048）+ leaf | 48 |
| B07 | **只出示 CA、不出示 leaf**（把 CA 当客户端证书） | 48 |
| B08 | 只出示 leaf（不带签发它的 CA） | 48 |
| B09 | **.ovpn 里的 VPN 客户端证书**（issuer=VPN CA，EKU=clientAuth，KU=digitalSignature，当前有效） | 48 |
| B10 | VPN leaf + VPN CA 链 | 48 |
| T01 | TLS1.2（带证书） | **70** `protocol_version`（证书交换前即拒） |
| T02–T05 | SNI = `tbox` / 空 / `TBOX` / `tbox.cybercar.local` | 均 116（同一张 leaf） |
| T06–T08 | ALPN = `h2` / `http/1.1` / `acme-tls/1` | 均 116，且 ALPN 协商恒为空 |
| T09 | ALPN=h2 + 形状正确的自签证书 | 48 |

**决定性的一条**：B01/B03/B04/B05/B06 这 5 张假 CA 的 subject DER 与真 CA 的 DN **逐字节相同**
（`0102_pki_cert_manifest.txt:40-44` 的 `BYTE-EQUAL` 判定，含 PrintableString 编码），其中 B03 还把 SKI 照抄成当轮 root 的 `6591B3ED…`，
结果仍然全部 48 ⇒ 服务端判的是**签名链**，不是名字、编码或指纹字段。

统计：**48×21 / 116×8 / 43×2 / 70×1 / 通过 0**。
证据：`03_EVIDENCE/tbox-mtls/0103_matrix_run.json`、`0104_matrix_run.txt`、`0102_pki_cert_manifest.txt`（27 条材料的 subject/issuer/EKU/SAN/SKI/AKI/有效期逐一列出）。

> B02（CA-first 链序）无法用 openssl/python 表达——两者的 `-cert`/`load_cert_chain` 都要求首证书与私钥配对
> （实测 `X509_check_private_key: key values mismatch`，见 `0109` K01）。Go 语义上被验证的永远是 `certs[0]`，
> 所以「CA 当 leaf」这一形状已由 B07 覆盖，结论相同。

---

## 3. TLS 层技巧（10 项，全部无效）

| 技巧 | 实测 | 证据 |
|---|---|---|
| **session ticket 时序**（最关键） | `-msg` 抓到的完整 flight：`CertificateRequest` → `Certificate` → `CertificateVerify` → `Finished` → 客户端空 `Certificate(0008)` → 服务端 `alert 116`。**全程没有任何 `NewSessionTicket`** | `0105_new_env_chain_and_msg.txt:105-187` |
| 能否先拿 ticket 再恢复 | `-sess_out` **不生成 session 文件**（握手从未完成） | `0109` K03 |
| 恢复握手是否跳过客户端认证 | 无 ticket 可恢复；`-sess_in` 直接报 `Can't open session file` | `0109` K04 |
| `-reconnect`（Session-ID 复用） | 5 次全部 `New`，**0 次 `Reused`** | `0109` K05 |
| 0-RTT early data | 结构性不可达：先要有一次成功握手才能拿到 ticket；且 Go 只对 QUIC 支持 early data（`session.EarlyData = c.quic != nil`） | `0109` K07 + `0110` §G |
| 后握手认证 PHA | `-enable_pha` 仍在握手阶段被 116 拒；Go 的 PHA 只在 `ClientAuth < RequireAnyClientCert` 时才会开 | `0109` K06 + `0110` §A/D |
| TLS1.2 降级 | alert **70**，ServerHello 之前即拒 | `0109` K08 |
| ALPN 分支（h2） | 不协商任何 ALPN，无 h2 专用处理 | `0104` T06–T09 |
| SNI 变化 / 空 SNI | 同一张 leaf，同一 alert | `0104` T02–T05 |
| 客户端链顺序 | leaf-first → 48；CA-first 不可表达，语义等价于 B07 → 48 | `0109` K01/K02 |

---

## 4. 为什么「不存在第二种解法」——Go 1.24.2 源码级

本机装有 go1.24.2（`C:\Program Files\Go`），把 8443 的行为逐条 pin 到标准库代码（`03_EVIDENCE/tbox-mtls/0110_go_source_pins.txt` 含行号原文）：

1. **是否索取客户端证书**：`requestClientCert() = ClientAuth >= RequestClientCert && !usingPSK`
   （`handshake_server_tls13.go:818-820`）。服务端确实发了 CertificateRequest ⇒ 走强制认证分支。
2. **无证书 → 116**：`processCertsFromClient` 里 `len(certs)==0 && requiresClientCert(...)` → TLS1.3 发
   `alertCertificateRequired`（116）（`handshake_server.go:916-923`）。与实测 A00/T02–T08 完全一致。
3. **有证书 → 用 `x509.Verify` 验链**：`Roots: c.config.ClientCAs`、`KeyUsages: [ExtKeyUsageClientAuth]`、
   中间证书只来自客户端自己发的链（`handshake_server.go:925-937`）。失败时按错误类型分流：
   `UnknownAuthorityError`→**48**，`CertificateInvalidError{Expired}`→**43**，其余→**42**（`:938-948`）。
   实测 48/43 的分布与这段代码逐条对应 ⇒ 判定依据是**签名链**，不是 DN/SKI/EKU/SAN。
4. **ticket 不可能先于认证下发**：只有当**没有**索取客户端证书时才在第一 flight 里发 ticket
   （`handshake_server_tls13.go:929-936`，注释即写明 "If we did not request client certificates…"）；
   索取了客户端证书时，ticket 在 `readClientCertificate()` 内、**`processCertsFromClient` 成功之后**才发
   （`:1115-1119`，注释 "If we waited until the client certificates to send session tickets…"）。
   ⇒ 「先拿 ticket 再靠恢复跳过 mTLS」这条路在服务端实现上被堵死，不是我们没构造出来。
5. **恢复握手不重验证书，但也进不去**：恢复时 `peerCertificates` 直接取自 ticket（`:455`），并额外拒绝
   「ticket 里的客户端证书已过期」（`:399-407`）；而 `usingPSK` 时 `requestClientCert()` 返回 false。
   即：**恢复确实不发 CertificateRequest，但前提是你先完整通过一次认证**——循环依赖，无起点。
6. **0-RTT**：Go 的非 QUIC 路径根本没有 early data（`handshake_client_tls13.go:891`）。

结论：这 6 条互相独立，任何一条都足以让「非证书旁路」这一整类失效。

---

## 5. 证书材质来源穷举（本机 → 0 张可用）

### 5.1 `.ovpn` 的全部 4 段 PEM

`cybercar-competition-…ovpn` 里只有 `<ca>`、`<cert>`、`<key>`、`<tls-crypt>`：

| 段 | 内容 | 判定 |
|---|---|---|
| `<ca>` | `CN=CyberCar Vehicle Range VPN CA`，自签，EC P-256，CA:TRUE，2026-08-12~2036-08-12，SKI `7A0CDD7E…` | VPN 域，与 CV6 根不同钥 |
| `<cert>` | `CN=cc-715a9a001b4a5abad5ce3ecc`，issuer=VPN CA，**EKU=clientAuth、KU=digitalSignature**、2026-11-14 01:00:24Z~11-17，AKI `7A0CDD7E…` | 形状**完全合规**的客户端证书，但签发者不在信任池 → 48（B09） |
| `<key>` | EC P-256 私钥，与 `<cert>` 配对 | 同上 |
| `<tls-crypt>` | OpenVPN 静态密钥（16×16 字节），只用于 VPN 控制通道加密 | 不含任何 X.509 材质 |

`%TEMP%\ca.pem|cert.pem|key.pem`（09:29 写入）经比对是同一组 VPN 材质的抽取残留，非新下发。

### 5.2 平台侧（会不会发 mTLS 客户证书）

`01_TARGETS/tbox/platform/` 里 dump 的平台前端与浏览器库显示：平台只有「个人 OpenVPN 证书 + 隧道地址」能力
（`index.html`：「每名选手获得独立证书和隧道地址」；`app.js`：`/vpn` 页签），**没有任何 mTLS 客户端证书/CA 签发入口**。
证书有效期字段也只对应 VPN 证书。

### 5.3 功能性穷举：把本机所有 key/cert 组**实际出示**给活靶机

`04_SOLVE/tbox-mtls/sweep_all_material.py`：遍历整个 `D:\qwb`，按 SPKI 配对成可出示的 key+cert 对，
逐组打到 10.225.139.3:8443。

- 找到证书 **125** 张、私钥 **70** 把
- 可配对并实际出示 **61** 组
- 结果：**通过 0**；`48 unknown_ca` × 48、`43 certificate_expired` × 5（过期/未生效）、
  7 组因「首证书与私钥不配对」（CA-first 链文件）在客户端侧就无法加载、1 组瞬时重置
- 另有 **16** 张证书在本机找不到对应私钥（无法作为客户端凭据）

证据：`0111_all_local_material_sweep.json` / `.txt`（每组含 cert 路径、subject、issuer、alert）。

⇒ 「本机没有 CV6 签发材质」不再是清点推断，而是 61 次实际出示后的实测结论。

### 5.4 8080（round-2 复查）

新主机 8080 仍只有 `/healthz`（`200`，体 `{"status":"ok"}\n`）、`OPTIONS *` → `200`/`Content-Length: 0`
（Go `globalOptionsHandler`），`/certs`、`/pki/ca.crt`、`/ca.crt`、`/ota`、`/graphql`、`/metrics`、`/version` 全 404。
证据：`0108_8080_round2.txt`。没有证书下载面。

---

## 6. 假如进了 8443，要探什么（未执行——没有进入，仅登记判据）

一旦出现握手完成，按序取证并落盘：`GET /`、`/healthz`、`/api`、`/api/v1`、`/ota`、`/campaign`、`/campaigns`、
`/diagnostics`、`/diag`、`/vehicle/CV6FF52FEE9EDDD86`、`/vehicles`、`/firmware`、`/package`，
记录 `status / Content-Type / Content-Length / body`；随后把 leaf 的 AKI 与当轮 root 对齐，确认「谁在替我们签名」。
**本条未执行，不得写成已验证。**

---

## 7. 什么会翻转本结论

任一条成立，本结论立即失效，回来重测（思路与命令都已备好）：

1. 拿到**当轮** CV6 root 签发的 clientAuth leaf + 私钥（`make_matrix.py` 加一例即可验证；预期 200）；
2. 拿到该 root 的私钥（可自签任意 leaf）；
3. 服务端配置变更：`ClientCAs` 变空（退化为系统根池）、或 `ClientAuth` 降为 `RequireAnyClientCert`/`RequestClientCert`
   —— 判据是「自签证书能否完成握手」，一条 `openssl s_client -cert pki/s01_cn_tbox.pem` 就能发现；
4. 出现第 4 个服务/端口能下发该 CA 的材质（本轮 8443/8080 之外无新面）。

---

## 8. 复现命令

```bash
# 0) 控制组（应为 116）
openssl s_client -connect 10.225.139.3:8443 -servername tbox -quiet </dev/null 2>&1 | tail -3

# 1) 证书形状矩阵（32 例；--regen 重新生成 27 条材料）
python 04_SOLVE/tbox-mtls/make_matrix.py --regen

# 2) TLS 技巧矩阵（ticket 时序 / 恢复 / PHA / 0-RTT / 降级 / 链序）
bash 04_SOLVE/tbox-mtls/tls_tricks.sh 10.225.139.3 8443

# 3) 全工作区 key/cert 实际出示（61 组）
python 04_SOLVE/tbox-mtls/sweep_all_material.py

# 4) 新环境服务端材质 + CR 的 CA 名（看 flight 顺序与有没有 NewSessionTicket）
openssl s_client -connect 10.225.139.3:8443 -servername tbox -msg -no_ticket </dev/null
```

---

## 9. 证据索引（全部在本目录 `03_EVIDENCE/tbox-mtls/`）

| 文件 | 内容 |
|---|---|
| `0101_pki_manifest.json` / `0102_pki_cert_manifest.txt` | 本轮 27 条测试材料的逐张清单（含「与真 CA 的 subject DER 是否逐字节相同」判定） |
| `0103_matrix_run.json` / `0104_matrix_run.txt` | 32 例矩阵的原始结果（每例 alert、耗时、握手结果） |
| `0105_new_env_chain_and_msg.txt` | 新环境 `-showcerts` + 完整 `-msg` flight（含 CR 的 CA 名、无 NewSessionTicket 的实证） |
| `0106_new_leaf_tbox.pem/.der`、`0107_new_leaf_facts.txt` | round-2 服务端 leaf 本体与全部字段 |
| `0108_8080_round2.txt` | 新主机 8080 面（只有 /healthz） |
| `0109_tls_tricks.txt` | 10 项 TLS 技巧原始输出（K01–K10） |
| `0110_go_source_pins.txt` | go1.24.2 `crypto/tls` 与 `alert.go` 的逐段原文（带行号） |
| `0111_all_local_material_sweep.json/.txt` | 61 组本机 key/cert 实际出示结果 |

脚本：`04_SOLVE/tbox-mtls/make_matrix.py`、`tls_tricks.sh`、`sweep_all_material.py`；
材料：`04_SOLVE/tbox-mtls/pki/`。

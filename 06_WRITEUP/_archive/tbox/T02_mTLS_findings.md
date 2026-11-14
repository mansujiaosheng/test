# T02 · T-BOX (10.230.164.3) OTA 与 mTLS 诊断 — 阶段性结论（证伪记录）

时间：2026-11-14 09:16–10:00 CST｜执行：teammate `tbox`
性质：全部为只读探测（TCP connect、TLS 握手、HTTP GET/HEAD/OPTIONS、UDP QUIC 探测）；未做写操作、未爆破口令、未改动靶机。

## 0. 一句话
8080 是纯存活探针（仅 `/healthz`）；**8443 是标准 Go `crypto/tls` + `RequireAndVerifyClientCert`，信任池只含 `CN=CV6 Fleet Diagnostics Root`**；本机没有任何该 CA 签发的证书，且 8443 的 TLS 层不存在证书校验旁路。**OTA ZIP / 客户端证书不可能从 10.230.164.3 本身取得**，只能来自赛事平台附件或其它目标。

## 1. 8080（明文 HTTP，Go net/http）
- `/healthz` → 200 `{"status":"ok"}\n`，**任意方法**（GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS/TRACE/CONNECT）都是 200 同体；
- 其它路径 → 404 `404 page not found\n`（Go 默认 NotFound）。
- `//healthz`、`/./healthz`、`/a/../healthz` → 307 → `/healthz`（Go ServeMux cleanPath，无文件服务）。
- `/healthz?debug|verbose|full|format|token|version=1` → 全 200 同体。
- POST body（`{"cmd":"diag"}` 等）与 WebSocket Upgrade → 无效。
- VIN 相关路径（`/ota/CV6FF52FEE9EDDD86`、`/firmware/…`、`/download/…zip`、`/vehicles/…` 等 30 条）全 404。
- 结论：无任何业务路由；该端口是基础设施存活探针（与 .2/.4 同款骨架）。

证据：`03_EVIDENCE/web/brute2_10.230.164.3_8080.*`、`03_EVIDENCE/tbox/0007_8080_methods_params.txt`、`0008_ota_path_probe.txt`、`0009_8080_bodies_ws.txt`、`0010_host_scoped_and_filtered.txt`

## 2. 8443（TLS 1.3 only + 强制客户端证书）
### 2.1 服务端事实
- TLS 1.3 only：TLS1.2 → alert 70 (`tlsv1 alert protocol version`)。
- 服务端证书：`subject CN=tbox`、`issuer CN=CV6 Fleet Diagnostics Root`、P-256 ECDSA、SAN `DNS:tbox`、有效期 2026-11-14 00:00:32Z ~ 2026-12-14 01:00:32Z；链上**只有 leaf**，无根/中间证书。
- `CertificateRequest` 的 `certificate_authorities` = `CN = CV6 Fleet Diagnostics Root`；请求签名算法 RSA-PSS/ECDSA/Ed25519 全套。
- 明文 HTTP 打到 8443 → `HTTP/1.0 400 Bad Request / Client sent an HTTP request to an HTTPS server.`（Go net/http over TLS 特征）。

### 2.2 客户端证书校验是**标准 x509 链验证**（逐条证伪）
| 客户端证书构造 | 结果 |
|---|---|
| 无证书 | alert 116 `certificate required` |
| 自签 CN=client / CN=tbox / CN=CV6 Fleet Diagnostics Root (CA:TRUE) | alert 48 `unknown_ca` |
| 伪造同名根 `CN=CV6 Fleet Diagnostics Root` 签发 leaf | alert 48 |
| 伪造根 + 伪造 SKI=476e90… + 链 | alert 48 |
| ed25519 / RSA-2048 自签 | alert 48 |
| v1 无扩展证书 | alert 48 |
| 无 EKU 的 leaf（有链） | alert 48 |
| **已过期**的自签证书 | **alert 45 `certificate_expired`** ← 说明跑的是真 x509 日期检查 |
| **VPN 客户端证书**（issuer `CyberCar Vehicle Range VPN CA`，EKU clientAuth）leaf-only 与 leaf+CA 链 | alert 48 |
- 过期 → 45、错 CA → 48 的组合证明服务端执行 `x509.Certificate.Verify`（Go 的 `CertificateInvalidError{Expired}` 映射 alert 45，`UnknownAuthorityError` 映射 alert 48），**不是只比对 CN/issuer 字符串**。

### 2.3 旁路尝试全部证伪
- SNI × ALPN 矩阵：30 个 SNI（tbox/TBOX/tbox.local/diag/ota/firmware/ca/pki/est/enroll/…）× 6 种 ALPN（无/h2/http1.1/h2,http1.1/grpc/acme-tls/1）= 204 组，无证书全部 alert 116；少量 RST/超时为网络抖动（复测一致）。
- 无 SNI、错误 SNI：116。
- UDP/8443 QUIC（aioquic，ALPN h3）：无响应（ConnectionError）。
- TLS1.3 post-handshake auth / early data / PSK：无 ticket、无 PSK，服务端不提供旁路。
- 8080 上无隐藏路由（9351 路径 × 方法矩阵 + 1576 词表两轮，仅 `/healthz`）。
- 10.230.164.0/24 只有 .2/.3/.4，无独立 PKI/文件服务；.3 全 65535 TCP 仅 8080/8443。

证据：`03_EVIDENCE/web/8443_*`、`03_EVIDENCE/tbox/0001..0014*`、`04_SOLVE/tbox/{probe_tls,sni_alpn_fuzz,mtls_matrix,quic_probe*}.py`

### 2.4 结论
要进 8443，必须拿到 **`CN=CV6 Fleet Diagnostics Root` 私钥真实签发**的 client cert+key。该材料不在本机（VPN 的 CA 是另一套 PKI，SPKI SHA1 与 tbox 证书 AKI `476e90…` 不符）。

## 3. OTA ZIP / 证书材料的唯一可能来源（截至 10:00）
1. **赛事平台附件**（最可能）：`https://175.27.210.153:9989/` 的 challenge 对象含 `attachments[]={id,filename,sizeBytes,downloadPath}`；但 `/api/v1/*` 全部 401，需要本队账号的 `cybercar_session`；平台反作弊规则明确统计「是否下载过附件」（`attachment_without_download`）。
2. 其它目标（CGW/DoIP）——CGW 0x1000 全 DID 0000–FFFF 扫描只有 F190/VIN 与 F1A0/LA 列表，无证书类数据。
3. TSP `10.230.164.2:8080/graphql` 是常量桩（任意合法 JSON → demo vehicle），无 BOLA/IDOR 面。

## 4. 下一步（需要用户动作）
用户在平台「车辆题目」页把 T02 的附件下载到本机（默认 `D:\下载文件`），我立刻接手 OTA ZIP 分析（AES-256-GCM / ARMv7-M Thumb-2 / RFC 3394）。

---

## 附：2026-11-14 10:01 CST 靶场重开（第二代实例）
用户在平台重启了整车靶场，全部目标 IP 变更；**旧一代证据对应已销毁的主机**，结论在新一代上复测一致：

| 角色 | 旧（已销毁） | 新（第二代，实测） |
|---|---|---|
| TSP | 10.230.164.2:8080 | **10.225.139.2:8080**（/graphql 仍是 demo 桩） |
| T-BOX | 10.230.164.3:8080/8443 | **10.225.139.3:8080/8443** |
| CGW | 10.229.221.2 / 10.230.164.4 | **10.225.139.4:8080/13400/13401**（VIN `CV622697F82A936A1`；另有 10.226.193.2 同 VIN） |

新一代 T-BOX 事实（`03_EVIDENCE/tbox/0021_newrange_tbox_handshake.txt`、`0022_newrange_clientcert_matrix.txt`）：
- 叶子证书 serial `FE7B39240E873E2F286DB4A739E0C40F`，AKI **`65:91:B3:ED:6C:B0:2B:42:1B:64:46:F9:62:EF:85:DE:CA:D5:12:0A`**（旧代 `476e90…`）⇒ 整代 PKI 重新生成。
- 仍为 TLS1.3 only + `RequireAndVerifyClientCert`，可接受 CA 仍为 `CN = CV6 Fleet Diagnostics Root`。
- 无证书 → 116；VPN 证书 / 自签 / 同名假 CA → 48。
- ⇒ 客户端证书必须**按代**从云侧（平台附件/签发接口）取得；旧代材料不可复用。

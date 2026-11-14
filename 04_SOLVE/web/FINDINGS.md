# FINDINGS — Web / 服务面（task-2，web-recon）

采集时间：2026-11-14 09:05–09:20 CST｜工作根 `D:\qwb`
性质：全部为只读 GET/HEAD/OPTIONS 与无害空体 POST，未做口令爆破、未写任何服务端数据。

---

## 一、总表

| host:port | path | 方法 | status | 关键响应 | 判断 |
|---|---|---|---|---|---|
| 10.230.164.2:8080 | `/healthz` | **任意**（含 TRACE/DELETE） | 200 | `{"status":"ok"}\n`（16 B） | 存活探针，未做方法约束 |
| 10.230.164.2:8080 | `/graphql` | POST+合法JSON | 200 | `{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}\n` | **桩函数**：与请求内容无关 |
| 10.230.164.2:8080 | `/graphql` | POST+非法JSON | 400 | `{"error":"invalid GraphQL request"}\n` | 只做 `json.Unmarshal`，失败即 400 |
| 10.230.164.2:8080 | `/graphql` | GET/PUT/DELETE/PATCH/OPTIONS/TRACE | 405 | `{"error":"method not allowed"}\n` | 方法白名单只放 POST |
| 10.230.164.2:8080 | 其余 1576 条 | 任意 | 404 | `404 page not found\n` | Go 默认 NotFound |
| 10.230.164.3:8080 | `/healthz` | 任意 | 200 | `{"status":"ok"}\n` | 同款探针 |
| 10.230.164.3:8080 | 其余 1576 条 | 任意 | 404 | `404 page not found\n` | **无任何业务路由** |
| 10.230.164.4:8080 | `/healthz` | 任意 | 200 | `{"status":"ok"}\n` | 同款探针 |
| 10.230.164.4:8080 | 其余 1576 条 | 任意 | 404 | `404 page not found\n` | **无任何业务路由** |
| 10.230.164.3:8443 | TLS 握手 | — | — | TLS1.3 only；ALPN 不协商；leaf `CN=tbox`，issuer `CN=CV6 Fleet Diagnostics Root` | TBOX 诊断口 |
| 10.230.164.3:8443 | 无客户端证书 | — | — | `TLSV13_ALERT_CERTIFICATE_REQUIRED (116)` | 强制 mTLS，不可降级 |
| 10.230.164.3:8443 | 自签/冒名/伪造CA 客户端证书 | — | — | `TLSV1_ALERT_UNKNOWN_CA (48)` | **真验签**，必须有真实 CA 签发 |
| 10.230.164.3:8443 | 明文 HTTP | GET | 400 | `HTTP/1.0 400 Bad Request` + `Client sent an HTTP request to an HTTPS server.` | Go net/http over TLS，HTTP/1.x |
| 10.230.164.4:13401 | — | — | open | nmap: open | **新发现**，未深入，已移交 cgw-doip |

原始证据目录：`03_EVIDENCE/web/`（逐项对应见文末索引）

---

## 二、结论（三条）

### 1. 三个 8080 的服务面近乎空白，不存在隐藏管理端点

- 两轮词表共 **1576 条唯一路径**，三台合计 **5949 次请求，0 网络错误**
  （wave1 GET 407×3=1221 + wave1 POST 407×3=1221 + wave2 GET 1169×3=3507）。
- wave2 的 1169 条域名词（`fleet/diagnostics`、`cv6/*`、`tbox/*`、`ca.pem`、`client.pem`、`vehicles/CV6FF52FEE9EDDD86/*` …）在 `.2/.3/.4` 上 **全部 404**。
- 因此 `.3:8080` 与 `.4:8080` 确实只挂了 `/healthz`（且是 Go 精确路径注册，`/healthz/` 会 404）。
  它们最可能是**基础设施存活探针 / 诱饵**，业务入口不在 8080。
- 三台的 404 页、307 重定向体、响应头完全一致 ⇒ **同一套 Go 代码模板**（同源服务骨架），
  唯一可区分特征是 `.2:8080` 多一个 `/graphql`。

### 2. `.2:8080 /graphql` 是桩，不是可打的 GraphQL

同一 POST 请求换 5 种 body 得到**字节级相同**的响应：

```
{}                                  → {"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}
{"query":""}                        → 同上
{"query":"{ __typename }"}          → 同上          ← 真 GraphQL 引擎这里必回 __typename:"Query"
{"query":"{ vehicles { vin label } }"} → 同上
{ "query":"...", 各种 Authorization/X-API-Key/X-Vehicle-VIN 头 } → 同上
```

只有非法 JSON 会走 400。加了 `Authorization: Bearer`、`X-API-Key`、`X-Vehicle-VIN`、
`X-TBOX-ID` 全部无影响，换 `Content-Type`（`application/graphql`/`text/plain`/form）也无影响。

⇒ 该端点**不解析 query、不读鉴权头**，只是"校验方法 + 校验 JSON → 返回固定 demo 数据"。
`vin":"CV6000000DEMO0001"` 是硬编码的访客演示车，与真车 `CV6FF52FEE9EDDD86` 无关。
**判定：诱饵 / 占位实现，不要在这上面继续投入。**

### 3. `.3:8443` 是唯一有实质内容的面，且被强 mTLS 卡死 —— 关键是"证书从哪来"

服务端要求的链条很明确：

```
Acceptable client certificate CA names
  CN = CV6 Fleet Diagnostics Root
```

三组伪造证书全部被 `alert unknown ca (48)` 拒（自签 CN=client、自签 CN=tbox、复刻 issuer DN 的假 CA 签发），
说明服务端是 `RequireAndVerifyClientCert` 级别校验，**不是**只比对 CN 或 issuer 字符串的弱实现。

⇒ 想进 8443，必须拿到**由 `CV6 Fleet Diagnostics Root` 私钥真实签发的 client cert + 私钥**。
这类材质的合理来源只有一处：**车端**（CGW / DoIP / UDS 侧读出来的凭据或固件包）。
本机所有 HTTP 面（含词表里的 `ca.pem`/`client.pem`/`certs/root.pem`/`pki/*`）都没有泄露。

---

## 三、最可疑入口（按优先级）

**① `10.230.164.4:13400` DoIP → UDS 取凭据 → 打 `10.230.164.3:8443`（跨队友链路，首选）**

这是唯一能解开 mTLS 的方向。建议在 cgw-doip 已跑通的 UDS 通道上补这几类读取：

| 手法 | 服务 / 子功能 | 找什么 |
|---|---|---|
| `ReadDataByIdentifier 0x22` | 扫 `F1xx` / `F18x` DID 段（cgw-doip 已跑过 F186–F1A1） | PEM/DER 形态的证书、base64 私钥、序列号 |
| `RequestDownload 0x34` + `TransferData 0x36` | `0x38`/`0x34` 文件传输 | `/etc/cv6/client.pem`、`client.key`、`root.pem` 之类 |
| `ReadMemoryByAddress 0x23` | 任意可读段 | 内存里的证书结构（`-----BEGIN`、`0x30 0x82` DER 头） |
| `RoutineControl 0x31` | 诊断例程 | 有些实现有"导出诊断凭据"的例程 |

一旦拿到 cert/key，`04_SOLVE/web/tools/tls_client.py` 可直接打通并爆破 8443 的路径：

```bash
python 04_SOLVE/web/tools/tls_client.py 10.230.164.3 8443 \
    --cert client.pem --key client.key \
    --path /healthz --path /diagnostics --path / --path /vehicles
```

**② `10.230.164.4:13401`（新发现，本次未深挖）**

与 DoIP 13400 同段相邻，nmap 显示 open 但未做协议识别。可能是第二个 DoIP 通道 / DoIP over TLS / 诊断代理。
建议 cgw-doip 顺手看一眼（本次主动不碰，避免与其撞车）。

**③ `.2:8080 /graphql`（已排除）**

桩实现，见上文证伪。**不建议再投入**。

---

## 四、跨队依赖与移交

| 事项 | 给谁 | 说明 |
|---|---|---|
| 从 CGW 取客户端证书/私钥 | **cgw-doip** | 唯一能解 8443 mTLS 的来源；拿到后交给 web-recon 或 lead |
| `.4:13401` 协议识别 | **cgw-doip** | 本次只报 open，未做协议探测 |
| 是否把 8443 当最终目标 | **lead** | 若 8443 后面有 flag，整条链是 DoIP→凭据→8443；若 8443 也是桩，则 8080 面已穷尽 |

**仍未覆盖的面：** `8443` 的 HTTP 层内容（路径/schema/能否读写诊断），因为 TLS 层就没过去；
`13401` 未识别；UDP 面未扫（ICMP/UDP 不在 task-2 范围）。

---

## 五、证据索引（`03_EVIDENCE/web/`）

| 文件 | 内容 |
|---|---|
| `nmap_full_tcp_2_3_4.txt` | 三台全 TCP 端口扫描（唯一开放端口清单） |
| `brute_10.230.164.{2,3,4}_8080.{txt,json}` | wave1 GET 爆破（407 路径）原始结果 |
| `brute_POST_10.230.164.{2,3,4}.txt` / `brute_POSThost_*.json` | wave1 POST 爆破原始结果 |
| `brute2_10.230.164.{2,3,4}_8080.{txt,json}` | wave2 域名词 1169 条，全 404 |
| `fingerprint_raw_8080.txt` | 三台 `/`、`/healthz`、`/graphql`、OPTIONS、HEAD 的 `curl -i` 全量转录 |
| `method_matrix_8080.txt` | 8 种 HTTP 方法 × 4 路径 的状态矩阵 |
| `redirect_and_vhost_probe.txt` | 307 脏路径重定向原文 + 12 种 Host 头测试 |
| `h2c_grpc_probe.txt` | HTTP/2 前言探测（证明无 h2c/gRPC） |
| `tls_on_8080_test.txt` | 对 8080 发 ClientHello（证明非 TLS） |
| `8443_s_client_servername_tbox.txt` | 完整证书链 + 可接受客户端 CA 名单 + 握手详情 |
| `8443_tls_probe_matrix.txt` | 证书 x509 全文、ALPN×3、SNI 空/错、TLS1.2 拒绝、明文 400 |
| `8443_mtls_selfsigned_test.txt` | 三组伪造客户端证书的 `alert unknown ca` 原始输出 |
| `8443_ciphers_groups.txt` | TLS1.3 三套件、三曲线、会话恢复测试 |
| `gql_introspection_types.json` / `gql_introspection_fields.json` | introspection 请求的响应（证明被忽略，返回 demo 数据） |
| `gql_baseline_variants.txt` / `gql_auth_header_probe.txt` | 5 种 body + 5 种凭据头 + 3 种 Content-Type 对照 |
| `tls_probe/` | 自签/伪 CA/伪造客户端证书材料与 `openssl.cnf`（负向对照可复现） |

## 六、工具索引（`04_SOLVE/web/tools/`）

| 文件 | 用途 |
|---|---|
| `pathbrute.py` | 并发路径爆破，`WEB_METHOD`/`WEB_WORKERS`/`WEB_WORDLIST` 环境变量控制 |
| `h2probe.py` | 裸 socket h2c 前言 + gRPC health HEADERS 探测 |
| `tls_client.py` | mTLS 客户端，拿到 cert/key 后一键打 8443（多路径、报 ALPN/套件/告警名） |
| `wordlist_wave2.txt` | 1169 条车联网域名词表 |

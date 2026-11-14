# CV6 车联网挑战 — Web/服务面资产清单

> 采集者：web-recon（task-2）｜时间：2026-11-14 09:0x-09:2x CST｜目标网段 10.230.164.0/24
> 所有结论均可在 `03_EVIDENCE/web/` 找到原始响应。本文只做只读 GET/HEAD/OPTIONS 与无害空体 POST。

## 1. 端口总表（nmap -Pn -sT -n -p- ，全 65535）

| 主机 | 开放端口 | 判定 | 备注 |
|---|---|---|---|
| 10.230.164.2 | **8080/tcp** | TSP（Go HTTP/1.1） | 唯一开放端口；其余为 filtered（SYN 被丢，非服务） |
| 10.230.164.3 | **8080/tcp** | Go HTTP/1.1，仅 /healthz | |
| 10.230.164.3 | **8443/tcp** | TBOX 诊断口，TLS1.3 + 强制 mTLS | 证书 CN=tbox |
| 10.230.164.4 | **8080/tcp** | Go HTTP/1.1，仅 /healthz | |
| 10.230.164.4 | **13400/tcp** | DoIP（cgw-doip 负责） | |
| 10.230.164.4 | **13401/tcp** | **新发现**，与 DoIP 同段 | 本任务未深入（避免与 cgw-doip 冲突），已上报 |

原始：`03_EVIDENCE/web/nmap_full_tcp_2_3_4.txt`

**关键结论：三个 8080 都是明文 HTTP/1.1，不是 TLS、不是 h2c/gRPC。**
- 对 `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` 前言回 `HTTP/1.1 400 Bad Request` + `Connection: close`（Go net/http 行为），
  无 SETTINGS 帧 ⇒ 不是 h2c，不能跑 gRPC。证据 `03_EVIDENCE/web/h2c_grpc_probe.txt`
- 对 TLS ClientHello 回 `wrong version number` ⇒ 不是 TLS。证据 `03_EVIDENCE/web/tls_on_8080_test.txt`

## 2. 路径枚举结果

两轮词表，均覆盖 GET 与 POST（空体 `{}`，`Content-Type: application/json`）：

| 轮次 | 词表 | 路径数 | 主机 | 命中（非 404） |
|---|---|---|---|---|
| wave1 通用 | API/OTA/诊断/管理/pprof/.git/swagger/actuator/… | 407 | .2:8080 | `/healthz` 200、`/graphql` 405 |
| wave1 通用 | 同上 | 407 | .3:8080 | 仅 `/healthz` 200 |
| wave1 通用 | 同上 | 407 | .4:8080 | 仅 `/healthz` 200 |
| wave2 域名词 | `fleet/diagnostics`、`cv6/*`、`tbox/*`、`ca.pem`、`client.pem`、`vehicles/<VIN>` 等 1169 条 | 1169 | 三台 | **0 命中**（除已有 /healthz） |

合计 **1576 条唯一路径 × 3 主机**，wave2 的 1169 条在三台上全部 404。

### .2:8080（TSP）——真实存在的两个路由

| 路径 | 方法 | 状态 | 响应 |
|---|---|---|---|
| `/healthz` | 任意方法（GET/HEAD/POST/PUT/DELETE/PATCH/OPTIONS/TRACE） | 200 | `{"status":"ok"}\n` |
| `/graphql` | POST + 合法 JSON | 200 | `{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}\n` |
| `/graphql` | POST + 非法 JSON | 400 | `{"error":"invalid GraphQL request"}\n` |
| `/graphql` | GET/PUT/DELETE/PATCH/OPTIONS/TRACE | 405 | `{"error":"method not allowed"}\n` |
| 其它 | 任意 | 404 | `404 page not found\n` |

### .3:8080 / .4:8080——只有存活探针

`/healthz` 对**所有 HTTP 方法**都返回 200（连 TRACE、DELETE 都 200），说明注册时未做方法约束；
`/healthz/`（带尾斜杠）返回 404 ⇒ 注册的是**精确路径**而非子树。
除此之外 1576 条路径全 404，包括 `/metrics`、`/debug/pprof/*`、`/.git/HEAD`、`/swagger`、`/openapi.json`、`/api/*`。

## 3. 指纹（三台高度同源）

| 特征 | .2:8080 | .3:8080 | .4:8080 |
|---|---|---|---|
| `Server` 头 | **不存在**（Go net/http 默认） | 同上 | 同上 |
| `X-Powered-By` | 不存在 | 不存在 | 不存在 |
| 404 页 | `404 page not found\n`（19 B，`text/plain; charset=utf-8` + `X-Content-Type-Options: nosniff`） | 同 | 同 |
| 脏路径（`//healthz`、`/./healthz`、`/a/../healthz`） | **307** + `Location: /healthz` + `<a href="/healthz">Temporary Redirect</a>.` | 同 | 同 |
| `/%2e/healthz` | 404（按转义路径路由，不先解码）⇒ Go **1.22+ ServeMux** 系行为 | 同 | 同 |
| HTTP/2 | 不支持（无 h2c，无 TLS） | 同 | 同 |
| h2 前言（`PRI *`） | `400 Bad Request` + `Connection: close` | 同 | 同 |
| CORS | 无任何 `Access-Control-*` 头（OPTIONS /graphql 直接 405） | — | — |
| Cookie | 无 | 无 | 无 |
| vhost 路由 | — | 换 12 种 `Host`（tbox/tsp/cv6/fleet/localhost/127.0.0.1/…）返回完全一致 | — |

**区分三台的唯一可靠指纹：`/graphql` 是否存在于 8080。** .2 有（405/400/200 三态），.3/.4 没有。
三台的 `/healthz` 响应体、头、404 页、307 重定向体**完全一致**，无法从响应区分。

原始：`03_EVIDENCE/web/fingerprint_raw_8080.txt`、`03_EVIDENCE/web/method_matrix_8080.txt`、`03_EVIDENCE/web/redirect_and_vhost_probe.txt`

## 4. 10.230.164.3:8443（TBOX 诊断口）

### 4.1 服务端证书

| 字段 | 值 |
|---|---|
| Subject | `CN=tbox`（SAN: `DNS:tbox`，仅此一个） |
| Issuer | `CN=CV6 Fleet Diagnostics Root` |
| 序列号 | `50:2c:0e:d0:df:fb:9e:ca:af:2b:ce:9f:97:73:78:27` |
| 有效期 | NotBefore `2026-11-14T00:00:32Z`，NotAfter `2026-12-14T01:00:32Z` |
| 公钥 | EC P-256（prime256v1），签名算法 ecdsa-with-SHA256 |
| 扩展 | KeyUsage=critical,DigitalSignature；EKU=**仅** TLS Web Server Auth；AKI=`47:6E:90:16:4F:64:70:BB:1C:80:72:36:AB:3C:54:70:03:78:10:99` |
| SHA-256 指纹 | `9B:88:66:9E:74:89:8E:7B:70:39:74:DF:20:A7:A1:4C:DE:EF:35:22:98:9D:29:46:BD:A1:2D:CE:8C:BD:DC:3B` |
| 链长度 | **只发叶证书**，不带中间/根（所以 `Verify return code: 21`） |

### 4.2 握手参数

| 项目 | 结果 | 证据 |
|---|---|---|
| 协议版本 | **只允许 TLS1.3**；`-tls1_2` 收到 `alert protocol version (70)` | `8443_tls_probe_matrix.txt` §7 |
| 密码套件 | TLS_AES_128_GCM_SHA256（默认）、TLS_AES_256_GCM_SHA384、TLS_CHACHA20_POLY1305_SHA256 **三个都接受** | `8443_ciphers_groups.txt` |
| 密钥交换组 | X25519、P-256、P-384 都接受 | 同上 |
| ALPN | **不协商**（客户端送 `h2` / `http/1.1` / `h2,http/1.1` 全部返回 `No ALPN negotiated`）⇒ 服务端未配置 NextProtos，不是标准 Go http.Server 的 h2 自动升级路径 | §2-4 |
| SNI | 空 SNI、错 SNI（`wrong.example`）返回**同一张证书**，无 SNI 路由 | §5-6 |
| 会话恢复 | 每次都是 `New`，无 ticket 重用（因握手在 client-cert 阶段即失败） | `8443_ciphers_groups.txt` |

### 4.3 双向认证是硬墙（已用三组伪造证书证伪）

```
Acceptable client certificate CA names
  CN = CV6 Fleet Diagnostics Root
```

| 客户端证书 | 结果 | 含义 |
|---|---|---|
| 不提供证书 | TLS1.3 `alert certificate_required (116)` | 强制 mTLS，无法降级到无证书 |
| 自签 `CN=client` | `alert unknown ca (48)` | 服务端**真正验签**，不是只比对 DN |
| 自签 `CN=tbox`（冒充同名） | `alert unknown ca (48)` | 名字匹配也没用 |
| 伪造 CA `CN=CV6 Fleet Diagnostics Root` 签发 | `alert unknown ca (48)` | 只复刻 issuer DN 字符串无效，必须能验签 |

⇒ **必须拿到由 `CV6 Fleet Diagnostics Root` 真实私钥签发的客户端证书+私钥**，否则 8443 连 HTTP 层都进不去。

原始：`03_EVIDENCE/web/8443_s_client_servername_tbox.txt`、`03_EVIDENCE/web/8443_mtls_selfsigned_test.txt`、
`03_EVIDENCE/web/tls_probe/`（自作的自签/伪造证书材料，可复现）

### 4.4 明文打到 8443

```
GET http://10.230.164.3:8443/
→ HTTP/1.0 400 Bad Request
  Client sent an HTTP request to an HTTPS server.
```

这句是 **Go net/http 在同一端口收到明文请求时的内置响应**，说明 8443 在 mTLS 之后跑的是 Go HTTP 栈（HTTP/1.x，非 h2，因为无 ALPN）。

## 5. 已就绪的工具

| 文件 | 用途 |
|---|---|
| `04_SOLVE/web/tools/pathbrute.py` | 并发路径爆破（支持 GET/POST/HEAD、外部词表 `WEB_WORDLIST`、软 404 基线） |
| `04_SOLVE/web/tools/h2probe.py` | 原始 h2c / gRPC 探测（发 HTTP/2 前言 + SETTINGS + gRPC health HEADERS） |
| `04_SOLVE/web/tools/tls_client.py` | **拿到客户端证书后一键打通 8443**：`--cert/--key/--sni/--path/--method`，支持多路径、报出 TLS 版本/套件/ALPN/失败告警名 |
| `04_SOLVE/web/tools/wordlist_wave2.txt` | 1169 条域名词表（fleet/cv6/tbox/vehicles/<VIN>/ca.pem/client.pem…） |

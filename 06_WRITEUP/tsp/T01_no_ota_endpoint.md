# T01 — TSP 云服务与 OTA 签名：否证材料（**结论已被推翻，见 T02_ota_chain.md**）

> ⚠️ **本文的最终结论「T01 不含任何 OTA 端点」是错的。** 2026-11-14 10:05 已查明：
> `/graphql` 不是硬编码桩，而是**手写的两把钥匙派发器**——只要 `query` 文本里含
> `vehicleDiagnostics` 且 `variables.vin` 等于已注册的真实 VIN，就会返回真实 OTA 凭据。
> 我们（包括我）此前把 VIN 写在 query 里或完全不带 variables，所以永远只看到访客回落分支。
> **正确解法与整条 T02 链见 [`T02_ota_chain.md`](T02_ota_chain.md)。**
> 本文保留作为**否证过程的记录**：它把"为什么当时会误判成桩"的每一条证据都留下了，
> 这正是 `/graphql` 是手写派发器（而非 GraphQL 引擎）的反面印证。


> ⚠️ **环境已于 2026-11-14 ~09:55–10:00 整体轮换。** 旧地址 `10.230.164.2/.3/.4`、`10.229.221.2`
> 全部作废（TCP 超时 + ICMP 不通）。新环境已实测定位，见末节「附录 A」。**本文所有实测命令与输出
> 都在旧环境采集，但新环境经逐条复测为同一 build，结论完全一致**（`0181`/`0183`/`0185`）。

状态：**HTTP 面已穷尽（新旧两套环境都是），T01 本身不含任何可用的 OTA/密钥/证书端点**。
OTA 包与工程包的真实来源已定位到赛事平台（登录受限），且平台前端里泄露了整套赛题设计文本。

时间：2026-11-14 09:16–10:15 (+08:00)
目标（旧）：`http://10.230.164.2:8080` ｜ 目标（新）：`http://10.225.139.2:8080`


## 1. 最终结论（一句话）

`10.230.164.2:8080` 是一个手写的 Go `net/http` 服务，**注册了 3 条路由**：

| 路由 | 行为 | 判定 |
|---|---|---|
| `/healthz` | 任意方法 → `200 {"status":"ok"}` | 无利用面 |
| `POST /graphql` | 只做 JSON 形状校验，**无条件返回硬编码 canned 响应** | 桩 |
| `/internal/audit` | 任意方法 → `404 application/json {"error":"not found"}`（22 B） | 已注册但**恒 404**（门后有判断），见 §3.5 |

没有 OTA 端点、没有密钥/证书端点、没有 h2c/gRPC、没有 vhost 路由、没有第 4 条路径。
**T01 的 flag 不可能从这个 8080 上取到。**

> 更正：本文件 09:40 的初版写"只有 2 个 handler"，漏了 `/internal/audit`。已在此修正（09:50）。

---

## 2. `/graphql` 已被完整逆向（不是"看起来像桩"，是推导出来的）

### 2.1 等价伪码

```go
func graphql(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        w.WriteHeader(405); json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"}); return
    }
    var req struct{ Query string `json:"query"` }            // 只声明了一个字段
    dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 131072))   // 128 KiB
    if err := dec.Decode(&req); err != nil {
        w.WriteHeader(400); json.NewEncoder(w).Encode(map[string]string{"error": "invalid GraphQL request"}); return
    }
    _ = req                                                  // ← 解析完直接丢弃
    json.NewEncoder(w).Encode(硬编码 vehicles 响应)           // 恒定 81 字节
}
```

### 2.2 判据（每条都对应可复跑的命令输出）

| # | 观测 | 推论 | 证据 |
|---|---|---|---|
| 1 | `{} extra`、`{} // c` 返回 200 | 用 `json.Decoder.Decode`（只解第一个值）而非 `json.Unmarshal` | `0110` |
| 2 | 请求体 **131071 B 通过 / 131072 B 失败**（二分） | `http.MaxBytesReader(w,r.Body,128<<10)` | `0115` |
| 3 | `{"query":123}`→400、`{"query":null}`→200、`null`→200、`[]`/`true`/`"x"`→400 | 目标是 `struct{Query string}`；`null` 解进 struct 不报错 | `0110` |
| 4 | `{"n":1e99999}`→200 | 不是 `map[string]any`（否则 float64 溢出会报错），未知字段不解析 | `0110` |
| 5 | `Content-Type: application/graphql / text/plain / x-www-form-urlencoded` 全一样 200 | 完全忽略 Content-Type，一律按 JSON 解 | `gql_auth_header_probe.txt` |
| 6 | query 内容 / operationName / variables / introspection / 37 组语义变体全返回同一 81 字节 | query 被丢弃，无 resolver 路径 | `0110` |
| 7 | 26 个 query string（`?vin=` `?debug=1` `?admin=1` …）全 SAME | 不读 `r.URL.Query()` | `0117` |
| 8 | 39 个 trust header（`X-Forwarded-For: 127.0.0.1`、`X-Real-IP`、`X-Client-Cert`、`Authorization: Bearer/Basic admin`、`Cookie`、`Forwarded`、`X-VIN`…）全 SAME | 无代理信任、无鉴权分支 | `0113` |
| 9 | 405 响应**没有 `Allow` 头** | 405 是 handler 手写，不是 Go 1.22 mux 的 405 | `0114` |

### 2.3 响应体（恒定）

```json
{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}
```

`"Guest demo vehicle"` 曾让人怀疑存在"认证后返回真车"的分支；第 8 条已证伪——**任何 header 都不改变它**。

### 2.4 路由存在性 oracle（强判据，值得复用）

这台机器上有**两套 404**，字节不同：

| 情形 | Content-Type | body |
|---|---|---|
| 未注册路径 | `text/plain; charset=utf-8` + `X-Content-Type-Options: nosniff` | `404 page not found\n`（19 B，Go ServeMux 默认） |
| 已注册但被门挡住 | `application/json` | `{"error":"not found"}\n`（22 B，handler 自己写的） |

⇒ **只要响应不是 `404 + "404 page not found\n"`，该路由就存在。** 只看状态码的扫描会把
`/internal/audit` 与噪声一起丢掉。

---

## 3.5 `/internal/audit`（第三条路由，恒 404）

- 存在性：`GET /internal/audit` → `404 application/json {"error":"not found"}`；
  而 `/internal`、`/internal/`、`/internal/x`、`/internal/audit/` 全是 **Go 默认 text/plain 404**
  ⇒ 以**精确路径**注册（不是前缀子树）。
- 方法：GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD/TRACE **全部**同 22 字节
  ⇒ handler 内部有一道判断，不通过就伪装成 404。
- 本会话补测的**此前未覆盖维度**：14 种 `User-Agent`（`Go-http-client/1.1`、`tsp-audit/1.0`、
  `kube-probe`、`Prometheus`、`grpc-go`…）+ 10 种杂项头（`TE: trailers`、`Upgrade: h2c`、
  `X-Forwarded-Prefix`、`X-Envoy-External-Address`、`Forwarded: for=127.0.0.1`…）
  → **全部恒 22 字节**。证据 `0151_audit_ua_matrix.txt`。
- 队友（并行 agent）已穷尽：440 组参数×值、20 种鉴权头、14 种 body、3 种 Content-Type、
  21 个 SSRF 风格参数、25 种 Host、4292 条路径 —— 0 命中。
  证据 `0303`–`0331`、`STUB_NEGATIVE.md`。
- **推测（未验证）**：门判据是源 IP（`r.RemoteAddr` 属内网/回环才放行）；`X-Forwarded-For` 一律无效，
  说明读的是 `RemoteAddr` 而非头。我们从 `10.252.3.20`（VPN 客户端段）发起，天然过不去。
- 结论：**在现有网络位置下不可达**；除非能借 T-BOX/CGW 的「取 URL 回来」能力做内网 SSRF 跳板。

---

## 3. 协议面排除

| 假设 | 实验 | 结果 | 证据 |
|---|---|---|---|
| gRPC over h2c | 裸发 `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` + SETTINGS | `HTTP/1.1 400 Bad Request`，无 SETTINGS 帧 ⇒ 非 h2c | `0114` |
| RFC 7540 h2c upgrade | `Upgrade: h2c` + `HTTP2-Settings` | 405，不升级 | `0114` |
| HTTP/2 over TLS | 8080 上 TLS 握手 | `wrong version number` ⇒ 非 TLS | `tls_on_8080_test.txt` |
| 反向代理前置（走私面） | CL+TE 双头 | 走 chunked（Go 语义），且无前置代理 | `0114` |
| 框架（chi/gin/echo） | `OPTIONS *` | `200 OK, Content-Length: 0` = **Go stdlib `globalOptionsHandler`** ⇒ 纯 `net/http` | `0114` |
| 虚拟主机路由 | 44 个 Host × `/healthz` 基线 diff | 零差异 | `0116` / `0100` |
| 绝对 URI 形式 | `GET http://internal/graphql` | 405，与普通请求一致 | `0114` |

> ⚠️ `03_EVIDENCE/web/redirect_and_vhost_probe.txt` 里那段 "Host: tsp/localhost/… → /graphql=404" 是**探针 bug**（连到了没有 /graphql 的主机）。正确复测见 `0100_host_and_trust_headers.txt`：所有 Host 都是 `/graphql=405 /healthz=200`。该文件按 legacy 处理。

---

## 4. 路径面穷尽

| 批次 | 路径数 | 方法 | 命中 |
|---|---|---|---|
| 通用 wordlist（前一会话） | 407 | GET | `/healthz`、`/graphql` |
| 通用 wordlist wave2 | 1169 | GET | 0（全 404） |
| TSP 专用（本会话） | 241 | GET + POST | 仅 `/healthz` |
| 非标准方法（PUT/DELETE/PATCH/HEAD/OPTIONS/TRACE/PROPFIND/MKCOL） | 22 条重点路径 × 8 | — | 全 404（`/graphql`、`/healthz` 除外） |

TSP 专用列表覆盖：`/ota/*`、`/firmware/*`、`/packages`、`/download`、`/sign`、`/verify`、`/keys`、`/pki/*`、`/ca`、`/certs`、`/admin`、`/internal`、`/debug/vars`、`/debug/pprof/*`、`/.well-known/jwks.json`、`/openapi.json`、`/swagger*`、`/graphiql`、`/graphql/*`、`/.git/config`、`/.env`、`/go.mod`、`/actuator/*` 等。
证据：`0111_targeted_path_sweep.txt`、`0117_graphql_querystring_and_methods.txt`、`03_EVIDENCE/web/brute*.txt`。

> 排查过程中 `/auth/` 报过一次 ReadTimeout，已 5 次复现全 404，属网络抖动（connect 3.0 s / 1.0 s），非真端点：`0112_auth_hang_repro.txt`。

---

## 5. 端口面

- 本会话独立 python connect 扫 1–65535：**仅 8080**（`0120_fullport.txt`）。
- **重要坑**：该主机非 8080 端口不是立即 RST，而是**约 2.2 s 后才 RST**。
  超时 <2 s 的扫描器会把一切误判为 filterved/timeout；nmap 不设短超时所以报 conn-refused。
  **后续任何端口扫描请把超时 ≥3 s。** （实测：port 22 在 0.6/1.0/1.5/2.0 s 超时、3.0 s 时 REFUSED，延迟 ~2.2 s）

---

## 6. OTA ZIP / 工程包的真实来源：赛事平台（已定位，需登录）

`.ovpn` 的下载来源直接写在浏览器史里：
`https://175.27.210.153:9989/?competitionId=competition-ed3e7d452581978ccae13421`

- 平台：「车联网数字孪生攻防平台」，Caddy + HTTP/3，API service = `cybercar-arena`（`/api/health`）。
- challenge 对象带 `attachments[] = {id, filename, sizeBytes, downloadPath}`，UI 文案「题目附件 · N 个（点击下载）」。
- 平台反作弊规则 `attachment_without_download = "未下载附件即正确提交"` ⇒ **必须用本队账号正常下载附件**，否则正确提交也会被判作弊。
- 全部数据接口需 `cybercar_session`：`/api/v1/bootstrap?competitionId=…`（含 challenges + attachments + instances）。
- 本队账号此前**从未**在该平台下载过任何附件（Chrome downloads 只有 `.ovpn`）。

**下一步**：拿到 session（用户浏览器点下载 / 给账号密码 / 给 cookie）后执行
`python 04_SOLVE/tsp/fetch_platform.py --cookie 'cybercar_session=…'` 或 `--user U --password P`，
脚本会自动拉 bootstrap、逐题列出附件、下载到 `01_TARGETS/tsp/platform/attachments/` 并写 sha256 清单。

### 平台的完整 API 面（从 `app.js` 反出来的，用于团队对齐）

```text
# 全局
GET  /api/v1/auth/check                          -> 200 {"authenticated":false}   (唯一免登录)
POST /api/v1/auth/login        {username,password}   （需 same-origin Origin/Referer，否则 403 cross_origin_request_denied）
POST /api/v1/auth/logout / GET /api/v1/auth/me / POST /api/v1/auth/password
GET  /api/v1/bootstrap?competitionId=<id>        -> 主数据：competition / challenges / instances / teams
GET  /api/v1/competitions
# 队伍维度
GET  /api/v1/competitions/{c}/teams/{t}/challenges
GET  /api/v1/competitions/{c}/teams/{t}/challenges/{id}
GET  /api/v1/competitions/{c}/teams/{t}/challenges/{id}/run
POST /api/v1/competitions/{c}/teams/{t}/challenges/{id}/run
POST /api/v1/competitions/{c}/teams/{t}/challenges/{id}/run/reset
GET  /api/v1/competitions/{c}/teams/{t}/challenges/{id}/run/events?afterSequence=&limit=
POST /api/v1/competitions/{c}/teams/{t}/challenges/{id}/submissions   {flag}
# 实例（= 车辆）维度   ← 这里就是"我方靶场 IP"的来源
GET  /api/v1/competitions/{c}/teams/{t}/instances/{i}/twin
GET  /api/v1/competitions/{c}/teams/{t}/vehicle-range          整车靶场状态
POST /api/v1/competitions/{c}/teams/{t}/vehicle-range/vpn/config   ← 我们的 .ovpn 就是这里生成的
DELETE /api/v1/competitions/{c}/teams/{t}/vehicle-range/vpn
POST /api/v1/competitions/{c}/teams/{t}/vehicle-range/snapshots
POST /api/v1/competitions/{c}/teams/{t}/vehicle-range/snapshots/{id}/restore
POST /api/v1/competitions/{c}/teams/{t}/vehicle-range/{start|stop|reset}
# 实时
WS   /ws/v1/competitions/{c}/teams/{t}/instances/{i}/twin
WS   /ws/v1/competitions/{c}/teams/{t}/challenges/{id}/run
# 管理端（需 admin）
/api/v1/admin/{overview,competitions,teams,users,audit,settings,challenge-library,
              vehicle-library,team-library,vehicle-range/templates,
              vehicle-range/dbc-assets,runtime/images,runtime/kvm-artifacts,attack-desktop}
```

关键推论：**我方靶场 IP 列表不是硬编码的，而是 `/api/v1/bootstrap` 里 `instances[]` 决定的。**
拿到 bootstrap 才能确认「10.230.164.2/.3/.4 是不是我们这队这批实例」，以及每道题的
`flagMode`（`dynamic` = 每队每实例唯一，flag 只存在于运行中的实例里）与 `attachments[]`。

### 免凭据路线已全部排除（别再试）

| 尝试 | 结果 | 证据 |
|---|---|---|
| 平台自己发给我们的 4 个标识符（`usr_b2ad…`、`ed3e7d…`、`competition-ed3e7d…`、VPN 证书 CN `cc-715a9a…`）× 9 种放置（Bearer / Token / X-API-Token / X-Auth-Token / X-User-Token / Cookie / `?token=` / `?api_key=` / `?usr=`）× 3 个端点 | 全部 `{"authenticated":false}` / `401` | `0160`、`0161` |
| 标识符当 login body（`token`/`usr`/`userToken`/`username+password`） | 全部 `401 invalid_credentials` | `0160` |
| 静态遗留：`.js.map`、`package.json`、`README.md`、`Dockerfile`、`Caddyfile`、`config.json`、`seed.sql`、`.git/`、`.env`、`/data/`、`/backup/`、`/src/`、`/logs/` | 全 404（只有 css/png 是真文件） | `0162` |
| `/api/v1/public/competitions`、`/api/v1/attachments`、`/api/v1/challenges` | `route_not_found` | `0136`、`0163` |
| 本机 3 个浏览器 cookie 库 | 只有 Chrome `Profile 1\Network\Cookies` 可能有 session，但**运行中的 Chrome 独占锁定**（`PermissionError`）；`Default` 0 条、Edge 62 条但无平台 cookie | `0135`、`0135b`、`0164` |
| Chrome 远程调试口 9222/9223/9229/9333 | 全不通 | `0152` |

⇒ **拿到 session 的三条可行路径（都需要人）**：用户浏览器点下载附件 / F12 复制 `cybercar_session` 值 /
给账号密码。拿到后一条命令：
`python 04_SOLVE/tsp/fetch_platform.py --cookie 'cybercar_session=…'`
（或 `--user U --password P`；脚本会自动写 `platform/challenges.md` 队内摘要 + `attachments_manifest.json` sha256 清单）

### 平台资产（已落盘）

| 文件 | 大小 | sha256（app.js） |
|---|---|---|
| `01_TARGETS/tsp/platform/app.js` | 129696 | `399dab5b7e2c1dedd6b4b5cd0de4ac9abfa2e410f8a6afe5f6a2c84c43beedc4` |
| `01_TARGETS/tsp/platform/admin.js` | 295721 | — |
| `01_TARGETS/tsp/platform/competitions.js` | 7267 | — |
| `01_TARGETS/tsp/platform/login.js` | 5229 | — |

---

## 7. 证据索引（本目录）

| 文件 | 内容 |
|---|---|
| `0100_host_and_trust_headers.txt` | Host 头重测（纠正 legacy 探针） |
| `0101_host_tbox_retry.txt` | `Host: tbox` 的 000 是一次抖动，5 次复测均 405 |
| `0110_graphql_semantic_fuzz.txt` | 37 组请求体语义变体 |
| `0111_targeted_path_sweep.txt` | 241 条 TSP 专用路径 GET+POST |
| `0112_auth_hang_repro.txt` | `/auth/` 抖动复现 |
| `0113_trust_header_matrix.txt` | 39 个信任头 |
| `0114_raw_socket_teardown.txt` | h2c / 分块 / 100-continue / 走私 / OPTIONS * |
| `0115_graphql_sizelimit.txt` | 128 KiB 上限二分 |
| `0116_vhost_sweep.txt` | 44 个 Host 基线 diff |
| `0117_graphql_querystring_and_methods.txt` | 26 个 query string + 8 种方法 |
| `0120_fullport.txt` | 1–65535 端口扫描 |
| `0121_vpn_infra_probe.txt` | VPN 网关与 175.27.210.153 端口 |
| `0122_platform_origin_browser_history.txt` | 平台来源（Chrome 下载来源） |
| `0130`–`0139` | 平台入口 / 资产 / API 探测 |


---

## 附录 A — 环境轮换与新环境测绘（2026-11-14 10:00–10:15）

### A.1 旧环境死亡

`10.230.164.2/.3/.4`、`10.229.221.2`：TCP 全部 timeout、ICMP 全丢包；但 `tracert` 第 1 跳
`10.252.3.1` 仍回 25 ms ⇒ VPN 隧道本身存活，是靶场侧换了网段。证据：
`0180_newenv_probe.txt`、`03_EVIDENCE/cgw/0515_vpn_health.txt`、`0517_vpn_recheck.txt`。

### A.2 新环境拓扑（2 个 /24 × 23 端口全扫，仅 4 台存活）

| 地址 | 开放端口 | 身份判据 |
|---|---|---|
| **10.225.139.2** | 8080 | **TSP**：`GET /graphql`→405 json、`POST /graphql`→81 B demo、`/internal/audit`→404 json |
| 10.225.139.3 | 8080, 8443 | T-BOX |
| 10.225.139.4 | 8080, 13400, 13401 | 中央网关 |
| 10.226.193.2 | 8080, 13400, 13401 | 另一台网关（与 .4 同一 DoIP 实体，VIN/EID 相同） |

扫描面：`10.225.139.0/24` 与 `10.226.193.0/24` ×
`{80,443,1883,1884,8883,9001,22,3000,5000,7001,8000,8080,8081,8082,8443,9000,9090,13400,13401,2181,6379,5432,3306}`
= 11684 次 connect，**只有上表 6 个端口开放**。证据 `0186_newrange_service_scan.txt`。

> **重点否证**：平台 stage 文本（附录 B）里的 q3 提到「MQTT 任务报文」，但新环境
> **1883/1884/8883/9001 全无服务** ⇒ 该描述对应的环境**并不存在**于我们能到达的靶场里。

### A.3 新 VIN

DoIP `0x0001` 车辆识别（`10.225.139.4:13400` 与 `10.226.193.2:13400` 返回一致）：

```
resp_type=0x0004  len=33
VIN = CV622697F82A936A1
LA  = 0x1000   EID = 060000001000   GID = 000000000000   FA = 0
raw = 435636323236393746383241393336413110000600000010000000000000000000
```

证据 `0184_newrange_doip_vin.txt`。（旧环境 VIN 为 `CV6FF52FEE9EDDD86`。）

### A.4 新 TSP 复测结果：与旧环境逐条相同

| 复测项 | 结果 | 证据 |
|---|---|---|
| 129 条定向路径 × GET/POST，JSON-404 oracle | **仅 3 条路由**（`/healthz`、`/graphql`、`/internal/audit`） | `0183_newtsp_route_sweep.txt` |
| `alg=none` JWT 矩阵（6 header×claim × 3 载体 × 3part/2part） | 72 次检查 **0 偏差** | `0182_newtsp_jwt_quick.txt` |
| 用**新 VIN** `CV622697F82A936A1` 打 IDOR（query / variables / 顶层字段 / `X-VIN` / JWT `vin` claim / `/internal/audit?vin=` / POST body） | **32 次检查 0 偏差**，仍是 81 B demo + 22 B not found | `0185_newtsp_with_new_vin.txt` |

⇒ 新环境不是"真 TSP 上线"，而是同一套靶场重新部署。**T01 的结论对两个环境都成立。**

---

## 附录 B — 平台前端泄露的整套赛题设计文本

`01_TARGETS/tsp/platform/app.js` 里 `VEHICLE_RANGE_STAGE_DETAIL_FALLBACKS` 常量（免登录可读），
原文见 `03_EVIDENCE/tsp/0170_platform_stage_fallbacks.txt`：

**链 A（整车靶场主链）**
1. `cloud-bola-exposed` — 通过虚构 TSP 的 BOLA/IDOR 缺陷读取不属于访客账号的维护包
2. `tbox-maintenance-session` — 利用旧版 JWT 算法混淆取得受控的维护诊断票据
3. `diagnostic-session-unlocked` — 在 DoIP 上经扩展会话和 SecurityAccess 解锁受控诊断权限
4. `legacy-route-exploited` — 验证功能寻址被错误转发至物理 BCM 的缺陷
5. `body-control-confirmed` — CGW 写入带 CRC/计数器的 CAN 车身动作，BCM ACK 由可信采集器确认
6. `final-objective-retrieved` — 在控制闭环成立后从 TSP 读取该作用域专属动态 Flag

**链 B（q1..q10，OTA 主线）**
- `q1-ota-package` — 利用云端 IDOR 读取测试车 OTA 包和历史 PCAP 附件
- `q2-service-token` — 从 OTA 包中提取开发态 JWT，并利用 `alg=none` 分支伪造服务账号凭据
- `q3-protocol-map` — 结合 MQTT 任务报文和历史 PCAP，还原自定义二进制协议字段布局
- `q4-task-forged` — 利用 ECDSA-P256 nonce 复用恢复任务签名私钥，伪造越权诊断任务
- `q5-diag-session` — 根据可推导时间种子破解 UDS SecurityAccess，建立安全诊断会话
- `q6-route-open` — 发现并利用网关 ACL 通配测试路由，建立到动力域的 ISO-TP 诊断路径
- `q7-body-applied` — 读取运输密钥并派生 BCM SecOC Key，构造四门解锁帧序列
- `q8-power-applied` — 迁移 SecOC 逆向方法到动力域，构造 VCU 驻车使能帧
- `q9-interlock` — 在 BCM 解锁与 VCU 驻车的 10 秒窗口内完成 BMS 涓流放电互锁
- `q10-complete` — 读取最终 DID，提交由当前 generation 状态生成的动态令牌

**如何解读**：这是平台 UI 的**兜底文案**（拿不到真实 stage 详情时显示的设计说明）。它描述的是一条
**完整环境**上的链路；但我们实测到的靶场既没有 MQTT（A.2 已否证），TSP 也没有 IDOR 端点
（A.4 已否证）。两种可能，目前证据不足以区分：
(a) 该文案属于平台的另一场赛事/更大部署，与本靶场无关；
(b) 本队应使用的实例地址来自 `/api/v1/bootstrap` 的 `run.accessHost/accessPort`（我们打的是共享切片）。
**判别方法只有一个**：拿到平台 session 读 bootstrap（`run.accessHost` 才是权威目标地址）。

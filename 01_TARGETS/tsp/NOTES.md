# TSP `10.230.164.2:8080` —— 侦察笔记（tsp-hunter）

更新时间：2026-11-14 09:45 (+08)
状态：**攻击面已穷尽；TSP 本身拿不到 OTA 资源。发现一个新的隐藏路由 `/internal/audit`。**

---

## 0. 一句话结论

`10.230.164.2` 全机只有 **TCP/8080 一个端口**，8080 上只有 **3 条路由**：

| 路由 | 方法 | 行为 | 判定 |
|---|---|---|---|
| `/healthz` | 任意（含 TRACE/PROPFIND） | `200 {"status":"ok"}\n`（16B） | 无鉴权、无状态、无参数，**无利用面** |
| `/graphql` | 仅 POST | 恒返回 `{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}` | **硬编码桩**，不解析 GraphQL |
| `/internal/audit` | 任意 | 恒返回 `404 {"error":"not found"}\n`（22B） | **新发现**。真实注册的 handler（不是 Go 默认 404），但对外部一切探测恒 404 |

**没有任何 OTA / campaign / 签名 / 固件 / 诊断入口。** 任务语义里说的 BOLA/IDOR 在 TSP 上**无法落地**。

---

## 1. 关键方法论（给队友复用）

**路由存在性判别器（强 oracle）** —— 这台机器上有两套 404，字节不同：

```
未注册路径      -> 404  Content-Type: text/plain; charset=utf-8
                        X-Content-Type-Options: nosniff
                        body = "404 page not found\n"          (19B, Go ServeMux 默认)
已注册的 API 路径 -> 404  Content-Type: application/json
                        body = {"error":"not found"}\n          (22B, handler 自己写的)
```

⇒ **只要响应不是 `404 + "404 page not found\n"`，该路由就存在。**
这个 oracle 比只看状态码强得多：`/internal/audit` 若只用 GET/状态码扫描，会与 404 噪声混在一起被丢掉。

证据：`03_EVIDENCE/tsp/0310_internal_prefix.txt`

---

## 2. 已验证事实

### 2.1 端口面（确定性结论）

- `04_SOLVE/tsp/fullport.py` 全量 65535 TCP connect 扫描：
  **只有 8080 open；其余 65534 个端口全部 timeout（不是 refused）**
  ⇒ 未开放端口是**丢包**而非回 RST。所以「其它端口」无法用 connect 区分「有服务但被 ACL 拦」与「没有服务」。
  证据：`03_EVIDENCE/tsp/0300_fullportscan.txt`、`0300_fullport_open.json`
- UDP（53/67/68/69/123/137/161/162/500/514/520/1900/4500/5353/5683/4789/8883/1883）对 .2/.3/.4 全部无应答。
  证据：`03_EVIDENCE/tsp/0303_udp_probe.txt`
- 8080 上做 TLS 握手 → `wrong version number`，确认是**纯明文 HTTP**，不存在"HTTPS 藏在 8080"。
- 非 h2c：`PRI * HTTP/2.0` 预置帧 → `400`；RFC7540 Upgrade → 仍走 HTTP/1.1 handler（405）。
  证据：`03_EVIDENCE/tsp/0114_raw_socket_teardown.txt`

### 2.2 路由面（4193 条路径，确定性结论）

`04_SOLVE/tsp/route_sweep_final.py`：21 个前缀 × 200 个 API 名词 = **4193 条**，用上面的 oracle 判定，
**命中仅 3 条**（`/healthz`、`/graphql`、`/internal/audit`），传输错误 2 条。
证据：`03_EVIDENCE/tsp/0330_route_sweep_final.txt` / `.json`

历史轮次还覆盖过：1576 条通用字典、1169 条车联网域名词、241 条定向词、706 条 internal/api/public 词。
**累计 8000+ 条路径，无第 4 条路由。**

Go 1.22 `ServeMux` 的方法语义也确认了这一点：
`/graphql` 非 POST → **405**（说明用 `POST /graphql` 方法模式注册）；未注册路径 → **404**。
两者严格区分，不存在"注册了但扫不到"的可能。

### 2.3 `/graphql` 是桩（实现级证据）

| 探针 | 结果 |
|---|---|
| `{}` / `{"query":""}` / `{"query":null}` / `{"query":"!!!! not graphql !!!"}` | 全部 200，**字节级相同**的 demo 车 |
| `{"query":"{ __schema { types { name } } }"}`（introspection） | 200，仍 demo 车 |
| `{"query":"{ vehicles(vin:\"CV6FF52FEE9EDDD86\") { vin label } }"}` | 200，仍 demo 车（**没被用来做过滤**） |
| `{"query":"mutation { signOta(...) { ok } }"}` | 200，仍 demo 车 |
| `operationName` / `variables` 任意 | 不改变响应 |
| `{"query":123}` / `{"query":{}}` / `{"query":[]}` | **400 invalid GraphQL request** |
| `{"query":null}` | 200（Go `json.Unmarshal` 把 null 写进 string 字段是 no-op） |
| `{"variables":{"vin":"..."}}` 单独 | 200 |
| 非法 JSON / 空 body / BOM | 400 |
| 请求体大小 | **≤131071 接受，≥131072 拒绝**（=128 KiB 上限，`http.MaxBytesReader` 一类） |

⇒ handler 结构就是：
`限长读 body → json.Unmarshal 到 struct{Query string; Variables map[string]any} → 成功就 w.Write(固定 demo JSON)`。
**query 从不被执行**（语法错误的 query 都 200）。这是诱饵，不是引擎。
证据：`0110_graphql_semantic_fuzz.txt`、`0200_e1_differential.json`、`0201_e2_field_oracle.json`、`0115_graphql_sizelimit.txt`、`0301_graphql_shape_matrix.txt`

### 2.4 鉴权面：`/graphql` 上**不存在**任何鉴权分支

试过并全部无效（响应字节不变）：`Authorization: Bearer/Basic`、无签名 JWT、`X-API-Key`、`X-API-Token`、
`X-Vehicle-VIN`、`X-VIN`、`X-TBOX-ID`、`X-TSP-Token`、`X-TSP-Role`、`X-Authenticated-User`、
`Cookie`、`Forwarded`/`X-Forwarded-*`/`X-Real-IP`/`CF-Connecting-IP`、`X-Original-URL`/`X-Rewrite-URL`、
`X-Client-Cert`/`X-SSL-Client-CERT`/`X-Forwarded-Client-Cert`、25 种 Host 值、25 种 query 参数。
证据：`0113_trust_header_matrix.txt`、`0202_e3_identity_channels.json`、`0203_e4_host_matrix.json`、`0117_...`

### 2.5 `/internal/audit`（本轮新发现）

- 存在性：`GET /internal/audit` → `404 application/json {"error":"not found"}`；
  而 `/internal`、`/internal/`、`/internal/x`、`/internal/audit/` 全是 **Go 默认 text/plain 404**
  ⇒ 是以**精确路径** `"/internal/audit"` 注册的 handler，不是前缀子树。
- 方法：GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD/TRACE **全部** `{"error":"not found"}`
  ⇒ handler 内部有一道判断，判断不过就伪装成 404（真实 API 常见的「隐藏存在性」写法）。
- 解门尝试（全部失败，响应恒为 baseline）：
  - 40 个参数名 × 11 个值（含真实 VIN、demo VIN、id=0..25、all、*、true）= 440 组
  - 20 种鉴权/内部路由头（Bearer/Basic/X-Internal-Token/X-Service/X-Scope/X-HTTP-Method-Override…）
  - 14 种 body（`{}`、`null`、`[]`、`action=list`、`vin=…`、`filter{}`、`limit/offset`）× POST/PUT
  - form-urlencoded / text-plain / application-json 三种 Content-Type
  - 21 个 SSRF 风格参数（`?url=/path=/file=/host=/callback=…`）
  - 25 种 Host 头（tsp / tsp.internal / internal / localhost / 10.230.164.2 / audit …）
- 证据：`0310_internal_prefix.txt`、`0311_internal_audit_methods.txt`、`0320_internal_api_discovery.txt`、
  `0321_audit_unmask.txt`、`0322_audit_gate_final.txt`、`0323_audit_host_matrix.txt`

**推测（未验证）**：这道门最可能是 **源 IP 判定**（`r.RemoteAddr` 落在内网/回环才放行），
因为我们是从 `10.252.3.20`（VPN 客户端网段）发起的，而 `X-Forwarded-For` 一律不生效 ⇒ 它读的是 `RemoteAddr` 而非头。
其他可能：需要一份我们手上没有的凭证（JWT/内部 token）、或它本来就是作者留的诱饵。

### 2.6 ⚠ 三台主机是同一套代码（重要结构发现）

`/internal/audit` 在 **三台主机上响应完全一致**（`404 application/json {"error":"not found"}`）：

```
10.230.164.2:8080 /internal/audit  -> 404 application/json {"error":"not found"}
10.230.164.3:8080 /internal/audit  -> 404 application/json {"error":"not found"}
10.230.164.4:8080 /internal/audit  -> 404 application/json {"error":"not found"}
（三台的 /zzz-not-a-route-xyz 都是 text/plain "404 page not found"，/ 同样）
```
证据：`03_EVIDENCE/tsp/0340_oracle_portability_check.txt`

⇒ TSP / T-BOX / CGW **共用同一份 Go 服务骨架**，`/internal/*` 是框架层命名空间，
   各题的真实业务路由（DoIP、8443 mTLS）在骨架之外。这解释了为什么 TSP 这么"空"：
   **它可能本来就只有健康检查 + 一个业务桩 + 框架内部端点。**

`/internal/` 命名空间已闭合：`/internal/{a}/{b}` 两级组合 **4292 条 → 0 命中**。
证据：`03_EVIDENCE/tsp/0331_internal_twolevel.txt` / `.json`
（累计：4193 + 4292 + 706 + 1576 + 1169 + 241 ≈ **12000+ 条路径**，路由恒为那 3 条）

---

## 3. 已排除（别再花时间）

| 假设 | 结论 | 依据 |
|---|---|---|
| `/graphql` 是真 GraphQL，存在 `vehicle(vin:)`/`campaigns` 字段 | **否**。query 完全不执行 | §2.3 |
| 换个 header 就能拿到真实车数据 | **否**。25+ 头组合字节不变 | §2.4 |
| 换 Host / vhost 有另一套路由 | **否**。25 种 Host 全 baseline | §2.4 / 0323 |
| 8080 上还有隐藏路由 | **否**。4193 条 + 累计 8000+ 条 | §2.2 |
| 本机还有别的端口 | **否**。65535 全扫，仅 8080 | §2.1 |
| 同 /24 有别的 OTA 主机 | **否**。10.230.164.0/24 + 10.229.221.0/24 × 40 端口 × 254 主机，只出已知 3 台 | `0302_sibling_sweep.txt` |
| UDP 有服务 | **否** | §2.1 |
| HTTP 请求走私 / h2c / 绝对 URI | **否**。Go 标准库，无前端代理 | `0114` |
| `/auth/token` 有东西 | **否**。首次 3s 延迟是我方 curl 首包开销，复测 5×5 次全 404 | `0112_auth_hang_repro.txt` |

---

## 4. 与"识别当前目标车辆"的对应

- TSP 给的 `CV6000000DEMO0001` + `Guest demo vehicle` = **访客诱饵**。
- 真实车辆 VIN 由中央网关 DoIP 得到：**`CV6FF52FEE9EDDD86`**（`22 F1 90` 正常返回，routing activation SA `0x0E00` 通过）。
- T-BOX `8443` 服务端证书 `CN=tbox` / issuer `CN=CV6 Fleet Diagnostics Root`，与 VIN 前缀 `CV6` **同一套 PKI** ⇒ 车端身份链自洽。
- **⚠ 注意区分两套 PKI**：VPN 的 CA 是 `CN=CyberCar Vehicle Range VPN CA`（见 .ovpn），
  与车队 PKI `CN=CV6 Fleet Diagnostics Root` **不是同一个**。拿 VPN 客户端证书去连 T-BOX 8443 必然 `unknown ca`。

---

## 5. 下一步建议（给别人接手）

1. **`/internal/audit` 的源 IP 门**：若 T-BOX（`10.230.164.3`）或 CGW 存在任何"取 URL 回来"的功能（OTA 下载、诊断上报、日志回调），
   让它去请求 `http://10.230.164.2:8080/internal/audit`。这是唯一能验证"源 IP 门"的方法。
2. **把 JSON-404 oracle 用到其它两台**：`10.230.164.4:8080` / `10.230.164.3:8080` 若也有 `{"error":...}` 系列响应，
   说明存在同风格的隐藏 handler 树，用同一 oracle 扫。
3. **OTA 签名入口大概率不在 TSP**：任务语义（绑定 VIN + campaign + rollback=2 → ECDSA P-256/SHA-256 签名）
   描述的是一个**有状态的业务接口**，而 TSP 这台机器**没有任何状态**（无 DB、无上传、无文件下载、无写接口）。
   建议把重点移到 T-BOX 8443（mTLS 后的裸协议）与 CGW。

---

## 6. 证据索引（本目录）

| 文件 | 内容 |
|---|---|
| `0300_fullportscan.txt` / `0300_fullport_open.json` | 65535 端口全扫，仅 8080 |
| `0302_sibling_sweep.txt` / `0302_sibling_open.json` | 两个 /24 × 40 端口扫描，无新主机 |
| `0303_udp_probe.txt` | UDP 无应答 |
| `0310_internal_prefix.txt` | **`/internal/audit` 的 JSON-404 发现** |
| `0311_internal_audit_methods.txt` | 8 种方法全 404 |
| `0320_internal_api_discovery.txt` / `.json` | 706 条路径 + oracle，仅 2 命中 |
| `0321_audit_unmask.txt` / `.json` | 参数/头/body 三维解门，0 命中 |
| `0322_audit_gate_final.txt` | form/SSRF 参数/id 1..25，0 命中 |
| `0323_audit_host_matrix.txt` | 25 种 Host，0 命中 |
| `0330_route_sweep_final.txt` / `.json` | **4193 条路径最终扫描，仅 3 条路由** |
| `0331_internal_twolevel.txt` / `.json` | `/internal/{a}/{b}` 4292 条，**0 命中** |
| `0340_oracle_portability_check.txt` | **三台主机 `/internal/audit` 响应一致 ⇒ 同一套代码** |
| `0110`–`0117`、`0200`–`0205`、`0301` | `/graphql` 桩的完整证伪链 |

脚本：`04_SOLVE/tsp/fullport.py`、`sibling_sweep.py`、`internal_api.py`、`audit_unmask.py`、`route_sweep_final.py`

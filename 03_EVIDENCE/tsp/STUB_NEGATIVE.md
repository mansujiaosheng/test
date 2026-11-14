# STUB_NEGATIVE — TSP `POST /graphql` 的「纯桩」否证材料

> 目标：`http://10.230.164.2:8080/graphql`（Go net/http）
> 结论一句话：**这个 handler 只把请求体反序列化进一个两字段的 Go struct，然后无条件返回一条固定的 81 字节 JSON。请求内容（query 文本、variables、任何 header）对输出零影响。**
> 证据目录：`03_EVIDENCE/tsp/`，脚本目录：`04_SOLVE/tsp/`
> 采集时间：2026-11-14 09:20–09:45 (+08:00)

---

## 1. 结论（可直接进 writeup 的"否定结论"章节）

| 编号 | 否证对象 | 结论 | 依据 |
|---|---|---|---|
| N1 | "`/graphql` 有 GraphQL schema，只是我们没猜对语法" | **否证** | 5 条语义完全不同的 query，响应 **sha256 全等**、逐字节相同（§2） |
| N2 | "query 文本被解析，只是解析器宽松" | **否证** | 请求体是 Go struct 解码：字段类型错即 400，而 query 内容（含非法语法）不影响响应（§3） |
| N3 | "存在隐藏的顶层参数（vin / token / tenant / operationName …）" | **否证** | 160 个候选键的类型探测，只有 `query`、`variables` 两个键被 struct 接受（§4） |
| N4 | "缺少认证头，加上就走别的分支" | **否证** | 9 类 IP/身份头 × 9 个来源值、Cookie、路径改写头、Host 55 变体，共 ~250 条请求，响应同一 sha（§5） |
| N5 | "字段名没猜对（ota / campaign / diagnostics …）" | **否证（有限）** | 734 个字段名 × 2 种查询形状共 1807 条查询，0 条产生非 demo 响应（§6） |
| N6 | "有别的路由（/graphql/{op}、/api/graphql、pprof、metrics …）" | **否证** | 历史 1169 条路径字典 + 通配符/斜杠/大小写变体全部 404；`.2:8080` 只有 `/healthz` 与 `/graphql` 两条路由（§7） |

**未被否证的（保留为开放项）**：服务端是否有我们没能触发的"第二套数据源"（例如靠 TCP 源地址、mTLS 客户端证书、或外部数据库在特定条件下切换）。见 §9 局限。

---

## 2. 判据一：5 条不同 query → 响应 sha256 全等（最直接的一条）

请求体（UTF-8 原始字节）与响应：

| # | 请求体 | status | 响应字节数 | 响应 sha256(前16) |
|---|---|---|---|---|
| 1 | `{"foo":1}` | 200 | 81 | `a4901502af52dc8e` |
| 2 | `{"query":"query { vehicles { label vin } }"}` | 200 | 81 | `a4901502af52dc8e` |
| 3 | `{"query":"query { vehicles(vin:\"CV6FF52FEE9EDDD86\") { label vin } }"}` | 200 | 81 | `a4901502af52dc8e` |
| 4 | `{"query":"{ vehicles }"}` | 200 | 81 | `a4901502af52dc8e` |
| 5 | `{"query":"mutation { __typename }"}` | 200 | 81 | `a4901502af52dc8e` |

五条的响应体逐字节相同：

```
{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}\n
```

`byte-identical = True`，唯一 sha 集合大小 = **1/5**。

### 为什么这条能推出"服务端不读请求"

1. 若存在 schema，`{ vehicles { label vin } }` 与 `{ vehicles }` 的**选择集**不同，标准 GraphQL 语义下返回的字段必然不同（后者要么报错要么返回完整对象）；若解析器实现"宽松"，它至少要对 query 文本做一次词法/正则扫描，才可能产出 `vehicles` 这个键。
2. `{"foo":1}` 里根本没有 query，若解析器按 query 分派，它拿到的应当是空串，与第 2 条（完整合法 query）走不同分支的概率极高；实测两者输出 81 字节全等。
3. `mutation { __typename }` 是一个**必然报错**的 GraphQL 文档（mutation 里不能只有 `__typename`），任何真实的 GraphQL 执行器都会返回 `errors` 数组。实测返回 200 + demo 数据 —— 说明根本没有执行器。
4. 这三条覆盖了"选择集变化 / 无 query / 必然报错"三种最容易被实现差异放大的输入，全部同输出。**在"解析并执行"的假设下，P(三条同输出) 可以忽略。**

---

## 3. 判据二：请求体解码目标是 Go struct（不是 interface{}），且解码成功后 query 不再被消费

Go `encoding/json` 的行为特征可以当作显微镜用：**未知字段被静默忽略；已知字段类型不符则返回错误**。实测：

| 请求体 | status | 说明 |
|---|---|---|
| `1` / `"x"` / `[]` / `true` | **400** | 解进 `map[string]any`/`interface{}` 时这四者都合法 → 目标是 struct（或要求 object 的自定义 Unmarshaler） |
| `null` | 200 | `json.Unmarshal("null", &struct)` 是 no-op，不报错 —— 与 struct 假设一致 |
| `{}` | 200 | 零值 struct 也能通过 |
| `notjson` / 空体 | 400 | 语法错误 |
| `{"query":123}` / `{"query":true}` / `{"query":1.5}` / `{"query":{}}` / `{"query":[..]}` | **400** | `query` 是**具体非 object 类型**；配合 `{"query":"x"}` → 200，判定为 **string** |
| `{"query":null}` / `{"variables":null}` | 200 | struct 字段的 null 是 no-op |
| `{"variables":"x"}` / `{"variables":[]}` | **400** | `variables` 不是 string、不是数组 |
| `{"variables":{}}` / `{"variables":{"k":1}}` / `{"variables":{"k":{"a":1}}}` | 200 | `variables` 是 **map（object）**，值可为任意 JSON |

由此还原出的请求契约（推断，与全部观测一致）：

```go
type gqlRequest struct {
    Query     string                 `json:"query"`
    Variables map[string]interface{} `json:"variables"`
}
```

**关键推论**：`{"foo":1}` 这种"不含 query、只含未知字段"的请求同样 200 并返回 demo，证明 handler 在解码成功后**没有对 Query 做任何前置校验**（既不判空、也不判语法），而是直接输出常量。

---

## 4. 判据三：字段存在性 oracle —— 160 个候选键，只有 2 个存在

利用 §3 的规律：**给某个键喂一个该键"不该接受"的类型，若服务端 400 则键存在，若 200 则键不存在**。每个候选键喂 4 种值（`"zz"` / `{"k":"v"}` / `["zz"]` / `123456789`），按"哪种值被接受"反推类型。

扫描 160 个候选键（`query, variables, operationName, extensions, data, input, args, params, filter, where, vehicle, vin, vehicleId, tenant, account, user, role, token, apiKey, auth, session, signature, campaign*, ota*, firmware*, package*, artifact*, diagnostic*, release*, version, dtc, ecu, gateway, tbox, fleet, org, region, ..., limit, offset, ...`），结果：

| 键 | 接受的值型 | 判定 |
|---|---|---|
| `query` | 仅字符串 | **存在，string** |
| `variables` | 仅 object | **存在，map** |
| 其余 158 个（含 `operationName`、`vin`、`token`、`tenant`、`auth`） | 四种值全接受 = 全被忽略 | **不存在** |

对照组：`zzznotafield` 四种值全 200（确认"不存在"的判定是有效的）；`query`/`variables` 复测稳定。

> **这条特别重要**：连 `operationName` 都没有。标准 GraphQL over HTTP 的请求体必备 `operationName` 字段，没有它基本可以断定"这不是任何 GraphQL 实现，而是一个手写 HTTP handler"。

（原始数据：`0201_e2_field_oracle.json`）

---

## 5. 判据四：身份通道全无效（header / cookie / host / 代理头）

共 5 组、249 条请求，**全部 status=200、响应 sha 唯一（1 种）**：

| 组 | 内容 | 条数 |
|---|---|---|
| H1 | 9 个 IP 来源头（`X-Forwarded-For`、`X-Real-IP`、`X-Client-IP`、`X-Originating-IP`、`Client-IP`、`X-Remote-Addr`、`X-Proxy-User-IP`、`True-Client-IP`、`CF-Connecting-IP`）× 9 个来源值（`10.230.164.3/4/2`、`127.0.0.1`、`::1`、`10.0.0.1`、`172.16.0.1`、`192.168.1.1`、链式值） | 81 |
| H1b | `Forwarded: for=<VIN>` / `for=10.230.164.3` 等 + 路径改写头 `X-Original-URL` / `X-Rewrite-URL` / `X-Forwarded-Host` / `X-Forwarded-Prefix` / `X-HTTP-Method-Override` | 10 |
| H2 | 83 个 `variables` 键名（`vin/vehicleId/target/input/id/tenant/user/scope/where/...`）都填真实 VIN | 83 |
| H3 | `variables` 值类型（object/number/bool/array/null） | 5 |
| H4 | 把 JSON 塞进 `query` 字符串（`'{"vin":"..."}'`、`'{"op":"vehicle.get",...}'`、纯 VIN、纯 `vehicles`） | 10 |

另有两组（`0200`、`0203`）：
- **Authorization / X-API-Key / Token 等**：`Bearer <VIN>`、`Bearer <随机JWT>`、`Basic <base64>`、裸 VIN、历史 lead 的 `alg:none` JWT（`{"vin":"CV6FF52FEE9EDDD86"}`）—— 全部 demo。
- **Host 头 55 个变体**（`tsp`、`tsp.local`、`api.tsp`、`tbox`、`cgw`、`ota`、`fleet`、`admin`、`<VIN>`、`127.0.0.1`、`10.230.164.2:8080` …）：POST 全部 200 + demo，GET 全部 405。**无 vhost 路由**。

> 注：历史证据 `web/redirect_and_vhost_probe.txt` 里"Host: tsp → /graphql=404"一行经复测不成立（实测 405），判定为该脚本的测量假象，不应作为 vhost 存在的依据。

---

## 6. 判据五：字段名穷举 1807 条，0 差分

若解析器"按字段名分派到不同数据源"，真实字段会返回非 demo 响应。构造 734 个候选字段名：

- 单字段：`vehicle(s)`、`ota(s)`、`campaign(s)`、`firmware(s)`、`package(s)`、`artifact(s)`、`engineering`、`diagnostic(s)`、`session(s)`、`image(s)`、`update(s)`、`release(s)`、`manifest(s)`、`signature(s)`、`key(s)`、`bundle(s)`、`job(s)`、`task(s)`、`ecu(s)`、`gateway(s)`、`dtc(s)`、`telemetry`、`fleet(s)`、`config(s)`、`token(s)`、`secret(s)`、`cert(s)`、`pki`、`sign`、`verify`、`hash`、`digest`、`blob`、`storage`、`bucket` …
- 组合（10×10 两两拼接 + 复数化 + `get` 前缀）：`vehicleOta`、`otaCampaign(s)`、`vehicleOtaCampaign`、`campaignPackages`、`engineeringArtifacts`、`diagnosticSessions`、`diagEntry`、`otaTargets`、`getVehicleOta` …

每个名字测两种形状：`{NAME}` 与 `{NAME(vin:"CV6FF52FEE9EDDD86"){id}}`。

结果：**1807 条查询（1468 + 339 重试）中，产生非 demo 响应的 0 条**；唯一"差分"是本地 socket 耗尽（`WinError 10048`）造成的传输错误，重试后 0 真差分，剩 1 条超时未确认。
（`0206_e6_fieldname_brute.json`、`0206b_e6_retry.json`）

---

## 7. 判据六：路由面穷尽

- 历史字典 1169 条路径（含 `/ota`、`/api/v1/vehicles/<VIN>`、`/api/v1/vehicles/<VIN>/ota`、`/api/ota/campaigns`、`debug/pprof/*`、`.git/*`、`actuator/*` 等）→ 全 404。
- 本次补测：`/metrics`、`/debug/pprof/`、`/debug/vars`、`/version`、`/config`、`/api`、`/graphql/` → 全 404。
- 通配符/前缀：`POST /graphql/`、`/graphql/vehicles`、`/graphql/ota`、`/graphql/<VIN>`、`/graphql/v1`、`/graphql/query`、`/graphql/VEHICLES` → 全 404（**无 Go 1.22 通配符路由**）。
- `/graphql` 对 GET/PUT/DELETE/… 恒 405 且**不带 `Allow` 头** → 405 是 handler 内自查方法，不是 Go 1.22 mux 的自动响应；`/healthz` 对所有方法（含 TRACE）恒 200 → 该路由未做方法限制。两者组合说明：只有两条精确匹配路由。
- `/healthz` 加 `?verbose/?debug/?full/?pretty/?all/?details` 全部返回同一 16 字节 `{"status":"ok"}`；三台（`.2/.3/.4`）的 healthz 逐字节相同（sha `6489d6d7a33c`）→ 同镜像无调试面。

---

## 8. 会不会是"请求体太大"之类的基础设施问题？

不是。同一端口对 100 KB 的 query 正常返回 200 + demo；1 MB / 5 MB 时返回 400 `{"error":"invalid GraphQL request"}`（约 1 MB 的 `MaxBytesReader` 类上限）。**说明服务端完整读入并解码了请求体**，只是解码后不使用内容。这条同时排除了"我们其实没把 query 发出去"的可能性。

---

## 9. 局限（诚实边界）

1. **N5 是有限的否证**：734 个字段名是人造词表，若真实字段是任意生僻名字（不在词表内），本实验无法排除。
2. **未验证"非 HTTP 层身份"**：若服务端按 **TCP 源地址** 或 **客户端证书** 切换数据源，本实验的 header 伪造全部无效（我们无法改变真实源 IP）。可验证性很低：`.2:8080` 是明文 HTTP，无 mTLS 空间；源 IP 校验只能靠从 `.3`（T-BOX）发起请求来排除，而 `.3:8080` 同样只有 `/healthz`。
3. **未做二进制级验证**：无法取到 `.2:8080` 的进程/镜像，因此"handler 无条件返回常量"是**行为层结论**（黑盒可重复、可证伪），不是源码结论。

---

## 10. 复现

```bash
cd 04_SOLVE/tsp
python e7_schema_vs_stub.py      # §2 五条 query 的字节级对比（输出 sha256 + byte-identical）
python e1_differential.py        # §3 54 条形状/类型差分（45×demo / 9×400）
python e2_field_oracle.py        # §4 160 键字段 oracle（47s）
python e3_identity.py            # §5 身份通道 189 条
python e4_host.py                # §5 Host 55 变体
python e6_fieldnames.py && python e6b_retry.py   # §6 1807 条字段名
python doip_client.py            # DoIP 车辆识别对照（VIN/LA/EID，证明另一条腿是真的）
```

环境：Python 3.13，仅用标准库；单次运行的请求速率 < 20 req/s。

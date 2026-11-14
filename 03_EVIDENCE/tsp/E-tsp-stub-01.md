# E-tsp-stub-01：TSP /graphql 为静态桩的判据链

目标：`http://10.230.164.2:8080/graphql`（POST，Content-Type: application/json）

## 1. 常量性
同一请求连发 5 次，md5 全部 `461cc94efa52fa3c52eeef2b910a47de`：
`{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}\n`

## 2. 解码行为（类型 oracle，反推 handler 结构体）
| 请求体 | 结果 | 推论 |
|---|---|---|
| `{"foo":"bar"}` | 200 + 常量 | 未知字段被忽略 |
| `{"query":123}` | 400 invalid | query 是 **string** |
| `{"query":null}` | 200 + 常量 | null → 零值 |
| `{"query":{"a":1}}` | 400 | 非 string |
| `{"variables":123}` | 400 | variables 不是 interface{} |
| `{"variables":"abc"}` | 400 | 不是 string |
| `{"variables":[]}` | 400 | 不是 array |
| `{"variables":{...}}` | 200 | 是 **map[string]interface{}** |
| `{"variables":{"vin":12345}}` | 200 | 内部值无类型约束 |

⇒ handler 结构体等价于 `struct{ Query string; Variables map[string]interface{} }`，解码后**不看内容**直接回常量。

## 3. 选择集不被尊重（决定性）
`{"query":"{ vehicles { ONLY_VIN } }"}` → 仍返回 `label` + `vin` 两个字段。
真实 GraphQL 会对未知字段报错或只回 `vin`。⇒ 无解析、无执行。

## 4. 穷举（全部同一响应，无一例外）
- 3500 条路径（GET+POST）→ 仅 `/graphql`、`/healthz`
- 270 个 variables key（含 snake/camel/大写变体）× 真 VIN `CV6FF52FEE9EDDD86`
- 30 个 operationName
- 23 个 Host / vhost
- 12 个 User-Agent、8 个 X-Client-Id
- 路径混淆（`/./graphql`、`/x/../graphql`、`/%67raphql`）→ 均被 mux 规范化回 `/graphql`
- h2c prior-knowledge → 连接被 RST（只支持 HTTP/1.1）
- `multipart/form-data`、`application/graphql`、`function form` → 400
- persisted query（extensions.persistedQuery）→ 200 + 常量
- `X-HTTP-Method-Override` → 无效

## 5. 结论
该端点**不存在任何输入依赖行为**，无法承载"对象级越权"利用。任务 01 的 TSP 侧在当前部署下不可达，
需要向出题方确认 TSP 是否绑定/未生效，或者目标车辆数据实际存放在别处。

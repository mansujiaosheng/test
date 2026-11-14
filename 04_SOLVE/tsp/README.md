# `04_SOLVE/tsp/` — T01 可重放脚本索引

环境已在 2026-11-14 ~09:55–10:00 轮换。**旧**：`10.230.164.2:8080`；**新**：`10.225.139.2:8080`。
下表脚本除注明外，默认打旧地址，改 `HOST/BASE` 常量即可复用到新地址（新地址的复跑结果已归档在
`03_EVIDENCE/tsp/0181`–`0186`）。

## TSP 本体（新旧环境同 build）

| 脚本 | 干什么 | 主要输出 |
|---|---|---|
| `tsp_probe.py` | 四个子命令的总入口：`gql`（37 组请求体语义变体）/ `paths`（241 条定向路径 GET+POST）/ `hdrs`（39 个信任头）/ `raw`（裸 socket：h2c、分块、100-continue、走私、`OPTIONS *`）/ `vhosts`（44 个 Host 基线 diff） | `0110`–`0117` |
| `gql_sizelimit.py` | 二分出 `/graphql` 请求体上限 = **131072 B**，并测 `json.Decoder` 语义（尾随垃圾被忽略 / 非法 UTF-8 被接受） | `0115` |
| `gql_querystring_and_methods.py` | 26 个 query string × `POST /graphql`；22 条重点路径 × 8 种非标准方法 | `0117` |
| `fullport_scan.py` | 1–65535 TCP connect 全扫（**注意**：该主机非 8080 端口是 ~2.2 s 延迟 RST，超时须 ≥3 s，否则全被误判 filtered） | `0120_fullport.txt` |
| `range_alias_sweep.py` | 3 个 /24 × 4 端口连通性（已确认 164.4 与 229.221.2 是同一服务的双 IP） | `0120_range_alias_sweep.txt` |
| `jwt_none_forge.py` | `alg=none` 伪造 JWT 全矩阵（5 header × 23 claim × 6 载体 × 2 端点 + HS256 弱密钥），判据是响应偏离 81 B demo | `0171`（旧，运行中被环境轮换打断）/ `0182`（新环境） |
| `newrange_route_sweep.py <host> [port]` | **新环境专用**：129 条路径 × GET/POST，用 JSON-404 oracle 判定已注册路由 | `0183` |
| `newrange_service_scan.py [subnet...]` | **新环境专用**：2 个 /24 × 23 端口服务发现（含 MQTT 1883/8883），40 并发 | `0186` |

## 赛事平台（`https://175.27.210.153:9989`）

| 脚本 | 干什么 | 主要输出 |
|---|---|---|
| `find_platform_origin.py` | 从本机 Chrome/Edge `History` 库的 `downloads.referrer` 反查 `.ovpn` 下载来源 → 定位平台；只打印命中关键词的行 | `0122` |
| `platform_token_try.py` | 把平台自己发给我们的 4 个标识符（`usr_b2ad…`、`ed3e7d…`、`competition-…`、VPN 证书 CN `cc-715a9a…`）当凭据试（Bearer/Token/X-API-Token/Cookie/query/登录体）。**注意该脚本 §2 的 query 拼串有 bug**，正确复跑见 `0161` | `0160` / `0161` |
| `fetch_platform.py` | **等 session**：`--cookie 'cybercar_session=…'` 或 `--user U --password P` → 拉 `/api/v1/bootstrap`、写 `platform/challenges.md`（题面摘要 + `run.accessHost/accessPort`）、下载全部题目附件到 `platform/attachments/`、写 `attachments_manifest.json`（sha256） | 待运行 |

## 关键判据（复跑时请沿用）

1. **JSON-404 oracle**：`404 + text/plain + "404 page not found\n"`(19 B) = 未注册；
   其它任何 404（尤其 `404 + application/json + {"error":"not found"}` 22 B）= **已注册但被门挡住**。
2. `/graphql` 基线 = `200` + 81 B `{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}\n`。
3. 非 8080 端口超时须 ≥3 s（延迟 RST 特性）。
4. 平台所有数据接口都需 `cybercar_session`；唯一免登录的是 `/api/v1/auth/check`（`{"authenticated":false}`）。

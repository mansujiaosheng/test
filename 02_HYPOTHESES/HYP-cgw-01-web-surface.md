# HYP-cgw-01 — 10.229.221.2:8080 是否存在可用的 CAN FD 桥 API 面

- **日期**：2026-11-14 09:2x–09:5x
- **负责人**：ecu-bridge
- **所属**：C03 中央网关 / DoIP / CAN FD 桥
- **状态**：**已证伪**（无 API 面）

## 判据（先写后跑）

若 8080 是「往 CAN FD 总线发一帧」的控制面，则应至少满足一条：

1. 存在某个路径对 `GET/POST` 返回 200/400/405/415/422（**不是** 404），
   因为 Go 1.22 `ServeMux` 对「路径已注册但方法不匹配」返回 **405**、
   对「body/参数不合法」返回 400 系列 —— 这两种都不会是 404。
2. 或存在 `CONNECT` / absolute-form 的正向代理行为（能借它到 10.224.139.0/24）。
3. 或存在 WebSocket / h2c / gRPC 升级通道。

反证判据：全部路径在全部方法下都只回 `404 page not found`（19B text/plain），
且 `CONNECT` 也 404、h2c 被 400 拒绝、gRPC 404 ⇒ 判定无控制面。

## 实验结果

| # | 实验 | 覆盖量 | 结果 |
|---|---|---|---|
| 1 | GET 路径枚举（pathbrute + wordlist_wave2） | 407 | 仅 `healthz` 200，其余 406 全 404 |
| 2 | 多方法枚举 GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD | 1252 词 × 7 方法 + bridge 类路径 × 3 种 body = **8977 请求** | 8949×404、14×200（全 `healthz`）、14 连接错误；**唯一非 404 的应用响应是 `/internal/audit` → 404 `{"error":"not found"}`** |
| 3 | `/internal/audit` 参数矩阵（31 个参数名 × 6 值 = 186 次）+ 6 个伪造源 IP/认证头 + 6 种 POST body + 5 种路径变体 | 210 请求 | 响应恒为 `404 {"error":"not found"}`（22B），**无任何变化** |
| 4 | 路径归一化（`//internal//audit`、`/internal/./audit`、`/%69nternal/audit`、大小写、`;.json`、尾部空格） | 7 | 307 重定向到 `/internal/audit`，其余 404 text；无绕过 |
| 5 | Host 头虚拟路由（`localhost`/`cgw`/`cgw.local`/`gw`/`doip`/`can`/`vehicle`/裸 IP） | 9 | 全部 200，说明 `healthz` 无条件应答，**无 host 路由** |
| 6 | 正向代理判定 `CONNECT 10.224.139.5:8080` | 1 + 对照 | **404**（不是代理）。⚠️ `curl -x` 会给出假 200，见下「坑」 |
| 7 | h2c prior-knowledge（`PRI * HTTP/2.0` + SETTINGS） | 1 | `400 Bad Request`（HTTP/1.1 服务器拒绝），**无 h2c** |
| 8 | gRPC `grpc.health.v1.Health/Check` | 1 | `404 page not found`，无 gRPC |
| 9 | 跨主机一致性（221.2 / 164.2 / 164.3 / 164.4） | 4 | `/internal/audit` 四台**全部** `404 {"error":"not found"}` ⇒ 同一镜像的标准组件 |

## 结论

1. `10.229.221.2:8080` 的完整 API 面 = **`/healthz`**（任意方法 200 `{"status":"ok"}`）
   \+ **`/internal/audit`**（任意方法 404 `{"error":"not found"}`，与 Go 默认 404 的
   19B text/plain 明显不同 ⇒ 它是**已注册的应用路由**，不是 mux 未命中）。
2. `/internal/audit` 在参数、方法、认证头、源 IP 伪造、路径归一化全部维度下响应恒等，
   判定为**静态桩 / 诱饵路由**，无可利用参数。
3. 8080 **不是** CAN FD 桥，**不是**正向代理，**不支持** h2c/gRPC/WebSocket 升级。

## 坑（重要，会影响别人判读）

- **`curl -x http://10.229.221.2:8080 http://10.224.139.5:8080/healthz` 返回 200 `{"status":"ok"}`，
  这是假阳性**：curl 对 http:// 目标发的是 absolute-form 请求
  `GET http://10.224.139.5:8080/healthz`，Go 的 `http.Server` 会把 URI 解析成
  `r.URL.Path = /healthz`，于是命中 **221.2 自己**的 healthz，而不是代理到了 BCM。
  我用同一手法打 `http://10.230.164.4:8080/healthz` 同样得到 200 做对照，
  且裸 `CONNECT` 返回 404，三者合起来证明「不是代理」。
  任何人看到 `curl -x` 的 200 都必须先做这个对照，否则会误判「打通了车内网」。

## 证据

- `03_EVIDENCE/cgwweb/0301_pathbrute_221_8080.json` — 407 条 GET 枚举
- `03_EVIDENCE/cgwweb/4100_methodfuzz_221_8080.json` — 8977 条多方法枚举 + 状态直方图
- `03_EVIDENCE/cgwweb/4110_internal_audit_probe.json` — `/internal/audit` 210 条参数矩阵
- `04_SOLVE/cgwweb/methodfuzz.py`、`04_SOLVE/cgwweb/audit_probe.py` — 可重放

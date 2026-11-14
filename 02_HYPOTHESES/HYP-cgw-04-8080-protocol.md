# HYP-cgw-04：8080 管理口是否存在隐藏接口/转发面

状态：**已证伪（无新增面）**｜负责人：cgw｜时间：2026-11-14 09:42 CST

| ID | 假设 | 判据 | 实测 | 结论 |
|---|---|---|---|---|
| H1 | 存在隐藏管理路径（web 组 1576 条之外） | 任一路径非 404 且响应随输入变化 | 本轮 14 条协议级怪点全部 404/200(仅 /healthz)，无变化 | REFUTED |
| H2 | 需要特殊 Host / vhost 路由 | 换 Host 后路由变化 | web 组 12 种 Host 全一致 | REFUTED |
| H3 | 支持 h2c/gRPC/WebSocket 等第二条协议 | 协议升级成功 | h2 preface→400；Upgrade→200 普通 JSON | REFUTED |
| H4 | 反向代理/CONNECT 转发（可绕过到 13401） | CONNECT 成功隧道 | `CONNECT`→404 | REFUTED |
| H5 | 请求走私（CL+TE）可利用 | 后端解析差异 | 无后端；Go 忽略 CL 用 TE，均 200 | REFUTED |
| H6 | 管理 API 需认证后才从 404 变 200 | 任意方法/头/体触发 | `/healthz` 全方法 200，其余恒 404 | REFUTED |
| H7 | 8080 上有"CANGW 转发 API"可绕到内部 CAN 侧 | 存在转发语义的端点 | 无（handler 忽略 query/body/method） | REFUTED |
| H8 | `/internal/audit` 需要特殊 Host / 绝对 URI | 换 Host(内部名)/absolute URI 后响应变化 | 全部 404 JSON 不变；带尾斜杠回落 text 404（精确路径） | REFUTED |
| H9 | `/internal/audit` 需要 DoIP 语义的内部头（X-DoIP-Tester/Entity、X-CGW-Token、Bearer CGW1…） | 头命中后 404→401/200 | 9 组头全部 404 JSON 不变 | REFUTED |
| H10 | 条件请求/分块（Range、Accept-Encoding、If-Modified-Since）能触发文件服务行为 | 出现 206/304/压缩 | 全部 200/404 原样，头被忽略 | REFUTED |

证据：`0530_internal_audit_host.txt`、`0534_8080_range_headers.txt`、`0536_audit_doip_headers.txt`。

原始：`03_EVIDENCE/cgw/0513_8080_protocol_oddities.jsonl`；画像：`01_TARGETS/cgw/8080_mgmt.md`。

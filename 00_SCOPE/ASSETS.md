# 资产四表

## 表 A：目标资产（2026-11-14 09:1x 实测）

| ID | 名称 | 地址 | 开放端口 | 已确认行为 |
|---|---|---|---|---|
| S1 | TSP 云服务 / OTA 签名 | 10.230.164.2 | 8080 | `GET /healthz` 200；`POST /graphql` 200 固定返回 `{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}`；4149 条路径 × GET/POST 全 404 |
| S2 | T-BOX（HTTP） | 10.230.164.3 | 8080 | 仅 `/healthz` 200；其余 404 |
| S3 | T-BOX（mTLS 诊断） | 10.230.164.3 | 8443 | TLS1.3，ServerHello 证书 `CN=tbox` / 签发者 `CN=CV6 Fleet Diagnostics Root`（ECDSA P-256，SAN DNS:tbox，EKU serverAuth，2026-11-14~12-14）；`Acceptable client CA = CV6 Fleet Diagnostics Root`；无客户端证书 → alert 116 `certificate required`；带 VPN 证书 → alert 48 `unknown ca` |
| S4 | 中央网关 | 10.229.221.2 | 8080, 13400, 13401 | `/healthz` 只有；DoIP 13400 正常（见下）；13401 TCP 可连但 DoIP 0x0001 无响应 |
| S5 | 网关第二入口 | 10.230.164.4 | 8080, 13400, 13401 | 与 S4 同一 DoIP 实体：同 VIN / 同 EID / 同 LA |
| S6 | BCM / BMS / VCU | 10.224.139.5 / .6 / .7 | 8080(预期) | **不可达**：ICMP 无响应、TCP connect 超时 |

## 表 B：入口与可控性

| ID | 入口 | 形态 | 可直接控制 | 证据 |
|---|---|---|---|---|
| E1 | `POST http://10.230.164.2:8080/graphql` | JSON GraphQL | 是（但被忽略） | `03_EVIDENCE/web/gql_baseline_variants.txt`、`recon/` |
| E2 | `https://10.230.164.3:8443` | TLS1.3 mTLS | 需客户端证书 | `03_EVIDENCE/tbox/8443_vpncert_handshake.txt` |
| E3 | `tcp://10.229.221.2:13400` | DoIP/UDS | 是 | `03_EVIDENCE/cgw/trace.jsonl` |
| E4 | `tcp://10.229.221.2:13401` | 未知 | 待定 | — |

## 表 C：判据

| 项 | 内容 |
|---|---|
| flag 正则 | 待确认（无题面） |
| 预期产物 | Task03：有时效的**诊断票据**（token/JSON），可用它访问下一步 |
| 判据命令 | 票据须由服务器返回且可复用于某受保护接口；不能只有本地字符串 |
| 提交方式 | 待确认 |

## 表 D：实验设施（已自检）

| 设施 | 自检 |
|---|---|
| VPN 连通 | `ping 10.230.164.2` 25ms ✅ |
| nmap 7.98 | `nmap -sT -Pn -p-` 可用 ✅ |
| openssl 3.0.15 | `s_client -tls1_3` 可用 ✅ |
| python 3.13 | 可用 ✅（无 pycryptodome 已确认？未验证） |
| DoIP 客户端 | `05_TOOLS/doip.py` ident 返回 VIN ✅ |

## DoIP 已知事实（S4/S5）

- Vehicle Identification (0x0001) → 0x0004：`VIN=CV6FF52FEE9EDDD86`，`LA=0x1000`，`EID=060000001000`，`GID=000000000000`
- Entity Status(0x4001)/PowerMode(0x4003) → `01`
- Routing Activation(0x0005, SA=0x0E00) → 0x0006 code `0x10` routing successfully activated
- UDS on LA 0x1000：`22 F190` → VIN；`22 F1A0` → `07E0 07E8 07E1 07E9`（两条 CAN 诊断 ID 对，ECU1 7E0/7E8，ECU2 7E1/7E9）；`3E 00` → NRC 0x31

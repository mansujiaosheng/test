# 03_EVIDENCE/ecu-reach · 索引

task-5（ECU 可达性）原始证据。全部为 2026-11-14 靶场重启后（09:51 之后）的新地址测量；旧地址 10.224.139.x 的结论作废。
结论与判据见 `04_SOLVE/ecu-reach/FINDINGS.md`，目标画像见 `01_TARGETS/ecu-reach/REACHABILITY.md`。

## 数字速查

| 项 | 数字 | 文件 |
|---|---|---|
| 三台 ECU 全端口 TCP | 196,605 probes，OPEN=0，RST=0，全 TIMEOUT，157 s | `22_fullport_ecus.json` |
| `10.226.0.0/16` × 8080/13400 | 131,068 probes，只有 `10.226.193.2` | `21_sweep_10_226_0_16.json` |
| DoIP 全 16 位逻辑地址（3E00） | 65,536/65,536 有应答；唯一异源 `0xE442 → src 0x1220` | `18_ta_full_0000_FFFF.json` |
| 13401 静默关闭 | connect 26.4 ms，0 字节发送时 +25.6 ms FIN，10/10 | `31_13401_close_timing.json` |
| SSRF 反连 | 0 callbacks | `ssrf/callbacks.log` |

## 文件

### IP 层
- `01_tcp_controls.txt` — 旧地址存活期对照：关闭端口全 DROP（无 RST），说明 timeout 不能单独作死证据
- `02_tcp_matrix_ecus.txt` — 旧地址三台 ECU 8 端口矩阵
- `10_newaddr_icmp.txt` / `11_newaddr_tcp_matrix.txt` — 新地址 ICMP / TCP 矩阵
- `17_tracert_new.txt` — 新地址 tracert（ECU 静默 vs 活主机第 2 跳到达）
- `40_gateway_interfaces.txt` — 路由器接口 / LSRR 测试
- `41_record_route.txt` — `ping -r 9`：`10.225.139.1`、`10.226.193.1` 为直连接口
- `42_router_unreachable_control.txt` — **决定性对照**：直连 /24 未用地址回 host-unreachable，ECU 段静默
- `43_ttl2_path.txt` — TTL=2 复测，同上
- `44_ecu_8080_repeat.txt` — 10:12 稳定性复测（9/9 TIMEOUT）

### 扫描
- `20_sweep24_*.json` — `10.225.139.0/24`、`10.226.193.0/24`、`10.226.197.0/24` × 14 端口
- `21_sweep_10_226_0_16.json` — `10.226.0.0/16` × 8080/13400
- `22_fullport_ecus.json` / `.log` — 三台 ECU 全端口
- `23_fullport_cgw_addrs.json` / `.log` — CGW 两地址全端口（只有 8080/13400/13401）

### DoIP
- `12_new_cgw_ident.txt` / `13_new_cgw_uds.txt` — 身份、RA、22F190、22F1A0
- `14_doip_forward_matrix.json` — 33 条定向转发矩阵（全部 NRC31，除 TA=0x1000）
- `15_doip_ta_sweep.*` — 1,280 个地址预扫
- `18_ta_full_0000_FFFF.json` / `.log` — 全 65,536 逻辑地址（流水线，0 补测）
- `34_la_1220_probe.txt` — 0x1220 物理寻址被网关拒绝
- `35_ta_sweep_E000_EFFF.json` — 功能地址段重扫
- `36_entity_1220_readonly.txt` / `37_entity_1220_extended.txt` — 0x1220 只读能力
- `38_target_probe_22.txt` — 22F190 定向验证功能地址
- `39_ta_sweep_REPEAT_3E00.json` / `.log` — 全空间扫描独立复跑

### 13401
- `16_cgw_13401_handshake.json` — 第一批 18 种 payload
- `19_cgw_alias_13401_handshake.json` — CGW 云侧地址同测
- `31_13401_close_timing.json` / `.txt` — 关闭时序 + 14 种 payload
- `32_13401_protocol_battery2.txt` — HTTP/CONNECT/WS/h2/SOCKS5/MQTT 等
- `33_udp_and_tls_13401.txt` — UDP 静默；13401 非 TLS

### SSRF / 代理
- `30_ssrf_battery.txt` — TSP/T-BOX/CGW 的 URL 参数、绝对 URI、CONNECT 测试
- `ssrf/callbacks.log` — 本机 `10.252.3.20:9999` 监听日志（零回连）

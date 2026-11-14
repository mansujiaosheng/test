# 03_EVIDENCE/cgw —— cgw（13401 + 8080）证据索引

> **编号约定（重要）**：本目录由两组共用。`0001_*`–`0499_*` 是 doip 组早期批次；
> 两组现在都从 0500 起编号，**同一序号下可能并存多个文件**（后缀不同），例如
> `0501_probe13401_timing.jsonl`（本组）与 `0501_ra_manual_sa0e80.json`（doip 组）。
> 本组文件一律带 `13401`/`8080`/`newenv`/`bridge_watch`/`gate` 等词缀；doip 组多为
> `ra_*`/`manual`/`recheck_*`/`verify_*`。引用时请**连文件名一起写**，不要只写序号。

## 0500+（cgw：13401 / 8080）

| 文件 | 内容 | 结论指向 |
|---|---|---|
| `0500_probe13401_round1.jsonl` | 第一轮行为探测：server-first / 半关闭 / 1–64B 零字节 / CRLF / HTTP / DoIP ident | 无 banner；FIN/RST 混合是"数据与 close 赛跑" |
| `0501_probe13401_timing.jsonl` | 关闭时延测量 + 首轮 UDP（含关闭端口对照） | FIN ~3.6–26 ms；UDP 无回包但对照端口也无 ICMP |
| `0502_host_connectivity.jsonl` | 8080/13400/13401 各 3 次连通性 | 主机本身稳定，偶发 SYN 重传是 VPN 抖动 |
| `0503_13401_state_and_timing.jsonl` | DoIP 激活后/源端口 13400/8 次时延 | 状态不影响 13401 |
| `0504_udp_probe.jsonl` | UDP 13400 ident、13401 空包/CANGW/8×00、关闭端口 34777 对照 | 本环境 UDP 不可判定 |
| `0505_nmap_13401_13400.txt` / `0505b_nmap.txt` | nmap -sV 尝试 | **nmap 在本机启动即 0xC0000005 崩溃**（不可用） |
| `0506_scapy_synack.txt` | 8080/13400/13401 的 SYN-ACK 指纹 | 三端口同栈：TTL 63 / win 64240 / MSS 1386 |
| `0507_ifaces.txt` | scapy 接口/路由表 | VPN TAP = `\Device\NPF_{42C6004D-…}`，本机 10.252.3.20 |
| `0508_13401_session.pcap`、`0508_13401_capture.txt` | 首次抓包尝试（**失败：sniff 在建连之后才启动**） | 教训：抓包要先起 sniffer |
| `0509_13401_crosshost_tfo_state_timeline.jsonl` | .4 实例、TFO（Windows 不支持）、13400 0x10 03 后、60 s/20 次时间线 | 全部 FIN；无时间窗/无状态依赖 |
| `0510_13401_protocol_shotgun.jsonl` | 20 条已知车联网/工业协议首帧 | 全部无回包 |
| `0511_13401_packetlevel.txt` | **决定性包级实验**：connect-only / send16 / 第三 ACK 带数据 / 无数据对照 | 有数据→ACK 后 RST；无数据→FIN；**read 从未发生** |
| `0512a_blastscan_2.txt` | 65535 端口 scapy blast 尝试（500 pkt/s，131 s/轮，超时中止） | 方法太慢且高频，已弃用 |
| `0512b_fastscan_2_4.txt` | selector 全端口 connect 扫描（VPN 已断，65535 全 unknown） | 无效（作 VPN 断线时间戳证据） |
| `0513_8080_protocol_oddities.jsonl` | 8080 的 14 条协议级怪点 | 无新路由/协议面（详见 HYP-cgw-04） |
| `0514_closedport_probe.txt` | 13402/34999/65530 的 SYN 响应 | 关闭端口正常回 RST+ACK（不是 filtered） |
| `0515_vpn_health.txt` | 09:59 对**旧 IP** 全不可达 | 实为靶场重启迁移（见 0519），非 VPN 断 |
| `0516_ovpn_log_tail.txt` | OpenVPN Connect 日志尾 | 09:56:30 有一次重连（SSL 握手完成）；与旧 IP 退役叠加 |
| `0517_vpn_recheck.txt` | 10:0x 对旧 IP 再次健康检查 | 旧 IP 仍未恢复（新 IP 见 0519） |

| `0519_newenv_10.226.193.2.txt` | **新环境** 10.226.193.2：8080/13400/13401 全可连；13401 connect-only → 26 ms FIN | 环境迁移，13401 行为不变 |
| `0520_newenv_13401_packetlevel.txt` | 新实例上重跑 A/B/C/D 包级实验 | **逐字节复现**：C 中 `A(ack=seq+16)` 后 `RA`，仍未 read |
| `0521_newenv_8080.txt` | 新实例 8080：`/healthz` 200、`/internal/audit` 404 JSON、`OPTIONS *` 200 | 与旧实例同镜像 |
| `0522_bridge_watch.jsonl` / `0522_bridge_watch_console.txt` | 开桥监测器 10 s × 20 min：**119 采样全部 `CLOSED`**（`watch_end samples=119`） | 20 分钟窗口内门未开；开桥应出现 `DATA`/`STILL_OPEN` |
| `0535_bridge_watch_long.jsonl` / `_console.txt` | 60 min 长监测（10:09 起，1 连接/10 s） | 持续进行中；命中即打印 `STATE_CHANGE` |

| `0523_newenv_udp.txt` | 新实例 UDP：关闭端口无 ICMP、13400 DoIP ident 无响应、13401 无响应；**外网 DNS over UDP 正常** | ICMP 被过滤，UDP 侧仍不可判定 |
| `0525_newenv_closedport.txt` | 新实例关闭端口 34999/13402/22/443 → 连接挂起（SYN 被丢，无 RST） | 全端口扫描需超时，成本高 |
| `0526_newenv_targeted_scan.txt` | 新实例定向端口表（13300–13500 + 常见服务口） | 仅 8080/13400/13401 |
| `0527_newenv_net_sweep.txt` | 10.226.193.0/24 × (8080,13400,13401) 全网段 | 仅 .2 一台 |
| `0528_newenv_gate_state.txt` | 4 种 activation type + OEM "CGW1" → 13401；未激活直接发 0xE442（NRC 0x22） | 激活类型不影响 gate |
| `0529_newenv_gate_state2.txt` | 正确顺序：激活 → 0xE442 上 10 03 / 31 01 / 27 01 / 22F1A3 → 13401 | 0x1220 会话/例程均不改变 gate（仍 FIN） |
| `0533_subnet_sweep_cgwports.txt` | 6 个 /24（10.226.192–194、10.229.221、10.230.164、10.224.139）× (8080,13400,13401) 共 4572 探测 | 仅 10.226.193.2 一台 CGW |

## 复现命令

```bash
# 行为/时序（12 连接，250 ms 间隔）
python 04_SOLVE/cgw/probe_13401.py
# 包级判定（抓包先起，含第三 ACK 带数据实验）
python 04_SOLVE/cgw/cap2_13401.py
# 协议 shotgun（20 连接，300 ms 间隔）
python 04_SOLVE/cgw/shotgun_13401.py
# 8080 协议怪点（14 连接，250 ms 间隔）
python 04_SOLVE/cgw/http8080_odd.py
# VPN 恢复后的低频复核
python 04_SOLVE/cgw/retest_after_vpn.py
```

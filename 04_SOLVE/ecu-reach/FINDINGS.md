# ECU 子网可达性（task-5）· 结论与证据链

**时间**：2026-11-14 09:44–10:15 CST（靶场 09:51 重启，旧地址 10.224.139.x 全部作废，以下均为重启后新地址）
**范围**：只读探测。未刷写 ECU、未做 DoS、未改路由。
**一句话结论**：`10.226.197.5/6/7:8080` 从本 VPN 侧**不可达**。原因不是 ECU 进程没起，而是 **VPN 路由器 `10.252.3.1` 没有到 `10.226.197.0/24` 的路由**（该 /24 既不是它的直连网段，也没有可用下一跳），包在路由器处被静默丢弃。车辆侧唯一可达面是 CGW：DoIP `13400` 只把功能地址 `0xE442` 转发到节点 `0x1220`，`13401` 在开桥前是 accept-then-close 的空监听。没有任何 IP 转发、代理或 SSRF 面能绕过去。

---

## 1. 地址与拓扑（重启后）

| 角色 | 地址 | 实测端口 | 结论 |
|---|---|---|---|
| VPN 客户端 | `10.252.3.20`（TAP） | — | 路由 `10.224.0.0/12 → 10.252.3.1` |
| VPN 路由器 | `10.252.3.1` | 不回 ping，回 TTL-exceeded | 有 `10.225.139.1`、`10.226.193.1` 两个直连接口 |
| TSP | `10.225.139.2:8080` | 8080 OPEN | `/graphql` POST 是静态桩（任意 query 都回 demo 车） |
| T-BOX | `10.225.139.3:8080/8443` | 8080、8443 OPEN | 8443 为 mTLS |
| CGW（云侧） | `10.225.139.4:8080/13400/13401` | 三个都 OPEN | **与 10.226.193.2 同一 DoIP 实体**（VIN/EID/LA 逐字节相同） |
| CGW（车侧） | `10.226.193.2:8080/13400/13401` | 三个都 OPEN | VIN `CV622697F82A936A1`，entity LA `0x1000` |
| **目标 ECU** | `10.226.197.5/6/7:8080` | **全部 TIMEOUT，无 RST** | 路由器无路由 → 不可达 |

CGW 双归属是本轮新发现（此前只记录了 `10.226.193.2`）：`10.225.139.4` 与 `10.226.193.2` 的车辆识别响应完全相同
（VIN `CV622697F82A936A1`、LA `0x1000`、EID `060000001000`、`22F1A0` → `07E0 07E8 07E1 07E9`），
即同一实例的两个网口，分别落在云段 `10.225.139.0/24` 与车段 `10.226.193.0/24`。

```
10.252.3.20 ──TAP── 10.252.3.1
                     ├── 10.225.139.1/24 ── 10.225.139.2 (TSP) / .3 (T-BOX) / .4 (CGW 云侧)
                     ├── 10.226.193.1/24 ── 10.226.193.2 (CGW 车侧)
                     └── ✗ 10.226.197.0/24  ← 无路由（目标 ECU .5/.6/.7 在这段）
```

---

## 2. 证据链 A：IP 层不可达（决定性）

### 2.1 路由存在，但只到两个 /24

- 本机 `route print -4`：唯一相关路由 `10.224.0.0/12 → 10.252.3.1`（metric 257，TAP 接口 `10.252.3.20`）。
- OpenVPN profile 本身也只 push 这一条：`route 10.224.0.0 255.240.0.0`（`cybercar-competition-*.ovpn`）。
- 因此"路由不存在"不是客户端问题——**粗路由覆盖了 10.226.197.0/24，但远端不认**。

### 2.2 tracert 正对照：活的 /24 在第 2 跳到达，ECU 段第 1 跳后静默

`03_EVIDENCE/ecu-reach/17_tracert_new.txt`：

| 目标 | 结果 |
|---|---|
| `10.225.139.4`（CGW 云侧） | hop1 `10.252.3.1` 25 ms → **hop2 目标本身** |
| `10.226.193.2`（CGW 车侧） | hop1 `10.252.3.1` 25 ms → **hop2 目标本身** |
| `10.226.197.5 / .6 / .7` | hop1 `10.252.3.1` → hop2–6 **全静默** |

### 2.3 决定性对照：路由器对"直连但未使用"的地址会回 ICMP host-unreachable

这是本轮最关键的一步：先证明 `10.252.3.1` 在找不到主机时**会**发 ICMP，再看 ECU 段有没有。

`03_EVIDENCE/ecu-reach/42_router_unreachable_control.txt`、`43_ttl2_path.txt`：

| 目标 | 观测 | 含义 |
|---|---|---|
| `10.225.139.250`（云段未用地址） | `Reply from 10.225.139.1: Destination host unreachable` | /24 直连，路由器 ARP 失败后回 ICMP |
| `10.226.193.250`（车段未用地址） | `Reply from 10.226.193.1: Destination host unreachable` | 同上 |
| `10.226.197.250 / .255`（ECU 段未用地址） | **纯 timeout，无任何 ICMP** | 路由器既不 ARP 也不转发 → **该 /24 不在它的路由表里** |
| `10.224.1.1`（从未部署的网段） | 纯 timeout，无任何 ICMP | 与 ECU 段表现完全一致 |

补充：

- `ping -i 1 10.226.197.5` → `Reply from 10.252.3.1: TTL expired in transit`：**包确实到达了路由器**，之后被丢弃，不是本机没发出去。
- `ping -i 2` 重做上述对照：直连 /24 仍回 host-unreachable，ECU 段仍全静默 ⇒ 路由器对 ECU 段没有下一跳（否则 TTL=2 会在第二跳产生 TTL-exceeded）。
- `ping -r 9`（record route）到 `10.225.139.4` 记录到 `10.225.139.1 → 10.225.139.4`，到 `10.226.193.2` 记录到 `10.226.193.1 → 10.226.193.2`；到 ECU 段无回包故无记录（`41_record_route.txt`）。
- LSRR 源路由（`ping -j 10.225.139.4|10.226.193.2 10.226.197.5`）全部超时——路由器丢弃源路由选项，不能用来借道 CGW（`40_gateway_interfaces.txt` 与执行记录）。

### 2.4 TCP：RST vs TIMEOUT，以及为什么 timeout 不能单独当证据

先做 fleet 对照（旧地址存活期，`01_tcp_controls.txt`）：**本舰队所有已知存活主机的关闭端口都是 DROP（纯 timeout），没有一台回 RST**。
所以"端口 timeout"单独不能证明主机不存在；本报告的不可达结论建立在 §2.3 的路由证据上，不是端口超时。

新地址实测（`11_newaddr_tcp_matrix.txt`、`44_ecu_8080_repeat.txt`）：

| 目标 | 8080 | 80 | 443 | 8443 | 13400 | 13401 | 3000 | 5000 |
|---|---|---|---|---|---|---|---|---|
| 10.226.197.5 | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT |
| 10.226.197.6 | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT |
| 10.226.197.7 | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT | TIMEOUT |

- **全端口**：3 台 × 65,535 = **196,605 次 connect，OPEN=0，RST=0**，157 s（`22_fullport_ecus.json`）。
- 复测：10:12 再测三台 8080，9/9 TIMEOUT（`44_ecu_8080_repeat.txt`）。
- UDP `13400/13401/8080` 在三台 ECU 上全静默（`33_udp_and_tls_13401.txt`）。

### 2.5 别名 / 邻段排查

| 扫描 | 规模 | 结果 | 证据 |
|---|---|---|---|
| `10.226.197.0/24` × 14 端口 | 3,556 | **0 hit** | `20_sweep24_10_226_197_0_24.json` |
| `10.225.139.0/24` × 14 端口 | 3,556 | `.2`/`.3`/`.4`（CGW 云侧） | `20_sweep24_10_225_139_0_24.json` |
| `10.226.193.0/24` × 14 端口 | 3,556 | `.2`（CGW 车侧） | `20_sweep24_10_226_193_0_24.json` |
| `10.226.0.0/16` × `8080,13400` | 131,068 | 只有 `10.226.193.2` | `21_sweep_10_226_0_16.json` |
| CGW 两个地址全端口 | 131,070 | 只有 `8080/13400/13401` | `23_fullport_cgw_addrs.json` |

结论：ECU 没有第二个地址；两个可达 /24 里也没有除既有服务之外的任何主机可作跳板。

---

## 3. 证据链 B：DoIP 侧（13400）

`03_EVIDENCE/ecu-reach/12_new_cgw_ident.txt`、`13_new_cgw_uds.txt`：

- Vehicle identification → VIN `CV622697F82A936A1`，entity LA `0x1000`，EID `060000001000`。
- Routing activation SA `0x0E00` → `0x10` 成功。
- `22F190` → VIN（POSITIVE）；`22F1A0` → `07E0 07E8 07E1 07E9`（两对 CAN 诊断 ID）。

### 3.1 定向转发矩阵（14_doip_forward_matrix.json）

对 `TA ∈ {07E0,07E8,07E1,07E9,E400,1000,1001,1002,1003,0001,1234}` × `UDS ∈ {3E00,22F190,1002}` 共 33 条：

- 除 `TA=0x1000` 外，**全部** `src=0x1000`、`NRC=0x31 (requestOutOfRange)` ⇒ 网关本地拒绝，未转发。
- `TA=0x1000`：`22F190` positive（网关自身），`3E00/1002` → `NRC 0x11`。

### 3.2 全 16 位逻辑地址扫描（18_ta_full_0000_FFFF.json）

单连接 + routing activation，按 64 条 pipeline 发送 `3E00`，逐块校验应答数（1,024 块，**65,536/65,536 全部有应答**，0 次需要串行补测）：

| 分类 | 数量 |
|---|---|
| `NRC31 from 0x1000`（未转发） | 65,534 |
| `NRC11 from 0x1000`（TA=0x1000 自身） | 1 |
| **`NRC11 from 0x1220`（TA=0xE442，真正被转发）** | **1** |

- 独立复跑一次结果逐条一致（`39_ta_sweep_REPEAT_3E00.json`）。
- `0xE000–0xEFFF` 单独重扫同样只有 `0xE442`（`35_ta_sweep_E000_EFFF.json`）。
- 定向验证：`TA=0xE442` 发 `22F190` 得到 `src=0x1220, 7F 22 31`；相邻 `0xE440/0xE441/0xE443/0xE444/0xE4FF/0xE400/0x07E0/0x07E1/0x07E8/0x07E9/0x1220` 全部 `src=0x1000, 7F 22 31`（`38_target_probe_22.txt`）。

### 3.3 第二个节点 0x1220 的能力（只读探测）

`36_entity_1220_readonly.txt`、`37_entity_1220_extended.txt`：

| 请求 | 响应 |
|---|---|
| `10 03` | **`50 03`**（扩展会话成功） |
| `10 01` / `10 02` | `7F 10 12`（subFunctionNotSupported） |
| `22 F190/F187/F189/F18C/F18E/F186/F188/F18A/F191/F194/F195/F1A0/F1A1/F1F0/F1F1/0100/0001` | 全部 `7F 22 31` |
| `19 02 FF` | `7F 19 11` |
| `3E 00` | `7F 3E 11` |
| `27 01` | `7F 27 7E` |

即：**DoIP 唯一的转发目的地是 `0xE442 → 0x1220`，它是一个纯 UDS 节点，不提供任何 IP/HTTP 面**；三台 ECU 的 8080 不在 DoIP 可达范围内。

> 交叉验证：`01_TARGETS/cgw/SECOND_NODE_1220.md`（cgw-doip，09:5x–10:1x）独立得出同一结论。本轮的差别是**流水线全扫**：65,536 条全部拿到应答（cgw-doip 的顺序扫有 125 条空响应，属于长尾超时），因此"唯一异源 0xE442"的结论更干净。

---

## 4. 证据链 C：CGW 13401（CAN FD 桥）

两个 CGW 地址（`10.226.193.2`、`10.225.139.4`）行为逐字节一致（`16_`、`19_`、`31_`、`32_`、`33_`）：

- `connect` 中位 26.4 ms；**客户端一个字节都不发**时，`+25.6 ms` 收到 FIN，10/10（`31_13401_close_timing.json`）。
- 发 DoIP ident/RA/diag、CAN 2B/4B id、CAN FD、ISO-TP、TLS ClientHello、HTTP GET/CONNECT、WebSocket、HTTP/2 preface、SOCKS5、MQTT、2B/4B LE/BE 长度前缀、JSON 行、16×`00` —— **全部 0 字节回包**。
- TLS 握手报 `SSLEOFError`（不是 TLS 服务）。
- 解释：服务端 `accept()` 后立即 `close()`，**从不 read**。任何"客户端先发首帧"的协议都不可能在当前状态被解析，不是协议猜错。
- 与 cgw 组包级证据一致：`03_EVIDENCE/cgw/0520_newenv_13401_packetlevel.txt`（第三个 ACK 携带 16B → 服务端 ACK 后同毫秒 RST，证明应用层未读）。因此维持 H15「关着的门」：**开桥后行为才可能改变**。

---

## 5. 证据链 D：SSRF / 反连 / 代理

`30_ssrf_battery.txt`、`03_EVIDENCE/ecu-reach/ssrf/callbacks.log`：

- 本机监听 `10.252.3.20:9999`（只绑本机 VPN 地址），在整个 battery 期间**零回连**。
- TSP `/graphql`：任意 query/variables（含 `url`、`callback`、`firmwareUrl` 字段）都返回同一句 demo 车 —— 静态桩，不解析输入。
- 对 TSP/T-BOX/CGW 的 8080 试 `?url=`、`/fetch`、`/proxy`、`/ota`、`/download`、`/redirect`、`/can`、`/bridge` → 全部 404。
- 绝对 URI 请求（forward-proxy 形式）被三台 8080 **本地**当普通路径处理，回 `200 {"status":"ok"}`；`CONNECT` → 404。⇒ 无正向代理语义。
- 结论：没有可用的 SSRF/代理中转。

---

## 6. 最终判定

### 6.1 判定

**目标 ECU `10.226.197.5/6/7:8080` 当前不可达，且不是"主机在、端口被过滤"，而是 IP 层没有路径。**

完整证据链：

1. `10.224.0.0/12 → 10.252.3.1` 的路由存在，包能到达路由器（`ping -i 1` 得到 TTL-exceeded）。
2. 路由器对**直连** /24（`10.225.139.0/24`、`10.226.193.0/24`）的未用地址会回 **ICMP host-unreachable**；对 `10.226.197.0/24` 与从未部署的 `10.224.1.1` **完全静默** ⇒ ECU 段不在路由器路由表中（或没有可用下一跳）。
3. 因此 TCP SYN 到 ECU 段被丢弃：196,605 次全端口 connect **0 OPEN / 0 RST**，ICMP echo 0 回包，UDP 静默。
4. 车辆侧唯一可达面是 CGW，但 DoIP 全 65,536 逻辑地址只有 `0xE442 → 0x1220` 一个转发目标，且它是纯 UDS 节点；`13401` 在开桥前 accept-close；8080 无代理/SSRF 面。
5. 两个可达 /24 与 `10.226.0.0/16` 内没有任何可作跳板的额外主机。

### 6.2 要打通需要的前置条件

| # | 前置条件 | 说明 |
|---|---|---|
| P1 | VPN 侧到 `10.226.197.0/24` 的路由（或让 ECU 段直连到 VPN 路由器 / 给一个该段内的 vantage） | 这是**唯一**能让 IP 探测生效的改动，属于平台侧 |
| P2 | 打开 CGW 13401 桥 | 桥开后才可能开始 read/回帧；开桥凭据在 OTA 工程包/后续任务（lead 已拿到含 mTLS 证书的工程包） |
| P3 | 或 CGW 出现 IP 转发/代理面 | 当前实测不存在（全端口只有 8080/13400/13401，8080 仅 `/healthz`） |
| P4 | 平台侧确认 ECU "运行中" 的定义 | 门户显示 running 只说明容器在跑，不代表其网络与 VPN 路由连通 |

**建议**：不要继续在 `10.226.197.5/6/7` 的 IP 面上投入。按题面链路走 `TSP → OTA 工程包 → T-BOX(mTLS) → CGW(DoIP) → 开 13401 桥`；桥开后再一次性复测 ECU 三台的 8080（用 `44_ecu_8080_repeat.txt` 同样的方法即可）。

---

## 7. 局限（随结论一起引用）

1. 本机**非管理员**：不能 `route add`、不能发 raw packet；LSRR 源路由实验失败不等于目标不支持源路由。
2. 舰队内已知存活主机的关闭端口 100% DROP ⇒ **端口 timeout 本身不能证明主机不存在**；本结论靠 §2.3 的路由器 ICMP 行为对照 + record-route，不靠端口超时。
3. DoIP 全空间扫描使用 `3E00` 探针。若某 ECU 被网关转发但**静默忽略** `3E00`，网关侧可能没有可观测应答；本次 65,536 条全部有应答、且唯一转发节点对 `3E00` 明确回 `NRC 11`，故该风险已被压低。
4. 13401 的"从不 read"结论由 TCP 层时序 + cgw 组包级证据共同支撑；源 IP 白名单（H12）在客户端侧不可证伪，仍作为 residual 保留。

---

## 8. 复核命令（全部只读）

```bash
cd D:/qwb

# 1) 路由 + 正对照 + ICMP host-unreachable 对照
route print -4 | grep 10.224
ping -n 2 -w 1500 -i 1 10.226.197.5            # 10.252.3.1 TTL expired
ping -n 2 -w 2000 10.225.139.250               # 10.225.139.1 host unreachable
ping -n 2 -w 2000 10.226.193.250               # 10.226.193.1 host unreachable
ping -n 2 -w 2000 10.226.197.250               # 静默
tracert -d -h 6 -w 1000 10.226.197.5
ping -n 1 -w 1500 -r 9 10.226.193.2            # record route: 10.226.193.1 -> .2

# 2) 精确 TCP（RST vs TIMEOUT）
python 04_SOLVE/ecu-reach/probe_tcp.py --targets 10.226.197.5,10.226.197.6,10.226.197.7 \
  --ports 8080,80,443,8443,13400,13401,3000,5000 --reps 3 --timeout 2.0 \
  --out /tmp/recheck_tcp.txt

# 3) DoIP：转发矩阵 + 全 16 位地址扫描
python 04_SOLVE/ecu-reach/forward_matrix.py --host 10.226.193.2 --timeout 3.0 \
  --out /tmp/recheck_fwd.json matrix \
  --tas 07E0,07E8,07E1,07E9,E400,1000,1001,1002,1003,0001,1234 --uds 3E00,22F190,1002
python 04_SOLVE/ecu-reach/full_ta_sweep.py --host 10.226.193.2 \
  --start 0000 --end FFFF --chunk 64 --pause 0.05 --out /tmp/recheck_ta.json

# 4) 13401 行为
python 04_SOLVE/ecu-reach/char_13401.py 03_EVIDENCE/ecu-reach/31_13401_close_timing.json
```

---

## 9. 证据索引

| 文件 | 内容 |
|---|---|
| `01_tcp_controls.txt` | 旧地址存活期对照：关闭端口全部 DROP，无 RST |
| `02_tcp_matrix_ecus.txt` | 旧地址三台 ECU 8 端口矩阵 |
| `10_newaddr_icmp.txt` / `11_newaddr_tcp_matrix.txt` | 新地址 ICMP 与 TCP 矩阵 |
| `12_new_cgw_ident.txt` / `13_new_cgw_uds.txt` | 新 CGW 身份、RA、22F190/22F1A0 |
| `14_doip_forward_matrix.json` | 定向 TA × UDS 转发矩阵（33 条） |
| `15_doip_ta_sweep.*` | 1,280 个地址的预扫 |
| `16_cgw_13401_handshake.json` | 13401 第一批 18 种 framed payload |
| `17_tracert_new.txt` | 新地址 tracert（含正对照） |
| `18_ta_full_0000_FFFF.json` / `.log` | 全 65,536 逻辑地址扫描（3E00，流水线） |
| `19_cgw_alias_13401_handshake.json` | 13401 在 CGW 云侧地址上的行为 |
| `20_sweep24_*.json` | 三个新 /24 的 14 端口普查 |
| `21_sweep_10_226_0_16.json` | `10.226.0.0/16` × 8080/13400 全扫 |
| `22_fullport_ecus.json` | 三台 ECU 全 65,535 端口（196,605 次） |
| `23_fullport_cgw_addrs.json` | CGW 两地址全端口 |
| `30_ssrf_battery.txt` / `ssrf/callbacks.log` | SSRF/反连 battery 与监听日志（零回连） |
| `31_13401_close_timing.json` / `.txt` | 13401 关闭时序（静默 10/10，+25.6 ms FIN）与 14 种 payload |
| `32_13401_protocol_battery2.txt` | HTTP/CONNECT/WS/h2/SOCKS5/MQTT 等第二批 |
| `33_udp_and_tls_13401.txt` | UDP 13400/13401/8080 静默；13401 非 TLS |
| `34_la_1220_probe.txt` | 0x1220 直连（物理寻址被网关拒绝） |
| `35_ta_sweep_E000_EFFF.json` | 功能地址段重扫（唯一 0xE442） |
| `36_entity_1220_readonly.txt` / `37_entity_1220_extended.txt` | 0x1220 只读能力矩阵 |
| `38_target_probe_22.txt` | 用 22F190 定向验证功能地址 |
| `39_ta_sweep_REPEAT_3E00.json` | 全空间扫描独立复跑 |
| `40_gateway_interfaces.txt` / `41_record_route.txt` / `42_router_unreachable_control.txt` / `43_ttl2_path.txt` | 路由器接口、record-route、ICMP 对照、TTL=2 路径证据 |
| `44_ecu_8080_repeat.txt` | 10:12 稳定性复测（9/9 TIMEOUT） |

**工具**（`04_SOLVE/ecu-reach/`）：`probe_tcp.py`、`forward_matrix.py`、`full_ta_sweep.py`、`sweep24.py`、`probe13401.py`、`char_13401.py`、`ssrf_listener.py`。

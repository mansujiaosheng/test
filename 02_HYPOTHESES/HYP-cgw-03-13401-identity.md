# HYP-cgw-03：13401/tcp 的身份（"CAN FD 桥"）

状态：**已收敛（证伪优先）**｜负责人：cgw｜时间：2026-11-14 09:17–10:10 CST
目标：旧实例 10.229.221.2:13401 = 10.230.164.4:13401；新实例 **10.226.193.2:13401**（09:5x 靶场重启后迁移）

## 判定规则

每条假设必须给出**可证伪判据**；判据不满足即记 REFUTED，并写下"若要翻案需要什么新观测"。
唯一成功判据（对本题）＝能稳定收发任意一帧（服务端回 ≥1 字节，且内容随请求变化）。

## 台账

| ID | 假设 | 判据 | 实测 | 结论 |
|---|---|---|---|---|
| H1 | 服务端先发握手帧，客户端读太早 | 建连后不发数据、保持 ≥3 s，应收到 banner | 0 字节；**25.6 ms 就收到 FIN** | **REFUTED** |
| H2 | 需要 DoIP routing activation 状态（同源 IP） | 13400 SA 0x0E00 激活成功(0x10)后立即连 13401，应有不同行为 | 仍 FIN（27.0 ms） | **REFUTED** |
| H3 | 需要 UDS 扩展会话/其他 13400 状态 | 13400 上 0x10 03 后再连 | 仍 FIN（29.3 ms） | **REFUTED** |
| H4 | 需要特定 TCP 源端口（tester 端口） | 本地 bind 13400 后连 | 仍 FIN（25.7 ms） | **REFUTED** |
| H5 | 只有 10.230.164.4 实例是真的 | 对 .4 重复 A 实验 | 仍 FIN（26.3/13.6 ms） | **REFUTED** |
| H6 | 时间窗/周期性开窗 | 60 s、20 次采样 | 20/20 FIN | **REFUTED** |
| H7 | TLS / mTLS / TLS-PSK | ClientHello 应得到 ServerHello 或 alert | EOF（lead 已测）；且 §"关键推理" 证明从不 read | **REFUTED** |
| H8 | 已知车联网桥协议（SLCAN/ELM327/socketcand/cannelloni/SOME-IP/DoIP-on-13401） | 规范握手应有回包 | 20 条全无回包，行为完全一致 | **REFUTED** |
| H9 | 自定义长度前缀 / 魔数 | 1/2/4 字节 LE/BE、AA55/CANFD/CANGW 前缀 | 全无回包 | **REFUTED** |
| H10 | 数据必须在 accept 前入队（TFO 思路） | 数据放第三个 ACK，应被读取并回包 | 服务端 ACK 数据后 RST，**未 read** | **REFUTED** |
| H11 | **accept 后立即 close 的空监听（死服务/诱饵/TCP wrapper）** | 无数据→FIN；有数据在队列→RST；全程无 read/write | A/D: FIN；B/C: RST；C 中先 ACK 后 RST | **SUPPORTED（唯一与全部观测一致）** |
| H12 | 源 IP 白名单（只放行内网/车辆网段） | 客户端行为无法改变；需内网 vantage 或伪源 IP | 无法证伪 | **UNTESTABLE（residual）** |
| H13 | 真实桥进程已死/未启动，只剩 listen socket 或 wrapper | 与 H11 观测一致，无法从外部区分 | —— | **residual（与 H11 相容）** |
| H14 | 真实服务在 UDP 13401 | 应回帧 | 无回包；但对照关闭端口也无 ICMP → 探测法失效 | **INCONCLUSIVE** |

## 关键推理（为什么 H11 成立而其他全灭）

1. 抓包（`0511_13401_packetlevel.txt`）：
   - 无数据连接：`S → SA → A → FA(len 0)`，FIN 在 25.6 ms（≈1 RTT）到达。
   - 数据在第三 ACK：服务端 `A(ack=seq+16)` 后**同一毫秒** `R(ack=seq+16)`。
   - `close()` 时接收队列有未读数据 ⇒ 内核发 RST；应用读取过则会 FIN。**这说明 read 从未发生。**
2. 任何应用层协议都必须先 read（否则无法解析 ClientHello/DoIP/SLCAN/MQTT…），因此 H2–H10 不是
   "参数没调对"，而是**机制上不可能**。
3. 于是只剩"监听被中间层替换/限制"（H12）或"真实服务不在这个 listener 后面"（H13/H14）。

## 交叉验证（其他组员的独立实验，结论一致）

- `04_SOLVE/cgw/13401_bytes.json`（另一组，09:37）：**256 个单字节值**逐个测试，`FIN=156 / RST=100`，
  **`with_rx = 0`**（没有任何一个值得到回包）。FIN/RST 的分布正是"数据与 close 赛跑"的统计指纹。
- `03_EVIDENCE/cgw/sec04/13401_framing.jsonl`（另一组，09:31）：27 种 framing 全部无回包。

两组独立数据 + 本组的包级实验，共同支持"该 listener 不 read、不 write"。

## 新实例复现（10.226.193.2，2026-11-14 10:02）

靶场 09:5x 重启后 CGW 迁移到 10.226.193.2（VIN `CV622697F82A936A1`），同一套 A/B/C/D 包级实验逐字节复现：

| 实验 | 观测 | 结论 |
|---|---|---|
| A 只建连 | +26 ms `FA`，0 载荷 | accept-close 不变 |
| B 建连后发 16B | `FA ack=our_syn+1`（未 ACK 16B）→ `R` | FIN 先于数据；数据未读 |
| C 16B 在第三 ACK | `A(ack=seq+16)` → 同毫秒 `RA` | **仍未 read（决定性）** |
| D 无数据对照 | 干净 `FA` ×4 | 行为稳定 |

证据：`03_EVIDENCE/cgw/0520_newenv_13401_packetlevel.txt`。

| ID | 假设 | 判据 | 实测 | 结论 |
|---|---|---|---|---|
| H15 | **"关着的门"：桥未开时 accept-close，开桥后开始 read/回帧** | 开桥例程成功后 13401 出现 DATA 或 STILL_OPEN | 当前仍 CLOSED；`watch_bridge.py` 已上线监测 | **待验证（当前主解释）** |

H15 与 H11/H13 不冲突：H11 描述"未开桥时的可观测行为"，H15 描述"该行为会因开桥而改变"。
题面"经 13400 诊断例程开启 CAN FD 桥"直接支持 H15；但 13400 的网关自身无 0x31（`7F3111`），
唯一有 0x31 的 `0x1220` 被安全门锁死（`7F 31 33`），故开桥凭据需来自 DoIP 之外。

## 新实例上的 gate 状态实验（10:05–10:06）

前提：13400 的 DoIP 必须**先 routing activation 再发诊断报文**，否则网关回 `src=0x1000, NRC 0x22`
（conditionsNotCorrect）——这是 cgw-doip 之外容易踩的坑（我们第一轮就踩了，见 `0528`）。

| 前置动作（同一 13400 socket） | 0x1220 响应 | 13401 gate |
|---|---|---|
| activation 0x0E00 | `0e00100010…` | FIN |
| activation type 0x00/0x01/0xE0/0xE1 + OEM "CGW1" | 全部 0x10 | 全部 FIN |
| `0xE442 10 03` | **`1220 0E00 50 03`**（扩展会话成功） | FIN ×2 |
| `0xE442 31 01 FF00` | `1220 0E00 7F 31 33`（安全拒绝） | FIN ×2 |
| `0xE442 27 01` | `1220 0E00 7F 27 7E` | FIN ×2 |
| `0xE442 22 F1A3` | `1220 0E00 7F 22 33` | FIN ×2 |

⇒ 13401 的 gate 不由 activation type、也不由 0x1220 的会话状态直接控制；要么由**成功的
securityAccess + 例程**控制，要么在别处（凭据链）。

## 翻案条件（若要重开）

- VPN 恢复后，**低频**（≤10 连接，间隔 ≥1 s）复核：若出现任何 ≥1 字节回包或行为改变 → 重开。
- 出现内网 vantage（10.229.221.0/24 或 10.224.139.0/24 内的主机）→ 测 H12。
- 能收到 ICMP 或可在对端抓包 → 测 H14。

## 关联证据

`03_EVIDENCE/cgw/0500`–`0511`（行为、时序、跨主机、状态、协议 shotgun、包级实验），索引见
`03_EVIDENCE/cgw/README.md`。目标画像见 `01_TARGETS/cgw/13401_can_bridge.md`。

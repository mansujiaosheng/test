# 共享简报 — 赛题 09「建立 VCU 签名更新下载状态」

> 所有 agent 开工前必读。Lead 维护此文件；各 agent 只在末尾「事实追加区」追加，不改别人条目。

## 0. 环境

- **CTF_ROOT = `D:\qwb`（唯一可写根）**，CHALLENGE_DIR = 无（纯远程靶场）
- VPN：OpenVPN TAP，本机 10.252.3.20，路由 `10.224.0.0/12 -> 10.252.3.1`
- 本机非管理员，不能改路由
- 目录结构见 `INDEX.md`：00_SCOPE / 01_TARGETS / 02_HYPOTHESES / 03_EVIDENCE / 04_SOLVE / 05_TOOLS / 06_WRITEUP / 07_LESSONS / 99_DEAD

## 1. 本轮目标（用户点名，唯一成功判据）

**赛题 09：建立 VCU 签名更新下载状态**

> 「进入 Programming Session，提交正确地址、明文长度、加密包长度与 rollback，取得 TransferData 块长度。」

拆解成可验证的子目标：
1. 进入 **Programming Session**（UDS `10 02`，或等价 HTTP 状态机）
2. 提交一组**正确**的 (地址 address, 明文长度 plaintext_len, 加密包长度 encrypted_len, rollback 值)
3. 服务端返回 **TransferData 块长度**（UDS `74` 响应里的 `maxNumberOfBlockLength`，或 HTTP 等价字段）

拿到块长度 ⇒ 该子目标达成。若该步响应里带 flag，按 flag 判据处理。

## 2. 目标清单与可达性（2026-11-14 09:2x 实测）

| # | 名称 | 入口 | 可达性 |
|---|---|---|---|
| 01 | TSP 云服务与 OTA 签名 | 10.230.164.2:8080 | ✅ 可达（仅 /healthz、/graphql） |
| 02 | T-BOX OTA 与 mTLS 诊断 | 10.230.164.3:8080 / 8443 | ✅ 可达（8080 仅 /healthz；8443 强 mTLS） |
| 03 | 中央网关 / DoIP / CAN FD 桥 | 10.229.221.2 = 10.230.164.4，8080/13400/13401 | ✅ 可达（DoIP 可用） |
| 04 | BCM SecOC 车身控制器 | 10.224.139.5:8080 | ❌ 直连不可达 |
| 05 | BMS RV32IM 固件与密钥派生 | 10.224.139.6:8080 | ❌ 直连不可达 |
| 06 | VCU 签名刷写 Bootloader | 10.224.139.7:8080 | ❌ 直连不可达 |

**关键推论**：VCU 直连不通 ⇒ 大概率要经 **中央网关（DoIP ↔ CAN FD 桥）** 打到 VCU。
`10.224.139.0/24` 整段无响应（无 RST，纯超时）⇒ 该网段未部署，只能走网关转发。

## 3. 已确认事实（勿重复验证）

1. 三个 8080 全是 Go net/http 明文 HTTP/1.1；`/healthz` → `{"status":"ok"}`；其余 404 `404 page not found`。
   已扫 1576 条唯一路径 × 3 主机，除 TSP 的 `/graphql` 外 0 命中。
2. TSP `/graphql`：POST 任意合法 JSON → 恒定
   `{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}`（不解析 GraphQL，是桩）。
   非法 JSON → `{"error":"invalid GraphQL request"}`；GET → 405。
3. T-BOX 8443：TLS1.3 only、强制客户端证书、服务端证书 `CN=tbox` / issuer `CN=CV6 Fleet Diagnostics Root`。
   无客户端证书 → alert 116；自签/伪造 CA → alert 48 unknown ca（真验签）。
4. CGW DoIP 13400：车辆识别 → VIN `CV6FF52FEE9EDDD86`，entity LA `0x1000`，EID `060000001000`。
   Routing activation SA `0x0E00` → code `0x10` 成功，tester LA `0x1000`。
   UDS `22F190` → VIN 正常。`10 03` → `7F 10 11`。
   **65536 个目标地址全扫（`03_EVIDENCE/cgw/1318_lascan_0000_ffff.jsonl`）：65409 个回 `7F3E31`，125 个空响应，2 个 `7F3E11`。**
   ⇒ 网关对所有 TA 都由 0x1000 回 NRC 0x31，没有明显的 ECU 分支。
5. CGW 13401：TCP 可连，发任意字节后立即关闭且不回包，疑似诱饵或需特定握手。

## 4. 目录分工（严格避免互相覆盖）

| 范围 | 归属 | 可写目录 |
|---|---|---|
| TSP 10.230.164.2 | teammate `tsp` | `03_EVIDENCE/tsp_s09/` `04_SOLVE/tsp_s09/` `01_TARGETS/tsp_s09/` |
| T-BOX 10.230.164.3 | teammate `tbox` | `03_EVIDENCE/tbox_s09/` `04_SOLVE/tbox_s09/` `01_TARGETS/tbox_s09/` |
| CGW 10.229.221.2 / DoIP | teammate `cgw` | `03_EVIDENCE/cgw_s09/` `04_SOLVE/cgw_s09/` `01_TARGETS/cgw_s09/` |
| ECU 直连 / 10.224.139.0/24 | teammate `ecu` | `03_EVIDENCE/ecu_s09/` `04_SOLVE/ecu_s09/` `01_TARGETS/ecu_s09/` |
| 统筹 / UDS 状态机 / 交付 | lead | `INDEX.md` `00_SCOPE/` `05_TOOLS/` `06_WRITEUP/` `02_HYPOTHESES/` |

**旧的 `03_EVIDENCE/cgw/`（1296 个文件）是上一轮产物，只读参考，不要写进去。**

## 5. 纪律

- 只写自己那几行目录；要改公共文件先发消息给 lead。
- 每条结论必须能追溯到 `03_EVIDENCE/<你>/` 里的原始输出（命令 + 输入 + 输出 + 时间）。
- 禁止破坏性/高并发爆破；UDS 写操作只做可逆探测。
- 找到疑似 flag：立刻 `send_message` 给 lead，并写进 `06_WRITEUP/` 之外自己的证据目录，lead 统一校验。
- flag 正则未定，暂用宽松判据 `[A-Za-z0-9_]{2,20}\{[ -~]{1,120}\}`。
- **不要重复已验证过的事实**（见 §3），把时间花在「解锁下一跳」上。

## 6. 事实追加区（各 agent 追加，lead 汇总）

### [ecu] 2026-11-14 09:47 — 13401 定性 + 10.224.139.0/24 证伪

**A. `10.229.221.2:13401` = 空壳监听器（accept 后立即 close），不是 DoIP 隧道、不是 TLS/HTTP，别再投入。**
- 空连接（**零字节发送**）12/12 被对端有序 FIN 关闭（`SO_ERROR=0`），中位 27.8 ms ≈ 1 个 RTT ⇒ 应用层 `accept()`+`close()`，与 payload 无关。
- 32 个探针（17 协议 + 9 长度 + 6 并发）**全部 recv = 0 字节**：无 TLS alert / 无 HTTP 400 / 无 DoIP 否定响应。
- 长度不敏感（1B→7.4 ms … 4096B→30.5 ms，无单调关系）；逐字节慢滴时第 11 字节就 `ConnectionAbortedError(10053)` ⇒ 无帧格式。
- 控制组同主机 **13400 空连接 3/3 保持打开**（真 DoIP），两者行为相反 ⇒ 13401 的关闭是其自身实现选择。
- UDP 13401：3/3 超时无回包，无 UDP 服务。
- nmap 对 13401 回 `syn-ack`/`open` ⇒ 排除"未监听/被过滤"。
- 报告 `03_EVIDENCE/ecu_s09/REPORT_13401.md`，脚本 `04_SOLVE/ecu_s09/{probe13401,control_13401_vs_13400,final_13401}.py`，原始 `03_EVIDENCE/ecu_s09/runs/`。

**B. 13400 控制组顺带复核（与 §3.4 一致）**：`02fd000100000000` → 41 字节 `02fd 0004 len=33 VIN=CV6FF52FEE9EDDD86 LA=0x1000 EID=060000001000 GID=0 further=0x00`。

**C. `10.224.139.5/.6/.7` 不可达确认（证伪留痕 `99_DEAD/ecu-reachable/WHY.md`）**
- ICMP 4/4 超时 ×3；对照 `10.230.164.2` 回包 **TTL=63**（=1 跳）。
- tracert：第 1 跳 `10.252.3.1` 正常，之后 2–8 跳全黑（无 ICMP TTL-exceeded）。
- `-sT -p 22,80,443,8080,8443,13400,13401`：**21/21 组合 `filtered`，reason 全 `no-response`**（既无 syn-ack 也无 rst）。
- `10.230.164.0/24 + 10.229.221.0/24` 共 512 IP：只有 `.2/.3/.4` 有开放端口，**无第 4 台主机、无换址的 VCU**；`10.229.221.2` 与 `10.230.164.4` 为同一台。

**D. 两个环境坑（会影响其他人）**
1. **本机 nmap `-sS`/`-sA` 静默失败**（非管理员无 Npcap 原始套接字）：只打印 `Starting Nmap` 即退出，**exit 0、输出文件 0 字节**，极易误读成"扫了没结果"。本机只能用 `-sT`。
2. 批量扫别用 `--host-timeout 15s`：512 目标下 `10.229.221.x` 大量记 `Timeout`，需单点复核。

# DoIP/UDS 面（13400）· 结论与复核方式

> 面向后续接手者。**先读这页，再决定要不要继续在 13400 上花时间。**

## 一句话结论

T03 的 13400 是一个**只读最小实现**：DoIP 识别 + routing activation + 一个 UDS 服务（0x22）
+ 两个 DID（VIN、4 个 CAN 诊断 ID）。**898 个逻辑地址里只有 0x1000 活着；256 个 UDS 服务里只有
0x22 存在；65536 个 DID 里只有 2 个有数据。** 没有任何 SecurityAccess、会话控制、写类服务，
也没有 flag。真正要打的东西在 13401。

## 复核（全部只读，逐条可跑）

```bash
cd D:/qwb

# 1) 身份 + 双地址同一性
python 04_SOLVE/cgw/doip_client.py --timeout 3.0 --out-dir 03_EVIDENCE/cgw \
  compare --hosts 10.229.221.2,10.230.164.4 --uds 22F190

# 2) 单条 UDS（带 routing activation）
python 04_SOLVE/cgw/doip_client.py uds --sa 0E00 --ta 1000 --uds 22F1A0
python 04_SOLVE/cgw/doip_client.py uds --sa 0E00 --ta 1000 --uds 22F190
python 04_SOLVE/cgw/doip_client.py uds --sa 0E00 --ta 1000 --uds 2701     # 7F2711
python 04_SOLVE/cgw/doip_client.py uds --sa 0E00 --ta 1000 --uds 1003     # 7F1011

# 3) TA 枚举（约 2 分钟，内建超时复测）
python 04_SOLVE/cgw/doip_client.py --gap 0.05 --timeout 2.0 --out-dir 03_EVIDENCE/cgw \
  sweep-ta --sa 0E00 --probe 3E00 --ranges 0001-00FF,0700-07FF,0E00,0E80-0EFF,1000,1001-10FF

# 4) 服务集 / DID 异常复测 / 协议层 / socket 语义
python 04_SOLVE/cgw/doip_service_sweep.py
python 04_SOLVE/cgw/doip_did_anomaly.py
python 04_SOLVE/cgw/doip_layer_probe.py
```

## 关键操作细节（踩过的坑）

1. **别用 0.8s 超时判"无响应"。** 网关偶发 800ms–4s 慢应答（p95≈800ms，测到过 4.0s 超时），
   150 连发无速率限制。任何 TIMEOUT 必须 ≥3s timeout 复测 ≥3 次。
   → 这直接推翻了"0x000A/0x000B/0x0022..0x0033 是隐藏地址段"的假设。
2. **别只按"有没有响应"分类 TA。** 网关对不认识的 TA 也会回，只是 NRC 是 0x31。
   判据用 `from=0x1000 & NRC=0x31` = 不认识；`from=0x1000 & NRC=0x11` = 认识但服务没实现。
3. **`22` 只吃恰好 3 字节**（SID+2 字节 DID）。多 DID、少字节、带尾巴一律 `7F 22 11`。
4. **29-bit CAN ID 不能当 DoIP 逻辑地址**，`0x18DA00F1` 会被 16 位单板截断成 `0x00F1`。
5. **客户端读取要"响应驱动"**：先等 0x8002 ack 再等 0x8001，拿到终态响应立刻返回。
   若用"空闲 gap 收满"的读法，每次请求会白白多等 350ms，扫描速度差 6 倍，还会把慢应答误判成超时。
   `doip_client.py` 的 `diag()` 已按此实现。
6. **扫描前必须 drain，且校验负响应回显的 SID。** 网关偶尔在上一次请求超时之后才把响应发出来，
   这帧会被下一次请求读到，表现为"请求 `13` 却收到 `7F 12 11`"。本组第一版服务扫描就踩到了
   （SID 0x12/0x13 出现异常）。修法：`DoIPClient.drain()` + 校验 `7F` 后那字节是否等于本次 SID，
   不等就丢弃。加了这两步重跑，1533/1534 条响应全部规整，只有 0x22 有非 0x11 响应。
   证据 `doip_sid12_13_isolate.txt`（新连接 + 6s 超时下 0x12/0x13 全部规整回 `7F xx 11`）。

## 交付物

| 文件 | 内容 |
|---|---|
| `04_SOLVE/cgw/doip_client.py` | 客户端/库，CLI: `ident` `ra` `uds` `raw` `sweep-ta` `sweep` `compare` |
| `04_SOLVE/cgw/doip_service_sweep.py` | 256 SID × 6 形状的服务集扫描 |
| `04_SOLVE/cgw/doip_did_anomaly.py` | 38 个"无响应"DID 的 4s×3 轮复测 |
| `04_SOLVE/cgw/doip_layer_probe.py` | DoIP 层：ptype/版本/激活/长度/UDS 边界 |
| `04_SOLVE/cgw/doip_reclassify_ta.py` | 从 jsonl 重算 TA 矩阵（分类器修正后） |
| `01_TARGETS/cgw/doip_gateway.md` | 目标档案（含全部实测数据与协议偏离清单） |
| `02_HYPOTHESES/HYP-doip-00{1..5}` | 假设台账（4 条证伪、1 条证实） |
| `03_EVIDENCE/cgw/doip_*` | 原始证据：矩阵、jsonl、console |

## 明确没做 / 不建议再做

- **SecurityAccess 穷举**：0x27 是 `7F 27 11`，服务不存在，穷举无意义。
- **DID 再扫**：0x0000–0xFFFF 已被两拨人扫完（cgw 全扫 + 本组异常复测），只有 2 个有值。
- **压力/模糊测试**：会打崩共用靶机，且 13401 由 cgw 组在用；已做的低强度边界测试未见异常。
- **UDP 13400 发现面**：已测，完全静默（`03_EVIDENCE/cgw-doip/E-cgw-udp-identify-01.txt`）。

## 未完成项（因赛事 VPN 掉线，非目标行为）

**"激活前"服务扫描只跑到 SID 0xA4。** 补跑用 `doip_service_sweep_no_activation.py`（已写就，带三重护栏）：

1. **preflight**：先做 ident + RA + `22F190` 读 VIN 三段校验，任何一步不过直接 abort、不写任何记录；
2. **连续 5 次失败即中止**（网关正常 ~60ms 必答，连续失败只可能是网络断了）；
3. 每个"无响应"在**新连接上复测一次**才计入。

已确认部分：SID **0x00–0xA4** × 3 种形状（约 495 次）**全部规整 `7F <sid> 22`**，
即"未激活 → conditionsNotCorrect"这条分支没有任何隐藏行为。
0xA6–0xFF 待 VPN 恢复后跑一次即可收尾（约 1 分钟）。

> 掉线经过见 `03_EVIDENCE/cgw/doip_outage_vpn_down.txt`。**教训**：扫描脚本必须自带
> "网络死了就中止"的护栏，否则一整段 `None` 会被误读成"目标对这些请求不响应"——
> 这正是本次差点产生的假结论。

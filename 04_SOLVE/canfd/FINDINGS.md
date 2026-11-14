# 05+06 CAN FD 层：桥开之前的准备结论

**状态（2026-11-14 11:25）**：四个工具全部就绪并自测通过（179/179 checks），**尚未接触真靶机**。
13401 此刻仍是 accept-then-close（见 §5），所以这里所有结论都是本地可复现的，不是靶机结论。

- 工作目录：`04_SOLVE/canfd/`
- 证据目录：`03_EVIDENCE/canfd/`
- 一键复跑：`python 04_SOLVE/canfd/run_all.py`

| 模块 | 作用 | 自测 | 证据 |
|---|---|---|---|
| `isotp.py` | ISO 15765-2:2016 for CAN FD，双向 | 71/71 | `00_selftest_isotp.{json,log}` |
| `secoc.py` | AUTOSAR SecOC 认证器 + profile 反推 | 52/52 | `01_selftest_secoc.{json,log}` |
| `bms_dump.py` | 0x23 ReadMemoryByAddress 拉 16 KiB | 31/31 | `02_selftest_bms_dump.{json,log}` |
| `tap13401.py` | 13401 framing 判定 + 传输层 | 24/24 | `03_selftest_tap13401.{json,log}` |
| — | 13401 baseline 探测 | — | `20_tap13401_probe_20261114-111919.json` |

---

## 1. ISO-TP：做到的边界条件

CAN FD 与经典 CAN 的差别全在长度编码上，这也是最容易写错的地方：

- **SF**：`N_DL=8` 时最多 7 B（PCI `0x0N`）；`N_DL>8` 时 8..62 B **必须**用转义形式（PCI `0x00` + 第二字节 SF_DL）。62 B 是上限（64 − 2）。
- **FF**：12-bit `FF_DL`；> 4095 B 自动切转义形式（`FF_DL=0x000` + uint32 BE），这正是 16384 B 读固件必须走的分支。自测里 4095 仍用 12-bit、4096 切转义，两条都钉住了。
- **FC**：FS（CTS/WAIT/OVFLW/reserved）、BS、STmin 三字段齐活；`FS=1` 受 `N_WFTmax=10` 约束，`FS=2` 立即 abort。
- **CF**：SN 1..15 回绕到 0；末帧允许不补齐（短帧），接收端按 FF 声明长度裁剪。
- **STmin**：`0x00–0x7F` 毫秒、`0xF1–0xF9` = 100–900 µs、`0x80–0xF0`+`0xFA–0xFF` 保留值按 127 ms 处理。自测测得 20 ms 档每 gap ≥ 20.04 ms、`0xF3` 档每 gap ≥ 312 µs（不是 300 ms）——这条是本节最容易被写错、也最容易在真车上表现为「ECU 丢帧」的地方。
- **发送侧的单帧判据**：SF 是否可用，取决于**本链路 N_DL**，不是 CAN FD 的 62 B 上限。16 B 链路上的 24 B 响应必须走 FF + CF（这条在自测里真实撞到过，已修）。

16384 B 双向回环：`dl=16` 时 FF 携带 10 B + 1092 个 CF（137 个 FC 块）；`dl=64` 时 260 个 CF。两个方向 sha256 都与源一致。

## 2. SecOC：参数化，等一份真实样本

题面要求「读取完整 64 位 Freshness，恢复 DataID/Payload/Freshness 的 AES-CMAC 输入」。现在没有抓包，所以**没有**硬编码任何一种拼接顺序：

- `SecocProfile` 把 DataID 宽度/字节序、Freshness 宽度/字节序、MAC 截断位数（24/28/32/64，含非字节对齐的 28）、取高位还是低位、三个 MAC 输入的拼接顺序、帧内 section 顺序、`TruncatedFreshness` 字节数、填充字节、CAN FD 长度全部做成字段。
- `crack()` 拿 ≥2 帧同 payload、不同 freshness 的抓包做**整帧逐字节**比对，只留全部命中的 profile。单帧不够：MAC 覆盖不到的参数（比如载荷字段填满时的填充字节）会留下等价解，自测里专门把这条证出来了。
- AES-CMAC 用 RFC 4493 四组向量自校验通过（空/16/40/64 B）。
- 交付形态：`to_canfd_frame()` 产出 16 B CAN FD 帧且 `brs=True`。
- **裸帧也能反推**（真车上的实际形态）：`Capture.from_frame(frame, freshness)` 不带 payload，`crack()` 会把 payload 的**长度**也当成搜索维度一起解。原因是 AUTOSAR 的语义 —— SecOC 先认证**未填充**的 I-PDU，之后才补 CAN FD 填充，所以帧里的填充字节不在 MAC 输入里；只按字段全宽去切会永远对不上（这个坑我在自测里真实撞到并修了）。解出来的 `CrackResult.payload_len` 就是真实 PDU 长度。

**桥开后需要第一件事**：抓 BCM 的 2–3 帧同类控制帧 + 读一次 64 位 Freshness，然后跑

```
python secoc.py --crack captures.json --key <候选key> --dataid <候选或区间>
```

`captures.json` 格式见 `Capture.from_dict`（payload / freshness / secured / can_id）。

## 3. BMS 固件读取

- 请求：`23 <ALFID> <addr> <size>`；ALFID 高半字节 = size 字段宽度，低半字节 = 地址宽度。`0x24` 是默认（size 2 B / addr 4 B），`0x14`（size 1 B）**表达不了 512**，会在本地直接 ValueError；真车上若要试，会得到 NRC 0x13。
- 顺序：先 `10 01`（必要时 `10 03`）拿会话 → ALFID 协商 → 32 × 512 B → 每块**读两遍**比对 → 可选跨块接缝复读。
- 完整性：逐块 sha256 + 整镜像 sha256；瞬态差异记 `mismatch` 并重读，最终仍不一致的块标 `unconfirmed`（不静默放过）。
- 结构体检 `rv32_sanity()`：reset vector（`0x000000EF`/`0x6F` 这类 jal）、字符串、高熵窗口、**孤立高多样性常量块**（32 B 里 ≥20 种字节且邻居低多样性 —— 这是嵌入式 AES/HMAC 密钥最典型的形状，自测里在 `0x0200` 命中而密集随机体段不误报）。
- CAN ID：默认 `--pair ecu2` = 7E1/7E9（BMS 大概率在第二对），`--pair ecu1` 切换 7E0/7E8。
- 地址基址默认 `0x00000000`，`--base` 可切 `0x08000000` 等；先用 16 B 探测再决定全量起点。
- `--scan` 一次连接就回答两个问题：两对 CAN ID 哪一对答 0x23、四个候选基址哪个有真实代码（判据：非全 0xFF / 非全 0x00）。全是只读，避免把「探测」混进 32 块的全量 dump 里。

## 4. 13401 framing：判定方法已就位

覆盖 6 类 framing、14 个具体 codec：

| 家族 | 形态 | 备注 |
|---|---|---|
| `raw8/16/64` | 裸帧数据，长度由 codec 决定 | 无元数据，最省事也最难确认 |
| `id2+16 / id4+16 / id4+64` | CAN ID + 数据 | ID 2/4 字节大端 |
| `len1/len2/len4 + 帧` | 长度前缀 + 数据 | 大端/小端都试 |
| `slcan` | `t7E180210...\r`；CAN FD 用 `d/b`，DLC 码 9=12 … F=64 | LAWICEL 风格，最像「CAN FD 桥」 |
| `socketcand` | `< send 0x7E1 8 02 10 >` / `< frame ... >` | Becker |
| `candump` | `(ts) can0 7E1#0210...` | 日志风格 |
| `isotp-direct` | 2 B 长度 + UDS 原文 | 桥自己终结 ISO-TP |

`--record frames.jsonl` 可把收到的帧逐条落盘（ts / can_id / dl / hex / brs / fd），直接作为 SecOC 分析的输入；配合 `secoc.py` 的裸帧模式就是完整链路：录帧 → 读 Freshness → `crack` → 定参数。

`detect()` 的探针**只发协议问候**（`V\r`、`< hi >`、裸 `\r`），不发任何 CAN 帧、不碰总线状态。四种结局可区分：

1. 服务端先说话 → 按 banner 分类；
2. `V` 回版本 → slcan；
3. `< hi >` 回 `< ok >` → socketcand；
4. 全部静默且 accept-then-close → **桥未开**（而不是"猜某种 framing"）。

自测用三个本地假桥（slcan / socketcand / 静默 raw）验证：三个都判对，且一个 520 B 的 `0x63` 响应能经 sLCAN 编解码后由 `IsoTpLink` 完整重组。

## 5. 13401 现状（2026-11-14 11:19 实测）

`tap13401.py --probe` 四个探针全部 `peer closed`，各约 51 ms 后 FIN，双向 0 字节：

```
passive         56.8 ms  0 B
slcan:V         51.7 ms  0 B
socketcand:hi   51.3 ms  0 B
bare-cr         51.8 ms  0 B
```

与上一轮的 accept-then-close 一致 ⇒ **桥仍未打开**。这条记录的价值是把「桥没开」与「framing 猜错」区分开：真开了以后，除非服务端彻底静默只发不收，否则至少有一个探针会回字节。

## 6. 桥开之后的顺序（已排好，等通知）

1. `python tap13401.py --probe` → 拿到 framing（若 `confidence=guess` 则逐个 `--framing` 试，先 `raw16`）。
2. `python bms_dump.py --scan` → 一次连接判定「哪对 ID 答 0x23 + 哪个基址有代码」。
3. `python bms_dump.py --pair <判定结果> --base <判定结果> --out ...` → ALFID 协商 + 32 块双读。
4. 拿到镜像 → `bms_dump.py --analyze <bin>` 出结构体检，交给 fw-re/任务 08。
4. SecOC：`tap13401 --monitor --record` 抓 2–3 帧 + 读 Freshness → `secoc.py --crack`（裸帧模式，顺带解出 payload 长度）；参数确认前**不发**控制帧（题面要求 BCM ACK，属写操作，必须等参数锁定）。

## 7. 未决 / 需要真靶机才能定的

- SecOC 真实 profile（DataID 值、Freshness 来源与步进、MAC 截断位数、是否带 TruncatedFreshness）。
- BMS 首地址基址（0x0 / 0x08000000 / 其他）与是否需要 `10 03`。
- 13401 是否要求先发某种「开桥确认」（握手）才转发帧。
- 0x23 单次 512 B 是否受 `maxNumberOfBlockLength` 限制；若受限，需降到 256/128 并加次数。

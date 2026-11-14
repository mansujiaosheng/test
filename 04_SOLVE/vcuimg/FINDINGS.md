# vcu-reference.bin 逆向 · FINDINGS

**日期**：2026-11-14 10:45–11:00 CST
**对象**：`work/bundle2/x/vcu-reference.bin`（1024 B，sha256 `2f3692767f605ef72fb47e1a779f2dfaeca802b4df1e35d38f8bb66d53ce6ea7`）
**范围**：只读离线分析；未联网、未改靶机。
**口径**：每条结论给 `offset + 原始字节 + 判据`，标注 `[确证]` / `[否定]` / `[推断]`。凡"假设成立则必然看到 X，实测看到 Y"的判据都写在对应小节。

---

## 0. 一句话结论

`[确证]` 该文件**不是 ARM/RV32 代码、不是用包里任何 key 能解开的密文、也不含双 lane 算法常量**。它是一份**随包固定分发**的 reference/fixture：`8 B magic + 24–32 B 不透明元数据 + 统计随机的 body + 0x300 处 50 B 明文 calibration 标记`。4 份独立下载的拷贝**逐字节相同**（sha256 一致），而同一批里的 `tbox-firmware.img` 每包都不同 —— 说明 VCU 文件按设计就是静态明文，不是每包加密。

`[推断]` 题面 04 要的「双 lane 64 位 Seed/Key 算法」不在这个文件里；目前唯一实物是 T-BOX 固件 `0x08000668`（双 lane、8 B 输入/8 B 输出、常量 `0x9E3779B9`/`0xA5A5A5A5`/lowbias32），已在 `04_SOLVE/fw/FINDINGS.md §5.2` 与 `04_SOLVE/fw/seedkey.py` 逆向完成。本文件里连它的一个常量都不存在。

---

## 1. 文件身份与跨包一致性

| 项 | 值 |
|---|---|
| size | 1024 B（= manifest `vcuReferenceSize`） |
| sha256 | `2f3692767f605ef72fb47e1a779f2dfaeca802b4df1e35d38f8bb66d53ce6ea7` |
| md5 | `971ab4d4327430d0b20b12a2520e93b5` |
| manifest 相关字段 | 只有 `vcuReferenceSize=1024`、`vcuRollback=2`、`vcuUpdateAddress=0x08040000`；**没有** vcu nonce / vcu sha256（对照 tbox 有 `nonce` + `tboxSha256`） |

四份拷贝逐字节一致 `[确证]`（`cmp` 0 diff，sha256 相同）：

- `work/bundle2/x/vcu-reference.bin`
- `work/bundle3/x/vcu-reference.bin`
- `03_EVIDENCE/ticket/b1/vcu-reference.bin`
- `03_EVIDENCE/tsp/bundle/extracted/vcu-reference.bin`

判据：同一批 `bundle2` 与 `bundle3` 的 `tbox-firmware.img` md5 不同（`08b853d0…` vs `933944a5…`），因为每包的 GCM nonce 不同；而 VCU 文件 md5 相同。⇒ **VCU 文件没有参与每包加密** `[确证]`。sign 组的 `04_SOLVE/sign/bundle_binding.py` 也独立记录了同一现象。

---

## 2. 字节布局图

| offset | len | 性质 | 证据 |
|---|---|---|---|
| `0x0000–0x0007` | 8 | **magic** `43 56 36 56 43 55 31 00` = `"CV6VCU1\0"` | ASCII 可读 |
| `0x0008–0x001F` | 24 | **不透明元数据（lead 说的 24 B）** `6e08e196088e346ab039d342775f4a50 bb421930333af73b` | 高熵；无字段/校验/哈希语义（§3） |
| `0x0020–0x0027` | 8 | 若把头部按 32 B 看，这是第 4 个 8 B 字段 `dd4b39df916ca101` | 同上 |
| `0x0028–0x02FF` | 728 | body 前段（随机样） | 熵 3.75–4.00/16 B（16 样本上限 4.0） |
| `0x0300–0x0331` | 50 | **明文 marker** `CALIBRATION: production steering and torque limits` | 逐字节 ASCII，无 NUL 填充 |
| `0x0332–0x03FF` | 206 | body 后段（随机样） | 同上 |

关键观察：

- `[确证]` marker 是**覆盖写入随机数据**，不是结构化字段：它后面紧跟的字节 `0x332 = a7`（非 ASCII、非填充），前后都没有 0x00/0xFF 对齐填充；长度 50 也不是任何 2 的幂/块对齐。
- `[确证]` 全文件**没有任何 ≥4 字节的 0x00 或 0xFF 连续段**（无 padding、无擦除态）。
- `[确证]` ≥4 字节可打印串共 12 条：11 条长度 4–6 且落在"随机"区（与随机期望 ≈12 条吻合），第 12 条就是 0x300 的 50 B marker。
- `[确证]` 熵：整文件 7.7897；16 B 窗口 3.50–4.00（16 样本上限 4.00）；32 B 窗口 4.44–5.00；64 B 窗口 5.08–5.84。χ²（vs 均匀 256）= 287.0（df=255，p≈0.07）。
- `[确证]` 自相关 `count(C[i]==C[i+s])` 与随机期望同量级（s=1: 3/4.0；s=16: 7/3.94；s=512: 2/2.0）。
- `[确证]` 16 B 块共 64 个，**重复块 0 个**；两半（2×512）逐字节相等仅 2/512（随机期望 2.0）。

### 2.1 头部 24/32 字节的候选字段解析

把 `0x08–0x27` 按 u32/u64、LE/BE 全解一遍（`04_SOLVE/vcuimg/evidence/01_layout.txt`）：

```
hdr32 = 6e08e196 088e346a b039d342 775f4a50 bb421930 333af73b dd4b39df 916ca101
u64 BE = 0x6e08e196088e346a, 0xb039d342775f4a50, 0xbb421930333af73b, 0xdd4b39df916ca101
u64 LE = 0x6a348e0896e1086e, 0x504a5f7742d339b0, 0x3bf73a33301942bb, 0x01a16c91df394bdd
```

逐一否掉常见语义 `[否定]`：

| 假设 | 成立则必然看到 | 实测 |
|---|---|---|
| 头部含长度/偏移/rollback/地址字段 | 1024 / 984 / 992 / 0x300 / 50 / 0x08040000 / 0x08000000 / 2 出现在 4/8 字节窗口（LE 或 BE） | **全文件 0 命中** |
| 头部 = body 的哈希 | sha256/sha1/md5/blake2b/blake2s/sha3_256 的 4/8/16/24/32 前缀或后缀命中 7 个候选区间（`0x28:`、`0x08:`、whole、`0x14:`、`0x18:`、`0x40:`、marker） | **0 命中** |
| 头部 = 校验和 | crc32/adler32/lena 的 4 B 值命中头部任一 4 B 窗口 | **0 命中** |
| 头部含时间戳 | u64 LE/BE 按 s/ms/us/ns 解释落在 1970–2100 | 无合理值 |
| 头部首 16 B 是 UUID | uuid3/uuid5(namespace, {VIN, magic, campaign, marker, …}) 命中 | **0 命中**；`0x08–0x17` 解析成 UUIDv3 仅是 1/64 巧合，`0x18–0x27` 解析版本位为 f（非法） |
| 头部是 PRNG 种子 | `random.Random(header 的 4/8 B LE/BE).randbytes(1024)` == 文件 | **0 命中** |

`[确证]` 结论：24 B（或 32 B）头部在当前证据下**不可解释**——没有长度、地址、校验、哈希、UUID、时间戳任何一种语义能通过判据。
`[推断]` 它要么是随机填充，要么是只有 VCU bootloader 才知道格式的元数据（nonce/票据/版本号之类），离线无 bootloader 无法判定。

---

## 3. 加密 / 编码假设（判据：成立则必然看到 X）

### 3.1 与 key 无关的否决：文件里有一段**明文** marker

`0x300–0x331` 的 50 个字节就是明文 ASCII（`CALIBRATION: …`）。

- 任何标准流/块密码（AES-CTR/CBC/CFB/OFB/GCM、ChaCha20、XOR-keystream）的密文在该位置都应近似均匀随机；
- 50 个字节全部落在可打印 ASCII 的概率约 `(95/256)^50 ≈ 3×10⁻²²`。

`[确证]` ⇒ **这 50 字节是明文，不是密文**。因此整文件不可能是"单一标准密码容器"（无论 key 是什么）。
这条判据与 key 无关，也是下面"已知明文攻击"不适用的原因：文件在该位置 `C == P`，不存在可与之 XOR 的密文，推出的 keystream 恒为 0（周期测试对任意 p 都"成立"，属退化结果，不能当证据）。

### 3.2 key × mode 矩阵：1437 个组合全负

key 候选（所有手里材料）：`packageKey`、`firmwareCredential`、`tboxSha256`、固件自度量 `138142b1…`、派生 KEK `0fd6e171…`、unwrap 出的 `693d2ab0…`、`vcu_sha256`、header 32 B、header 24 B、`C_DEV`、`UID16`、全零、marker/magic 的 sha256。

mode/layout 候选：

- AES-128/256 × {CTR, CBC, CFB, OFB} × IV ∈ {header 8/12/16 B、全零、manifest nonce、vcu sha 前 16/12}；
- AES-GCM × {nonce@0x08 长 8/12/16、tag 取末 16 B 或 @0x3f0、ct 取中间}；
- ChaCha20、ChaCha20-Poly1305、AES-ECB（含 0/8/0x28 三种起点偏移）；
- body 起点 ∈ {0x08, 0x14, 0x18, 0x28, 0x40, 全文件}。

判据：命中即 `S1` 明文含 marker / `S2` zlib ratio < 0.95 或熵 < 7.5 / `S3` 强可打印结构（≥16 B 串或可打印总量 ≥40 B）。

`[否定]` 实测 **1437 个候选，0 个命中 S1/S2/S3**；所有候选的 zlib ratio ≈ 1.011、熵 ≈ 7.79（等同随机）。
证据：`04_SOLVE/vcuimg/evidence/05_crypto_matrix.txt`。

（注：初版 S3 用"任意 ≥8 B 可打印串"会把 984 字节随机数据里 ~0.6 条偶然串误报成命中；已收紧为强判据后 0 命中。）

### 3.3 XOR / 常见变换：18 种全负

试过：`xor 0xFF`、bit reverse、nibble swap、`±i`、`xor i`、`xor i>>1`、`xor 4B counter`、相邻字节 XOR/SUB、整体反转、`xor header32/24 repeated`、`xor block0`、`xor next block`、`xor magic repeated`。

判据：变换后 zlib < 0.95 或出现 ≥16 B 可打印串。
`[否定]` 18 种变换的 zlib ratio 全部 ≈ 1.011（与随机对照相同）；唯一的真 ASCII 串始终是 marker 本身（以及整体反转后的它）。证据：`evidence/03_structure_hunt.txt`。

### 3.4 LSB 隐写：无

`[否定]` bit0/bit1/bit2 的打包平面 zlib ratio 都是 1.086（= 随机），无 ASCII 串。0/255 平面的 zlib 0.21 只是因为它是二值图，不是结构。

### 3.5 与双 lane hash（fw `0x08000668`）的关系：无

- 记录布局穷举：`A8|B8|C8|out8`（32 B 记录，起点 0x00–0x20 步长 8，含 B/C 互换、out 前置）、`A8|C8|out8`（24 B）、`A8|out8`（16 B），共 60+ 种布局，**0 命中**（`evidence/04_kat_hypothesis.txt`）。
- 8 B 窗口两两穷举：128 个窗口当 seed/key、5 个常量当 C，算 `hash8(seed,B,C)` 看结果是否等于另一个 8 B 窗口；共 81,920 次，**0 命中**（`evidence/09_pairwise_kat.txt`）。
- 常量字面量 **全部不存在**：`0x9E3779B9`、`0xA5A5A5A5`、`0x5A5A5A5A`、`0x7FEB352D`、`0x846CA68B`、`C_DEV=e224dd2bb23a15b8`、`A6A6A6A6A6A6A6A6`、`0x08040000`、`0x08000000`、`"CV6-TBOX-KEK"`。
- 与 T-BOX 固件明文/密文/证书/票据的 8 B 窗口重叠：**0**。

---

## 4. 是不是代码

### 4.1 压缩率（最强判据）`[否定]`

| 数据 | zlib-9 ratio | lzma ratio |
|---|---|---|
| vcu-reference.bin | **1.011** | 1.059 |
| 1024 B 随机对照 | **1.011** | 1.059 |

可执行代码（尤其 Thumb-2）通常 0.6–0.8；1.011 = 完全不可压缩 = 随机数据。若文件是代码/压缩代码/文本，必然 < 0.9。

### 4.2 Cortex-M 向量表 `[否定]`

判据：某个 2 字节对齐位置 `w0 ∈ 0x20000000–0x2000FFFF`（SP）且 `w1 ∈ 0x08000000–0x0807FFFF` 且 `w1` 为奇数（Thumb 入口）。
实测：**全文件 0 个**（200 份随机对照同样 0 个，说明此项单独偏弱，但结合 4.1 已足够）。若 1024 B 是 `0x08040000` 处的 ARM 镜像，其前 8 字节应是 SP+Reset，实测是 `"CV6VCU1\0"`。

### 4.3 反汇编 `[否定]`

| 架构 | 度量 | 实测 |
|---|---|---|
| ARM Thumb（capstone） | 解码指令数 / 字节覆盖率 | 41 条 / 8%（随机对照 median 2.9%、p95 14.8%——落在随机区间；8% 主要来自 marker 的 ASCII 被当指令） |
| ARM Thumb | `push {…,lr}` / `bl` / `ldr pc` | 0 / 0 / 1（随机量级） |
| RV32IM（capstone） | 解码指令数 | 0（首条即非法） |
| RV32IM | `addi sp,sp,-N` / `sw ra` / `ret` | 0 / 0 / 0 |

真实 Thumb-2 代码（对照：T-BOX 固件 `0x40–0x750`）有大量 `push/bl/ldr [pc]`、literal pool、函数序言；本文件一个都没有。

### 4.4 byte bigram 似然（与真实代码对比）`[否定]`

用 T-BOX 固件真实代码区 `fw[0x40:0x750]` 训练一阶 byte bigram，评分 = mean log2 P(bᵢ|bᵢ₋₁)：

| 数据 | 分数 (bits/byte) |
|---|---|
| 真实 Thumb-2 代码 | **−6.3967** |
| 固件数据/常量区 | −8.0141 |
| **vcu-reference.bin** | **−8.0014** |
| 300 份随机对照 | median −8.0165，p05 −8.0251，max −7.9973 |

本文件落在随机分布内，距真实代码 **1.60 bits/byte**。`[确证]` 其字节统计与随机不可区分、与 ARM 代码显著不同。

### 4.5 其他编码假设

- `[否定]` 不是 `python random.Random(header_seed)` 的字节流（4/8 B LE/BE 四种种子全不匹配）。
- `[否定]` 不是简单 XOR/位变换（§3.3）。
- `[否定]` 不是 ARM 代码经单字节 XOR 混淆：18 种变换后 zlib 仍 1.011。

---

## 5. 双 lane 特征搜索

判据：若文件含"双 lane 64 位"算法（题面描述），必然看到下列之一：(a) 两个相似常量块；(b) 两套并行查表；(c) `0xA5A5A5A5`/`0x9E3779B9` 字面量；(d) 8 B 进/8 B 出的函数或 KAT。

| 特征 | 实测 |
|---|---|
| (a) 两半相似 | 2×512 逐字节相等仅 **2/512**（随机期望 2.0）；16 B 重复块 **0/64** |
| (b) 并行查表 | 无重复/相似块；两半 XOR 后熵 7.555（仍随机） |
| (c) 常量 | `0xA5A5A5A5`、`0x9E3779B9`、`0x5A5A5A5A`、M1/M2、`C_DEV` **全部不存在** |
| (d) 8 B→8 B | KAT 布局 60+ 种 0 命中；两两穷举 81,920 次 0 命中 |

`[确证]` 文件**没有**双 lane 算法特征。

---

## 6. 结论与对主线的影响

### 6.1 对 lead 四个问题的直接回答

1. **布局**：见 §2。magic(8) + 24–32 B 不透明头 + 统计随机的 body + 0x300 处 50 B 明文 marker；无 padding、无校验/长度关系。
2. **换算法**：AES-CTR/CBC/CFB/OFB/GCM、ChaCha20、ChaCha20-Poly1305、ECB、XOR、18 种字节变换，共 1437+ 组合，**0 命中**。已知明文攻击**不适用**：文件在 0x300 处 `C==P`（明文），不存在对应的密文。
3. **是不是代码**：`[否定]`。压缩率 1.011（=随机）、无 Cortex-M 向量表、Thumb 覆盖率 8%（随机量级）、RV32 0 条、bigram 距真实代码 1.60 bits/byte。
4. **双 lane 特征**：`[否定]`，常量/相似块/KAT 全部为零。

### 6.2 那题面 04 的算法在哪？

`[推断]` 就在 T-BOX 固件里，只是不是"0x27 派发器"而是**原语**：

- 地址 `0x08000668`（`04_SOLVE/fw/FINDINGS.md §5.2`、`04_SOLVE/fw/seedkey.py`，有 Unicorn 仿真 + Python 复算双证）；
- 结构：`out[8] = F(A[8], B[8], C[8])`，**两个 32-bit lane**（i=0,1），每 lane `x = A[i]^B[i]^C[i]^((i+1)*GOLD)` → `lowbias32(x)` → `+ (i+1)*K5`；
- 常量：`GOLD=0x9E3779B9`、`K5=0xA5A5A5A5`、`M1=0x7FEB352D`、`M2=0x846CA68B`、`C_DEV=0xe224dd2bb23a15b8`；
- 形态正好是「**双 lane**（2×32-bit）+ **64 位**（8 B 进 8 B 出）」。

VCU 参考镜像与这个原语**没有任何关系**（常量不存在、KAT 0 命中、与固件明文/密文无 8 B 重叠）。

### 6.3 如果坚持"算法在 VCU 文件里"，需要什么前置

成立所需的最小证据链（当前都不具备）：

1. 能解开 body 的 key（当前包的 packageKey / KEK / unwrap key / 各种派生全不匹配）；
2. 能解释 0x300 的明文 marker——它说明该文件**至多是部分加密**，需要一个格式定义（哪个区间加密、哪个区间明文）和 VCU bootloader 代码；
3. 或者拿到 VCU bootloader（`0x08040000` 处的运行代码），看它如何解析 magic/头部/0x300。

`[否定]` 现有材料下可以确定：**不是 CV6-OTA-1 GCM 容器**（manifest 没有 vcu 的 nonce/sha 字段；且 marker 明文，概率论证见 §3.1）。

### 6.4 这个文件的用途（供 05–12 参考，标推断）

- `[推断]` magic `CV6VCU1\0` = VCU 更新包的识别头；`vcuUpdateAddress=0x08040000` 说明它最终被写到 VCU Flash。
- `[推断]` 0x300 的 calibration 标记是**刷写成功后的读回校验串**（flash 地址 `0x08040300`），内容随机化的 body 只是"占位 payload"，所以挑战不要求理解其内容。
- `[推断]` 后续 05–12 更可能需要的是 (a) `vcuRollback=2` 的 rollback 处理；(b) 明文长度/加密包长度/地址三元组；(c) 打开 13401 桥后的 VCU UDS 流程——而不是这个文件的字节。

---

## 7. 局限

1. 非标准/私有加密或自定义容器在没有 key/格式文档时**无法穷尽排除**；本报告只能证明"不是标准密码容器、不是代码、不含已知算法的常量与 KAT 关系"，不能证明文件内容到底是什么。
2. 反汇编与 bigram 是**证否**工具：分数落在随机区间支持"不是代码"，但不能反过来断言"一定是随机"。
3. 头部语义在缺 VCU bootloader 时不可判定；`0x300` 标记的用途是推断，没有运行证据。
4. 所有结论基于 4 份相同拷贝（同一 VCU 版本）；若后续包换了 VCU 镜像，需要重跑 `04_SOLVE/vcuimg/*.py`。

---

## 8. 复核命令

```bash
cd D:/qwb

# 布局 / 熵 / 自相关 / 头部字段 / 哈希关系
python 04_SOLVE/vcuimg/analyze_layout.py

# 代码 vs 随机（压缩率、向量表、反汇编、bigram）
python 04_SOLVE/vcuimg/code_plausibility.py
python 04_SOLVE/vcuimg/bigram_test.py

# 隐藏结构（18 种变换 + LSB + 已知明文）
python 04_SOLVE/vcuimg/structure_hunt.py

# 加密矩阵（1437 组合）
python 04_SOLVE/vcuimg/crypto_matrix.py

# KAT / 双 lane 关系（记录布局 60+ 种 + 8B 窗口两两穷举 81,920 次）
python 04_SOLVE/vcuimg/kat_test.py
```

---

## 9. 证据与脚本

| 文件 | 内容 |
|---|---|
| `04_SOLVE/vcuimg/analyze_layout.py` | 布局/熵/自相关/头部/哈希关系 |
| `04_SOLVE/vcuimg/code_plausibility.py` | 向量表 + Thumb/RV32 反汇编统计 vs 200 随机对照 |
| `04_SOLVE/vcuimg/bigram_test.py` | 真实代码 bigram 模型打分 vs 随机 |
| `04_SOLVE/vcuimg/structure_hunt.py` | 18 种变换、LSB、已知明文/周期 XOR |
| `04_SOLVE/vcuimg/crypto_matrix.py` | 1437 组 key×mode×layout |
| `04_SOLVE/vcuimg/kat_test.py` | 双 lane hash8 的 KAT 与两两穷举（均 0 命中） |
| `04_SOLVE/vcuimg/evidence/01_layout.txt` | 布局分析原始输出 |
| `04_SOLVE/vcuimg/evidence/02_code_plausibility.txt` | 反汇编统计原始输出 |
| `04_SOLVE/vcuimg/evidence/03_structure_hunt.txt` | 变换/隐写原始输出 |
| `04_SOLVE/vcuimg/evidence/04_kat_hypothesis.txt` | 记录布局 KAT 穷举（0 命中） |
| `04_SOLVE/vcuimg/evidence/05_crypto_matrix.txt` | 加密矩阵（0/1437） |
| `04_SOLVE/vcuimg/evidence/06_bigram_test.txt` | bigram 打分 |
| `04_SOLVE/vcuimg/evidence/07_header_hash_tests.txt` | 头部哈希/PRNG 测试 |
| `04_SOLVE/vcuimg/evidence/08_header_checksum_tests.txt` | 头部校验和/长度测试 |
| `04_SOLVE/vcuimg/evidence/09_pairwise_kat.txt` | 8 B 窗口两两 hash8 穷举（0 命中） |
| `04_SOLVE/vcuimg/evidence/10_overlap_with_bundle.txt` | 与固件/证书/票据的 8 B 重叠（0） |
| `04_SOLVE/vcuimg/evidence/11_uuid_timestamp_tests.txt` | UUID/时间戳解释测试 |

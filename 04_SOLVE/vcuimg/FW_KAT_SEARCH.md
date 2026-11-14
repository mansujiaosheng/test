# T-BOX 固件 KAT / 测试向量搜索 · 结果

**日期**：2026-11-14 10:53–11:00 CST
**对象**：`work/bundle2/tbox-firmware.dec.bin`（16384 B，sha256 `88b09d09…7229`，载入基址 `0x08000000`）
**目的**：给 `0x08000668` 双 lane hash 找**内建 KAT / 测试向量**，或找「第二套 lane 常量 C」。
**结论**：**两条都空**。固件里只有原语，没有 KAT，也没有第二个 C。已按 lead 指示把 `04_SOLVE/fw/seedkey.py` 的 `calc_key` 改成「32 位双 lane 最自然解释」的候选实现，并加了 `--verify` 反查工具。

---

## 1. 原语（复述，来自 fw FINDINGS §5.2，已由 Unicorn + Python 双证）

```
hash8(A[8], B[8], C[8]) -> out[8]
for i in 0, 1:                    # 两个 32-bit lane
    x   = A_i ^ B_i ^ C_i ^ ((i+1)*GOLD)
    y   = lowbias32(x)             # M1/M2 乘子
    out_i = (y + (i+1)*K5) mod 2^32
out = out_0 || out_1               # 小端
```

反汇编里只出现这些常量（`evidence/13_hash8_disasm_literals.txt`）：

| literal 地址 | 值 | 用途 |
|---|---|---|
| `0x080006ec` | `0x08002020` | **C 指针（唯一一个）** |
| `0x080006f0` | `0x9E3779B9` | GOLD |
| `0x080006f4` | `0x7FEB352D` | M1 |
| `0x080006f8` | `0x846CA68B` | M2 |
| 立即数 `0x0800067c` | `#-0x5a5a5a5b` | K5 = `0xA5A5A5A5` |

---

## 2. KAT 搜索（全空）

判据：若固件含 KAT，下列任一布局必然至少命中 1 次（`hash8(A,B,C) == out`）。

| # | 搜索空间 | 次数 | 命中 |
|---|---|---|---|
| L1 | 24 B `A|B|out`，**所有字节偏移**，C=C_DEV | 16,361 | **0** |
| L1b | 24 B `A|B|out`，8 B 对齐记录 × **2,051 个 C 候选**（含全镜像 8 B 对齐窗口） | 4,196,346 | **0** |
| L2 | 16 B `A|out`，B∈{0,C_DEV,A,UID0} × C∈{C_DEV,0,UID0} | 196,428 | **0** |
| L3 | 32 B `A|B|C|out`（C 在记录里），所有字节偏移 | 16,353 | **0** |
| L4 | 24 B `out|A|B`（out 前置） | 16,361 | **0** |
| L5 | 24 B `A|B|out`，out 字节序反转 | 16,361 | **0** |

合计 **4,458,210** 次 hash8，**0 命中**。证据：`evidence/12_fw_kat_search.txt`。

补充检查：

- `0x08002000–0x08003fff` 里 **非 0x00/0xFF 且不在已知区间**（UID16@0x2000、C_DEV@0x2020、wrapped@0x2040）的字节 = **0**。⇒ 那 512 字节（以及到 `0x3fff`）没有藏表，只有擦除态填充。
- 固件自身唯一 hash8 调用点（Reset handler `0x08000770`）传入的是 **A=B=0**：

```asm
08000758  movs r3, #0
0800075c  strd r3, r3, [sp]      ; sp[0:8]   = 0   -> A
08000760  strd r3, r3, [sp,#8]   ; sp[8:16]  = 0   -> B
08000764  bl   measure()
08000768  cbz  r0, wfi
0800076a  add  r2, sp, #0x10     ; out
0800076c  add  r1, sp, #8        ; B = sp+8
0800076e  mov  r0, sp            ; A = sp
08000770  bl   hash8             ; hash8(0,0,C_DEV) = 77be1f61090854c7
08000774  wfi                    ; 结果写 sp+0x10 后再没人读 -> 丢弃
```

⇒ 这不是 KAT（没有与任何常量比对，也没有被使用），只是「零上下文调用」。**固件没有把任何 (A,B,out) 三元组存下来**。

- 反查：`hash8(0,0,C_DEV)=77be1f61090854c7` 与 fw 组 selftest 的输出 `e21faa054c4f8037` **都不在镜像里**（LE/反转/hex ASCII 四种形态全 0 命中，`evidence/16_callers_and_output_search.txt`）。
- 全镜像 BL 目标 = `0x08000668` 的调用点**只有 1 个**：`0x08000770`（`evidence/17_callers_full.txt`）。

---

## 3. 「第二套 lane 常量 C」搜索（不存在）

判据：若存在第二套 C，必然看到以下之一：第二个 `ldr` literal 指向另一块 8 B 常量、或数据区另有 8 B 非常量、或调用点有分支选 C。

实测：

1. **反汇编**：hash8 里 C 指针只有一条 literal `0x080006ec -> 0x08002020`；没有条件分支、没有第二个 C 指针（`evidence/13`）。
2. **全镜像 flash 指针扫描**：所有 4 B 字里落在 `0x08000000–0x08004000` 的共 **24 个**——15 个向量表项（`0x08000755`）+ 9 个数据指针：SHA K 表 `0x080009a0`、AES S-box `0x080008a0`、SHA IV `0x08000778`、AES 逆 S-box `0x08000798`、AIV `0x08000898`、**C_DEV `0x08002020`**、`"CV6-TBOX-KEK" 0x08000aa0`、UID16 `0x08002000`、wrapped blob `0x08002040`。**没有第二个 8 B 常量指针**。
3. **数据区**：`0x2000–0x3fff` 的 8 B 非常量只有 UID16（2 个 8 B）、C_DEV（1 个）、wrapped blob（5 个），共 8 个；无其他常量。
4. **调用点**：全镜像只有 reset handler 一处调用，且无 lane 参数传递（`hash8(A,B,out)` 只有 3 个寄存器参数）。

⇒ `[确证]` 「双 lane」不是两套 C 常量，而是 hash8 内部 `i=0,1` 两个 32-bit lane 各自用 `(i+1)*GOLD` 与 `(i+1)*K5`。

---

## 4. 一个重要代数性质：hash8 只依赖 A⊕B

公式里 A 与 B 只以 `A_i ^ B_i` 出现，所以：

- `hash8(A,B,C) == hash8(B,A,C)`（数值验证通过）⇒ **「哪个是 seed、哪个是上下文」对输出没有影响**；
- `hash8(x, x, C) == hash8(0, 0, C) == 77be1f61090854c7` 对任意 x 成立 ⇒ **「self-mix」（B=seed）是退化映射，输出与 seed 无关**，不可能是题目的 Seed→Key；
- 因此有效映射必然是 `key = hash8(seed, K, C_DEV) = F(seed ⊕ K, C_DEV)`，其中 K 是某个**固定的 8 B 上下文**（0 / UID / 票据派生 / 等），且 hash8 对 seed 是双射。

这条性质把候选空间从「(A,B) 二元组」压缩到「一个 8 B 上下文 K」，并且可以直接排除 B=seed 这一类假设。

---

## 5. 对 `seedkey.py` 的修改（候选实现 + 反查工具）

已改（`04_SOLVE/fw/seedkey.py`，`--selftest` 全 PASS）：

1. **docstring**：新增本轮确证（无 KAT、单 C、A/B 对称、固件零上下文调用），并把「双 lane 是内部结构」写清楚。
2. **`calc_key(seed, lane=0, ticket=None)`** 改为最自然解释：
   - `A = seed`（8 B 归一；非 8 B 用 SHA-256(seed)[:8]）
   - `B = 0`（lane 0，复刻固件 reset handler）或 `B = SHA-256(ticket)[:8]`（lane 1，票据绑定候选）
   - `C = C_DEV`
   - 明确标注「候选，固件无 0x27/KAT 证据」。
3. **`context_candidates()` + `verify()`**：拿到真实 `(seed, key)` 后逐个候选反查：

```bash
python 04_SOLVE/fw/seedkey.py --verify --seed <hex> --key <hex> [--ticket <hex>]
# 逐个打印 B 候选（zero / seed / C_DEV / UID16[0:8] / UID16[8:16] /
#   sha256(ticket) 切片 / ticket 各 8B 切片）算出的 key，标出 <== MATCH
```

4. **`--selftest`** 新增：
   - `[PASS] firmware reset-handler vector hash8(0,0,C_DEV) = 77be1f61090854c7`
   - `[PASS] hash8(A,B,C) == hash8(B,A,C)`
   - `[PASS] calc_key lane 0/1` 契约

---

## 6. 结论与下一步

- `[确证]` 固件**只有原语，没有 KAT、没有第二套 C**。想从固件反推 A/B 的业务语义是不可能的（reset handler 用的是 0/0，结果被丢弃）。
- `[确证]` hash8 对 seed 是双射且只依赖 `seed ⊕ K`；`K` 是固定 8 B 上下文。
- **下一步（等 lead 真机拿到 seed）**：把真实 `(seed, key)` 喂给
  `python 04_SOLVE/fw/seedkey.py --verify --seed <hex> --key <hex>`
  —— 若命中，直接确定 K；若全部不中，说明 0x1220 的 0x27 用的是**另一套算法**（不是 0x08000668），应回退到「在 0x1220 附近找真正派发器」的路线。

证据索引：`04_SOLVE/vcuimg/evidence/12_fw_kat_search.txt`、`13_hash8_disasm_literals.txt`、`14_reset_handler_disasm.txt`、`15_hash8_usage_and_vectors.txt`、`16_callers_and_output_search.txt`、`17_callers_full.txt`；脚本 `04_SOLVE/vcuimg/fw_kat_search.py`。

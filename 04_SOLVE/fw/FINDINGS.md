# T-BOX 固件逆向 — FINDINGS（任务 02 后半段）

工作根 `D:\qwb`。只读分析，未改动靶机与固件。
镜像：`work/bundle2/tbox-firmware.dec.bin`（16384 B，sha256 `88b09d09edbf2951f7a111a51608e99a1bb28a27e653c169f4bf6ddd8c537229`，与 manifest.tboxSha256 匹配）
载入基址 `0x08000000`，ARMv7-M Thumb-2，向量表 SP=`0x20010000`，Reset=`0x08000755`。

**本文所有结论的判据分三级，逐条标注：**
- `[确证]` — 有反汇编 + 仿真逐指令复现，或 Python 独立复算逐字节吻合
- `[推断]` — 由确证事实推得的语义解释，无直接执行证据
- `[否定]` — 已穷尽搜索且明确未命中

---

## 0. 交付判据对照

| 任务要求 | 状态 | 位置 |
|---|---|---|
| 1) AES-256-GCM 解密流程已确认 | 前半段完成，本文引用不复做 | 第 1 节 |
| 2) SoC 绑定测量（地址+反汇编+常量+解读） | `[确证]` | 第 3 节 |
| 3) RFC 3394 密钥包装（KEK/blob/unwrap 结果） | `[确证]` | 第 4 节 |
| 附) SecurityAccess Seed/Key 双 lane | `[否定]` 固件内不存在；给出候选原语 | 第 5 节 |
| 【lead 追加】unwrap 出的密钥去哪了 | `[确证]` 从不被读取 | 第 6 节 |
| 【lead 追加】票据 tag 能否本地验证 | `[否定]` 103k 候选全未命中 | 第 7 节 |

---

## 1. 镜像总览

### 1.1 布局 `[确证]`

| 范围 | 内容 |
|---|---|
| `0x00000-0x0003f` | 向量表（16 项，除 SP 外全部指向 `0x08000755`） |
| `0x00040-0x0074f` | 代码（密码原语） |
| `0x00748-0x00753` | literal pool：`0x08000aa0` / `0x08002000` / `0x08002040` |
| `0x00754-0x00777` | Reset handler |
| `0x00778-0x00797` | SHA-256 IV（32 B） |
| `0x00798-0x00897` | AES 逆 S-box（256 B） |
| `0x00898-0x0089f` | `a6 a6 a6 a6 a6 a6 a6 a6` = RFC 3394 标准 AIV |
| `0x008a0-0x0099f` | AES 正 S-box（256 B） |
| `0x009a0-0x00a9f` | SHA-256 K 常量表（256 B） |
| `0x00aa0-0x00aab` | 字符串 `"CV6-TBOX-KEK"` |
| `0x00aac-0x00bff` | 全 0 填充 |
| `0x00c00-0x01fff` | **全 0**（熵 0.00） |
| `0x02000-0x0200f` | 16 B 设备身份 / UID |
| `0x02010-0x0201f` | 全 0 |
| `0x02020-0x02027` | 8 B 常量（0x668 的 `C[]`） |
| `0x02040-0x02067` | **40 B RFC 3394 wrapped blob** |
| `0x02068-0x021ff` | `0xff` 填充 |
| `0x02200-0x03fff` | 全 0 |

关键判据：`[确证]` 逐 512 B 熵剖面，`0x0c00` 之后除 `0x2000`/`0x2040` 两处外熵为 0.00
→ **镜像真实内容只有 0x0000–0x0bff 约 3 KB，其余是擦除态填充（0x00 / 0xff）**。

### 1.2 函数清单 `[确证]`

整镜像**只有 9 个函数**（`push {…,lr}` 扫描 + 全部 `bl` 目标交叉验证）：

| 虚拟地址 | 作用 |
|---|---|
| `0x08000040` | SHA-256 压缩函数（64 轮，K 表 @`0x080009a0`） |
| `0x08000164` | 逐字节 S-box 映射（表 @`0x080008a0`） |
| `0x0800018c` | AES AddRoundKey |
| `0x080001c0` | GF(2⁸) 乘法（poly 0x11b） |
| `0x080001e2` | memcpy |
| `0x080001f6` | memset |
| `0x08000204` | SHA-256(data, len, out32)，IV @`0x08000778` |
| `0x080002dc` | **RFC 3394 密钥 unwrap**（AES-256，逆 S-box @`0x08000798`） |
| `0x08000664` | 取 u32（`ldr r0,[r0]; bx lr`） |
| `0x08000668` | 8 字节 keyed hash（lowbias32 族），见第 5 节 |
| `0x080006fc` | **`measure()`** 派生 KEK + unwrap + 校验 |
| `0x08000754` | Reset（唯一入口） |

**`[否定]` 镜像内没有任何 UDS / 0x27 / 会话 / CAN / ISO-TP / 票据校验代码。**
全部 `bl` 目标闭合在上述 9 个地址内（另有 3 个垃圾目标 `0x0745b298`/`0x08381f56`/`0x089e59b0`/`0x08c48214`，来自数据区被误反汇编，非真实调用）。

---

## 2. 交付项 1：AES-256-GCM 解密流程（引用，不复做）

来自 `work/BRIEF_R2.md`，前半段已完成并经哈希校验：
```
格式 CV6-OTA-1：img = nonce(12) || ciphertext(16384) || tag(16)，共 16412 B
key = bytes.fromhex(packageKey)            # 32 B AES-256
AESGCM(key).decrypt(nonce, img[12:16384+12] + img[-16:], None) -> 16384 B
sha256(明文) == manifest.tboxSha256 ✅ 已匹配
```
本报告不重复该流程；注意它与本固件**运行时**的密码学是两套独立机制（前者是 OTA 传输层，后者是设备内度量/解封）。

---

## 3. 交付项 2：SoC 绑定测量 `[确证]`

### 3.1 函数 `measure()` @ `0x080006fc`

反汇编（原始字节见 `03_EVIDENCE/fw/disasm_0x40_0xc00.txt`）：

```asm
080006fc  push {r4, lr}
080006fe  sub  sp, #0x80
08000700  mov  r4, r0                 ; r4 = out（调用方缓冲，40 B）
08000702  add  r2, sp, #4             ; r2 = &digest[0..31]
08000704  mov.w r1, #0x2000           ; len  = 0x2000 = 8192
08000708  mov.w r0, #0x8000000        ; addr = 0x08000000  ← FLASH 基址
0800070c  bl   0x8000204              ; SHA-256(0x08000000, 8192, digest)
08000710  add  r0, sp, #0x44
08000712  ldr  r1, [pc, #0x34]        ; lit @0x08000748 -> 0x08000aa0 "CV6-TBOX-KEK"
08000714  movs r2, #0xc               ; 12 B
08000716  bl   0x80001e2              ; memcpy(&buf[0],  label, 12)
0800071a  add  r0, sp, #0x50
0800071c  ldr  r1, [pc, #0x2c]        ; lit @0x0800074c -> 0x08002000
0800071e  movs r2, #0x10              ; 16 B
08000720  bl   0x80001e2              ; memcpy(&buf[12], UID16, 16)
08000724  add  r1, sp, #4
08000726  add  r0, sp, #0x60
08000728  movs r2, #0x20              ; 32 B
0800072a  bl   0x80001e2              ; memcpy(&buf[28], digest, 32)
0800072e  add  r2, sp, #0x24          ; out = &derived[0..31]
08000730  add  r0, sp, #0x44          ; in  = &buf[0]        (60 B = 12+16+32)
08000732  movs r1, #0x3c              ; len = 0x3c = 60
08000734  bl   0x8000204              ; SHA-256(buf, 60, derived)   ← 派生 KEK
08000738  ldr  r1, [pc, #0x14]        ; lit @0x08000750 -> 0x08002040（wrapped blob）
0800073a  mov  r3, r4                 ; out
0800073c  movs r2, #0x28              ; len = 40
0800073e  add  r0, sp, #0x24          ; key = derived
08000740  bl   0x80002dc              ; unwrap(key=derived, blob=0x08002040, 40, out)
08000744  add  sp, #0x80
08000746  pop  {r4, pc}               ; 返回 unwrap 的 1/0
```

仿真实测（Unicorn，`04_SOLVE/fw/emu.py`）栈帧逐字段核对：

| 栈槽 | 内容 | 判据 |
|---|---|---|
| `sp+0x00..1f` | `138142b18d663291fc3febb15e004f57f76f10dee82f158a30b42ad7468ba085` | `[确证]` = `sha256(fw[0:0x2000])`，与 hashlib 一致 |
| `sp+0x20..3f` | `0fd6e171919fdc1a6afcee7f81a6599c67a136fc0f57e8f210fb2acf9c92b318` | `[确证]` 派生 KEK |
| `sp+0x40..4b` | `"CV6-TBOX-KEK"` | `[确证]` |
| `sp+0x50..5f` | `d31ad1cae3ffe1aedbf00f0d7fec3396` | `[确证]` = `fw[0x2000:0x2010]` |
| `sp+0x60..7f` | `138142b1…8ba085` | `[确证]` |
| `sp+0x24..43` | 32 B 派生结果 | `[确证]` |

### 3.2 KDF 公式 `[确证]`

```python
digest = SHA256(firmware_flash[0x0000:0x2000])        # 自度量整镜像
buf    = b"CV6-TBOX-KEK" + UID16 + digest             # 12 + 16 + 32 = 60 B
KEK    = SHA256(buf)                                  # 32 B
```
纯 Python 复算与仿真栈帧**逐字节一致** `[确证]`：
```
digest = 138142b18d663291fc3febb15e004f57f76f10dee82f158a30b42ad7468ba085
UID16  = d31ad1cae3ffe1aedbf00f0d7fec3396        @0x08002000
KEK    = 0fd6e171919fdc1a6afcee7f81a6599c67a136fc0f57e8f210fb2acf9c92b318
```

### 3.3 读的是哪个地址 / 期望值 / 失败分支

- **设备身份来源**：`0x08002000` 的 16 字节 `d31ad1cae3ffe1aedbf00f0d7fec3396`。这是**烧录在 flash 里的预置值**，作为设备身份 salt。
- **`[否定]` 没有读 UID/Device-ID 寄存器**：全镜像搜索 `0x1FFF7A10` / `0x1FFF7590` / `0x08FFF800`（STM32 类 UID 地址），**0 命中**；也没有任何 `0x40000000`–`0x5FFFFFFF` 外设区间访问。镜像内唯一的绝对地址常量就是 `0x08000000`（flash 基址）与 `0x08002000` / `0x08002020` / `0x08002040` 三个数据块。
- **期望值**：不是「与常量比较」形态，而是 **RFC 3394 unwrap 的完整性校验** —— 末轮 A 必须等于 `0xA6A6A6A6A6A6A6A6`（常量位于 `0x08000898`）。见第 4 节。
- **失败分支 `[确证]`**：Reset handler
  ```asm
  08000764  bl   0x80006fc        ; measure()
  08000768  cbz  r0, #0x8000774   ; 返回 0 -> 跳过
  0800076a  add  r2, sp, #0x10
  0800076c  add  r1, sp, #8
  0800076e  mov  r0, sp
  08000770  bl   0x8000668        ; 成功路径：8 字节 hash，结果写 sp+0x10
  08000774  wfi                   ; ← 两条路径都汇合到这里
  08000776  b    #0x8000774       ; 死循环
  ```
  **失败 = `wfi` + 无条件回跳的死循环挂死**，不是返回错误码，也不是复位重试。
  `[推断]` 这是典型的 fail-closed 反篡改：度量不过 → 固件静默挂起，不给任何可观测的差异。

### 3.4 解读

`measure()` 把三样东西绑成一个 32 字节密钥：
1. **固件自身全部内容的 SHA-256**（`0x08000000` 起 0x2000 字节）→ 篡改任一字节即改变 KEK
2. **设备身份 16 字节**（`0x08002000`）→ 换芯片即改变 KEK
3. **固定标签 `"CV6-TBOX-KEK"`** → 域分离

然后该 KEK 用于解开 `0x08002040` 的 wrapped blob。**所以「SoC 绑定」是通过 KDF 的 salt/info 实现，而不是寄存器比对** —— 题目描述的「与常量比较」形态在本固件不成立，实际形态是「绑进 KDF 输入 + RFC 3394 AIV 完整性校验」。

---

## 4. 交付项 3：RFC 3394 密钥包装 `[确证]`

### 4.1 字符串引用点

`"CV6-TBOX-KEK"` @`0x08000aa0`，**全镜像唯一引用 = literal pool `0x08000748`**（`[确证]`：搜遍 4 字节小端 `a0 0a 00 08` 只有 `0x748` 一处）。
它被 `0x08000712` 的 `ldr r1,[pc,#0x34]` 取用 → 即 KDF 的标签。**它本身不是 KEK，是 KDF 的域分离标签。**

### 4.2 KEK / blob / 调用点

| 项 | 值 |
|---|---|
| KDF 标签 | `b"CV6-TBOX-KEK"` @`0x08000aa0` |
| **KEK（AES-256 wrapping key）** | `0fd6e171919fdc1a6afcee7f81a6599c67a136fc0f57e8f210fb2acf9c92b318` — **运行期派生，不落盘** |
| **wrapped blob** | @`0x08002040`，40 B = `38c0627019a7a0e6` ‖ `d76af7acc3a273c5b0584a31c280eb2b8e7f70acfb1ac91948a15cbd48856509` |
| wrap/unwrap 调用点 | `0x080002dc`（函数体），唯一调用者 `0x08000740`（`measure()` 内）；签名 `(r0=key, r1=blob, r2=len, r3=out)` |
| AIV 校验常量 | `0xA6A6A6A6A6A6A6A6` @`0x08000898`，比较点 `0x08000620`–`0x08000642` |

`0x080002dc` 结构 `[确证]`（反汇编 + 仿真）：
- `0x080002e0`: `cmp r2,#0x17 / bls` + `ands r3,r2,#7 / bne` → **要求 len ≥ 24 且 len % 8 == 0**
- `0x080002fc`–`0x08000308`: 逐 u32 `rev` 读 32 B 密钥 → 标准 AES-256 key schedule（`[确证]` 与 Python 标准展开逐字吻合，仅字内字节序不同）
- `0x08000312`–`0x08000354`: 52 轮 key expansion，`w[i] = w[i-8] ^ SubWord(RotWord(w[i-1])) ^ rcon`，rcon 由 GF xtime 递推
- `0x0800038c`–`0x08000606`: 6×4 = **24 轮 unwrap 主循环**，计数器 t = 24 → 1
- `0x080003ee`: `AddRoundKey(state, rk, round=14)`；`0x080005d0`: `round=0`；中间 13 轮用**逆** S-box @`0x08000798` → 即 AES **解密**方向，符合 RFC 3394 unwrap
- `0x08000620`–`0x08000642`: 8 字节 AIV 比对，`clz r0,r0 / lsr r0,#5` → 返回 1（全等）/0

### 4.3 unwrap 实测（用 `cryptography`）

`[确证]` 三重交叉验证：

```
输入：
  key        = 0fd6e171919fdc1a6afcee7f81a6599c67a136fc0f57e8f210fb2acf9c92b318
  wrapped    = 38c0627019a7a0e6d76af7acc3a273c5b0584a31c280eb2b8e7f70acfb1ac91948a15cbd48856509   (40 B, @0x08002040)

aes_key_unwrap(key, wrapped)
  -> 693d2ab06a2fe1a6e1ada23ac8bbb08ec3a8ffbbc90015ddeff28e721c9f693d   (32 B)
```

验证链：
1. `[确证]` Python `aes_key_unwrap` 输出 = 仿真 `out[0:32]`，**逐字节一致**
2. `[确证]` `aes_key_wrap(key, 上述 32 B) == 0x08002040 处原始 40 字节` —— **完美 round-trip**
3. `[确证]` 用 Python 复现 unwrap 主循环，得到每轮 A 序列
   `d4a340c2…, f650038d…, ebf92c00…, 164d13c9…, 0e0a4564…, a6a6a6a6a6a6a6a6`
   与仿真 `postloop_A` 六次快照**逐轮一致**，末轮收敛到标准 AIV `0xA6A6A6A6A6A6A6A6`
4. `[确证]` 仿真 `measure()` 返回 **1**（校验通过）

**关键理解修正**：blob 的 40 字节是**完整 RFC 3394 wrap 输出** = `wrapped-A(8 B) ‖ wrapped-key(32 B)`。
`0x08002040` 前 8 字节是 wrapped-A **不是** IV；unwrap 后校验的是标准 AIV。
（我最初把 unwrap 输入只取 32 B 导致 `InvalidUnwrap`，取全 40 B 即通过——记录在此以免后人重踩。）

### 4.4 它保护的是什么

`[确证]` unwrap 出的 32 字节 = `693d2ab06a2fe1a6e1ada23ac8bbb08ec3a8ffbbc90015ddeff28e721c9f693d`，**长度正好等于 AES-256 密钥**。

`[否定]` 该值：
- 不等于 `packageKey`（OTA GCM 密钥），也不等于 `firmwareCredential`
- 不出现在 `vcu-reference.bin` / `tbox-firmware.img` / 解密后固件中
- 用它（32/16 B 两种切法）AES 解密 `vcu-reference.bin` 无可读输出

`[推断]` 它是一把**设备内密钥**（密文形态随镜像分发，明文只在设备上、且只在度量通过后才解出）。语义上最可能是 T-BOX 用于上行/OTA 签名或 SecOC 的对称密钥；但**本固件不消费它**（见第 6 节），所以无法从本镜像确定其用途。

---

## 5. 任务 04 依赖：SecurityAccess Seed/Key

### 5.1 `[否定]` 固件内不存在 0x27 实现

如 1.2 节，整镜像 9 个函数全是密码原语，无任何 UDS/会话/子功能派发代码。
**「双 lane Seed/Key」不在这份 T-BOX 固件里。** 固件的全部职责是「度量 + 解封 + 挂起」。

### 5.2 固件内唯一的 key 派生原语 `0x08000668` `[确证]`

反汇编关键行：
```asm
08000668  push.w {r3,r4,r5,r6,r7,r8,sb,sl,fp,lr}
0800066c  ldr.w  fp, [pc, #0x7c]     ; lit @0x080006ec -> 0x08002020  (C 数组)
08000670  ldr.w  r8, [pc, #0x7c]     ; lit @0x080006f0 -> 0x9e3779b9  (golden ratio)
08000674  ldr.w  sl, [pc, #0x7c]     ; lit @0x080006f4 -> 0x7feb352d
0800067c  mov.w  r7, #-0x5a5a5a5b    ; r7 = 0xA5A5A5A5
08000680  add.w  r0, r6, r4, lsl #2  ; loop i = 0,1
08000684  bl     0x8000664           ; A[i]
08000692  bl     0x8000664           ; B[i]
0800069c  bl     0x8000664           ; C[i]
080006a0  eors   r3, r5              ; x = A[i]^B[i]^C[i]
080006a4  mla    r0, r4, r8, r8      ; (i+1)*GOLD
080006aa  eor.w  r3, r3, r3, lsr #16 ; lowbias32 开始
080006b0  mul    r3, sl, r3          ; * 0x7feb352d
080006b4  eor.w  r3, r3, r3, lsr #15
080006b8  muls   r3, r0, r3          ; * 0x846ca68b  (lit @0x080006f8)
080006be  eor.w  r3, r3, r3, lsr #16
080006c2  mla    r4, r4, r7, r7      ; (i+1)*0xA5A5A5A5
080006c6  add    r4, r3
080006ca  strb   r4, [r2]            ; 小端存 8 字节
```

算法（`[确证]` Python 复算与仿真**逐字节吻合**，自测向量见 `04_SOLVE/fw/seedkey.py --selftest`）：
```
GOLD=0x9E3779B9  M1=0x7FEB352D  M2=0x846CA68B  K5=0xA5A5A5A5
C[] = 0x08002020 的 8 字节 e224dd2bb23a15b8
for i in 0,1:
    x = A[i] ^ B[i] ^ C[i] ^ ((i+1)*GOLD)
    x ^= x>>16; x *= M1; x ^= x>>15; x *= M2; x ^= x>>16     # 标准 lowbias32
    out_word[i] = x + (i+1)*K5
out = 小端两字 = 8 字节
```
自测向量：`A=1122334455667788, B=deadbeefcafebabe` → `e21faa054c4f8037`（仿真与 Python 一致）。

### 5.3 lane 分析 `[否定]` + `[推断]`

- `[确证]` `0x08000668` **没有任何 lane 分支**：循环变量 i 只有 0/1 两次迭代，无外部输入选择，无第二套常量表。
- `[确证]` 它**只在 Reset 成功路径被调用一次**（`0x08000770`），且入参是**常量**：`A = sp[0:8] = 0`、`B = sp[8:16] = 0`（`0x0800075c`/`0x08000760` 的 `strd r3,r3` 清零）、`C = 0x08002020`。结果写 `sp+0x10` 后即 `wfi`。
- `[推断]` 它形态上确实是「(seed, lane-const) → key」的 keyed hash：`0xA5A5A5A5` 是 UDS SecurityAccess 的经典常量（反汇编里就是 `mov.w r7,#-0x5a5a5a5b`），golden ratio 常用于 seed 混淆。但**没有 0x27 派发器、没有 lane 选择、入参还是常量**，所以它**不是可用的 0x27 算法**。

### 5.4 交付物

`04_SOLVE/fw/seedkey.py`，按任务要求签名：
```python
calc_key(seed: bytes, lane: int, ticket: bytes | None = None) -> bytes
```
- `hash8(a, b, c)` — **确证**的原语，逐字节复现固件
- `calc_key(...)` — 候选包装。lane 常量用固件中唯一一对 UDS 常量族 `0x5A5A5A5A`(lane0) / `0xA5A5A5A5`(lane1) 占位；`ticket` 参数**保留但不使用**（固件不消费票据）。文件头已明确标注哪些是确证、哪些是候选。
- `python seedkey.py --selftest` → 全 PASS（4 项）

**lane0/lane1 差异：固件中无差异，本实现按占位常量给出差异，属候选口径，未经真值验证。**

---

## 6. 【lead 追加】unwrap 出的密钥去哪了 `[确证]`

**结论：32 字节（不是 24 字节 —— 我第一封消息里的「24 字节」是错的，取全 40 B blob 后是 32 B），写入调用方缓冲后从不被任何代码读取。**

### 6.1 存储位置

调用链：`Reset` @`0x0800075a` 令 `r0 = sp+0x18` → `measure()` 的 `out` → `0x080002dc` 把 unwrap 结果写到这里。
Reset 栈帧：`sp = 0x20010000 - 4 - 0x3c = 0x2000ffc0`，故 `out = 0x2000ffd8`（40 B 范围 `0x2000ffd8-0x2000ffff`）。

仿真读出该缓冲最终内容 `[确证]`：
```
0x2000ffd8: 693d2ab06a2fe1a6 e1ada23ac8bbb08e c3a8ffbbc90015dd eff28e721c9f693d 0000000000000000
```
前 32 B 就是 unwrap 结果，后 8 B 为 0，与第 4.3 节 Python `aes_key_unwrap` 输出**逐字节一致**。

### 6.2 是否被读 `[确证]` 双重判据

**判据 A（静态，最硬）**：成功路径 `0x08000770 bl 0x8000668` 返回后，**镜像内剩余指令只有两条**：
```asm
08000774  wfi          ; 30 bf
08000776  b #0x8000774 ; fd e7
```
从 `0x774` 起是死循环，**不存在任何后续代码**，因此不可能有人消费该缓冲。

**判据 B（动态）**：Unicorn 挂 `UC_HOOK_MEM_READ` 监视 `0x2000ffd8-0x2000ffff`：
- 读写事件中，**唯一**触碰该区域的读指令是 `0x080001ec`（`memcpy` 内层 `ldrb r3,[r1],#1`），且这些读是通用拷贝循环的源读取，**不是语义消费**
- `measure()` 返回后到 `wfi` 之间**零次**对该区域的读

### 6.3 语义解读 `[推断]`

- **被消费的只有 1 比特**：`measure()` 的 1/0 返回值，经 `0x08000768 cbz` 分流。
- 两条路径都终止于 `wfi` 死循环。差别仅是成功路径多做一次 `hash8`（结果同样丢弃）。
- 所以本固件是**纯自检/证明（attestation stub）**：验证「镜像未被篡改 + 设备身份正确 + 密钥 blob 完整」，然后挂起。
- 真实产品里这一步之后应当有「把解出的密钥交给协议栈/OTA 验签」的代码，**本镜像里被裁剪掉了**。`[推断]` 这解释了为什么 blob 能在设备上解开、却找不到任何消费者。

### 6.4 「双 lane」判据对齐 `[确证]`

32 B 的可能切法：
| 切法 | 结果 |
|---|---|
| 4 × 8 B | `693d2ab06a2fe1a6` / `e1ada23ac8bbb08e` / `c3a8ffbbc90015dd` / `eff28e721c9f693d` |
| 2 × 16 B | `693d2ab06a2fe1a6e1ada23ac8bbb08e` / `c3a8ffbbc90015ddeff28e721c9f693d` |
| 1 × AES-256 key | `693d2ab0…1c9f693d` |

**不是 24 = 2×8+8。** 32 字节最自然的读法是**单把 AES-256 密钥**；若按「双 lane」解释则是 **2×16 B 两把 AES-128 lane key**。
`[推断]` 后者与「双 lane」题面吻合度不低，但：**固件里没有任何代码读取这 32 字节**（6.2），所以**无法从本镜像证实任何一种切法**。这是候选解释，不是确证结论。

**给 04 的直接建议**：不要再等固件里的 seedkey。本固件只证明「密钥按固件哈希 + 设备 UID 派生并成功解封」，它不提供任何 UDS 能力。

---

## 7. 【lead 追加】票据 tag 能否本地验证 `[否定]`

### 7.1 样本

两份真实票据（`03_EVIDENCE/ticket/0203_ticket_sample.json` + `work/ticket_fresh.json`）：
```
#1 nonce=dc8fad542b164df4aaa9913e66baac42 exp=000000006af7c7a6 tag=2c0950f5ab55f983bbd690b175827070
#2 nonce=1b7cebd023f9b4c31279c330d3ed7e31 exp=000000006af7cb5d tag=0341afd25f89dc4add1229961f36486d
```

### 7.2 暴力匹配 `[否定]`

脚本 `04_SOLVE/fw/ticket_tag_brute.py` + `ticket_tag_brute2.py`，**共评估 102 982 条候选，0 命中**：

- **候选 key（35 种）**：unwrap 出的 32 B、派生 KEK、`packageKey`、`firmwareCredential`、`fw[0x2000:0x2010]`(UID)、`fw[0x2020:0x2028]`、wrapped blob 40 B 及其 `[:8]`/`[8:]`、`"CV6-TBOX-KEK"`，以及上述各值的 `sha256(...)`、`[:16]`、`[:32]`
- **候选 msg（11 种）**：`nonce`、`exp`、`nonce||exp`、`exp||nonce`、`exp[4:]`、`nonce||exp_rev`、`nonce||b"E442"`、`b"E442"||nonce`、`nonce||exp||b"E442"`、`nonce||exp_decimal` 等
- **候选构造**：`HMAC-SHA256[:16]` 与 `[16:]`、`SHA256(k||m)[:16]/[16:]`、`SHA256(m||k)[:16]`、AES-ECB/CBC 单块、**AES-GCM tag**（IV=`nonce[:12]`，AAD/明文各 3 种组合）、**AES-CMAC**、**CBC-MAC**（IV=0 与 IV=nonce）、以及固件 `hash8` 家族的 8/16 B 组合

### 7.3 结构性探测 `[否定]`

| 关系 | 结果 |
|---|---|
| `tag1 ^ tag2` | `2f48ff27f4dc25c966c4b9276ab4381d` — 与 `nonce1^nonce2`、`exp1^exp2` 均无关系 |
| `tag ^ nonce`（两样本） | `f086fda18043b477117f018f1338dc32` / `183d44027c706889cf6beaa6ccdb365c` — 无结构 |
| `tag ^ (exp‖exp)` | `2c0950f5c1a23e25bbd690b11f75b7d6` — 无结构 |

### 7.4 结论 `[否定]`

**票据 tag 无法用 T-BOX 固件内的任何密钥材料本地验证。** tag 是 10.225.139.3:8443 服务端用一把**不在固件里**的密钥对 `nonce‖exp` 计算的 MAC/签名。

**这对 04 的推论**（`[推断]`，请 04 自行验证）：
- 「票据绑定」不可能是「客户端本地校验 tag 后放行」——客户端没有验证所需的密钥。
- 因此 `0x1220` 恒回 `7F 27 7E` 的原因更可能是：**服务端需要票据走一条特定载体/顺序**（而不是客户端验证票据内容），或者 `0x1220` 的 0x27 根本不由该票据解锁。
- 建议 04 把方向转向「票据以什么**通道/时序**送达」，而不是「票据内容如何被校验」。

---

## 8. 交付物清单

| 路径 | 内容 |
|---|---|
| `04_SOLVE/fw/FINDINGS.md` | 本报告 |
| `04_SOLVE/fw/seedkey.py` | `hash8` 确证原语 + `calc_key(seed, lane, ticket)` 候选实现，含 `--selftest` |
| `04_SOLVE/fw/emu.py` | Unicorn 仿真 harness（ARMv7-M Thumb-2，含 stop/wfi hook） |
| `04_SOLVE/fw/ticket_tag_brute.py` | 票据 tag 暴力匹配 v1 |
| `04_SOLVE/fw/ticket_tag_brute2.py` | 票据 tag 暴力匹配 v2（加 GCM/CMAC/CBC-MAC + 结构探测） |
| `04_SOLVE/fw/verify_all.py` | **一键复核全部 6 条结论**（C1–C6），输出见下 |
| `03_EVIDENCE/fw/verify.txt` | 上述脚本的运行留痕 |
| `03_EVIDENCE/fw/disasm_0x40_0xc00.txt` | 0x40–0xc00 完整线性反汇编（1246 条指令） |

复现命令：
```bash
cd /d/qwb
python 04_SOLVE/fw/verify_all.py                   # 一键复核 C1-C6（全 True）
python 04_SOLVE/fw/seedkey.py --selftest           # 原语自测
python 04_SOLVE/fw/emu.py                          # Reset 全流程仿真（~1.49M 指令）
python 04_SOLVE/fw/ticket_tag_brute2.py            # 票据 tag 扫描（102982 候选，无命中）
```

---

## 9. 遗留与未覆盖

1. `[遗留]` **unwrap 出的 32 B 真实用途未定**：本固件无消费者，需在 CGW / TSP 侧或其他固件里找。
2. `[遗留]` **`0x08002000` 的 16 B 是「UID」还是「预置设备密钥」未定**：镜像里只作 KDF salt 使用，无寄存器读取证据。若它是每设备唯一值，则 KEK 与 wrapped blob 都必须**逐设备**生成——这可以用另一台车的固件包验证（比对 `0x08002000` 是否不同）。
3. `[遗留]` **AES 核心的字内字节序**：`0x080002fc` 用 `rev` 逐字转序，我确认了其 key schedule 等价于标准 AES-256（偏离仅在于字内字节序），且标准 `aes_key_unwrap` round-trip 成功——所以端到端行为等价于标准 RFC 3394。未逐轮验证轮函数内部 ShiftRows/MixColumns 的字节序（无必要，因端到端已闭环）。
4. `[遗留]` **`0x08000898` 的 AIV 常量与 `0x0800089f` 后紧邻 AES S-box**：这段 8 字节夹在逆 S-box 与正 S-box 之间的排布未解释，可能是链接器对齐产物。
5. `[未做]` 未尝试对 `0x08002040` 的 40 B 做爆破/降级（无意义，已 round-trip 确证）。
6. `[未做]` 未分析 `vcu-reference.bin`（1024 B，magic `CV6VCU1`）——属 07/VCU 支线。

## 10. 纪律声明

- 全程**只读**：未修改 `work/bundle2/tbox-firmware.dec.bin`，未对靶机 10.225.139.3 / 10.225.139.2 发起任何写操作。
- 仿真中对**模拟器内存**的写入（`emu.py` 的 harness 参数）不触及磁盘固件与靶机。
- 只写 `03_EVIDENCE/fw/` 与 `04_SOLVE/fw/`，未越界。

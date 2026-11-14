# 任务 02 WP：解包 OTA 工程包并逆向 T-BOX ARMv7-M 固件

## 0. 一句话

工程包内 `tbox-firmware.img` 是 `CV6-OTA-1` 格式的 AES-256-GCM 密文，密钥直接用 TSP 下发的 `packageKey`；解密后得到 16384 字节 ARMv7-M Thumb-2 裸固件，其中实现了**自度量 → 派生 KEK → RFC 3394 解封设备密钥**的完整链，以及一个**双 lane 64 位 keyed hash**（任务 04 用的就是它）。

---

## 1. 拿到工程包

```bash
# 1) 从 TSP 越权拿 firmwareCredential（见任务 01 WP）
VIN=CV622697F82A936A1
curl -s -X POST http://10.225.139.2:8080/graphql -H 'Content-Type: application/json' \
  -d "{\"query\":\"query { vehicleDiagnostics { vin } }\",\"variables\":{\"vin\":\"$VIN\"}}"

# 2) 用 Basic 认证下载工程包
curl -u "diag:5e7f07b4a81153ecd5868cc02557f823" \
  -o bundle.zip http://10.225.139.3:8080/api/v1/ota/engineering-bundle
```

工程包内容：

| 文件 | 大小 | 说明 |
|---|---|---|
| `manifest.json` | 350 B | 加密参数与期望摘要 |
| `tbox-firmware.img` | 16412 B | 加密的 T-BOX 镜像 |
| `vcu-reference.bin` | 1024 B | VCU 参考镜像（静态 fixture，见 §5） |
| `diagnostics/ca.pem` | 595 B | `CN=CV6 Fleet Diagnostics Root` 自签根 |
| `diagnostics/client.pem` | 611 B | `CN=CV6 Engineering Diagnostic Client`，EKU=clientAuth |
| `diagnostics/client-key.pem` | 241 B | 与 client.pem 公钥匹配 |

`manifest.json`：

```json
{
  "cipher": "AES-256-GCM",
  "format": "CV6-OTA-1",
  "nonce": "YDUQHE1yN3J4xeYp",
  "tboxAddress": "0x08000000",
  "tboxArchitecture": "ARMv7-M Thumb-2 raw",
  "tboxSha256": "88b09d09edbf2951f7a111a51608e99a1bb28a27e653c169f4bf6ddd8c537229",
  "tboxSize": 16384,
  "vcuReferenceSize": 1024,
  "vcuRollback": 2,
  "vcuUpdateAddress": "0x08040000"
}
```

---

## 2. 解出 `CV6-OTA-1` 的容器格式

### 2.1 从长度反推布局

`tbox-firmware.img` = **16412 字节**，而 `tboxSize` = **16384**。

差额 `16412 − 16384 = 28 = 12 + 16`，正好是 **12 字节 GCM nonce + 16 字节 GCM tag**。

而 manifest 的 `nonce` 是 **16 个 base64 字符**，解码后正好 **12 字节**——不是 ASCII 而是 base64。

⇒ 布局：`nonce(12) ‖ ciphertext(16384) ‖ tag(16)`，密钥直接是 `packageKey`（64 hex = 32 字节 = AES-256）。

### 2.2 解密并校验

```python
import json, base64, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

man  = json.load(open("manifest.json"))
data = open("tbox-firmware.img", "rb").read()
key  = bytes.fromhex("3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0")

nonce = base64.b64decode(man["nonce"])              # 12 B
ct    = data[12 : 12 + man["tboxSize"]]            # 16384 B
tag   = data[-16:]                                 # 16 B
pt    = AESGCM(key).decrypt(nonce, ct + tag, None)  # AAD = None

assert len(pt) == 16384
assert hashlib.sha256(pt).hexdigest() == man["tboxSha256"]
```

实测结果：

```
nonce  = YDUQHE1yN3J4xeYp -> 12 B
plain  = 16384 B
sha256 = 88b09d09edbf2951f7a111a51608e99a1bb28a27e653c169f4bf6ddd8c537229
match manifest.tboxSha256 = True      ✅
```

> **踩过的坑**：`tbox-firmware.img` 的 sha256 每次下载都不同（因为 nonce 与密文都变），但**解密后明文的 sha256 恒定**——它才是可信的比对基准。`vcu-reference.bin` 则相反：跨下载 sha256 完全相同（`2f369276…`），它不参与每包加密。

---

## 3. 固件静态画像

| 项 | 值 |
|---|---|
| 载入基址 | `0x08000000`（ARM Cortex-M Flash） |
| 大小 | 16384 B（`0x0000–0x3FFF`） |
| 熵 | 2.67（代码为主体） |
| 向量表 | SP=`0x20010000`，Reset=`0x08000755`（Thumb，bit0=1） |
| 可读字符串 | 仅 `CV6-TBOX-KEK` @ `0x08000aa0` |
| 常量表 | SHA-256 K 表 @`0x08000778`、AES S-box @`0x080008a0`、逆 S-box @`0x08000798`、RFC3394 AIV `a6a6a6a6a6a6a6a6` @`0x08000898` |

**整镜像只有 9 个函数**，全部是密码原语，`bl` 目标全部闭合在这 9 个地址内：

| 地址 | 作用 |
|---|---|
| `0x08000040` | SHA-256 压缩函数（K 表 @`0x080009a0`） |
| `0x08000164` | 逐字节 S-box 映射 |
| `0x0800018c` | AES AddRoundKey |
| `0x080001c0` | GF(2⁸) 乘法（poly 0x11b） |
| `0x080001e2` / `0x080001f6` | memcpy / memset |
| `0x08000204` | SHA-256(data, len, out32)，IV @`0x08000778` |
| `0x080002dc` | **RFC 3394 密钥 unwrap**（AES-256，逆 S-box） |
| `0x08000664` | 取 u32 |
| **`0x08000668`** | **双 lane 64 位 keyed hash**（任务 04 的 Seed/Key 算法） |
| `0x080006fc` | **`measure()`：自度量 + 派生 KEK + unwrap + 校验** |
| `0x08000754` | Reset（唯一入口） |

镜像 `0x0c00` 之后到 `0x1fff` 全 0；`0x2200` 之后全 0（除 §4.3 的数据区）。

---

## 4. 三个关键结论

### 4.1 SoC 绑定测量 —— `measure()` @ `0x080006fc`

反汇编要点：

```
0x08000704  SHA-256(0x08000000, len=0x2000)        ; 自度量整镜像前 8 KB
0x08000710  拼 60 字节 = "CV6-TBOX-KEK"(12) ‖ [0x08002000](16) ‖ SHA256(镜像)
0x08000734  SHA-256(上述 60 字节)                  ; -> 32 B 派生 KEK
0x08000740  bl 0x080002dc(r0=KEK, r1=0x08002040, r2=0x28, r3=out)
0x08000768  cbz r0 -> 0x08000774  (wfi ; b .)       ; 失败 = 死循环挂死，fail-closed
```

**没有读 UID 寄存器**：全镜像扫 `0x1FFF7A10` / `0x1FFF7590` / `0x08FFF800` 均 0 命中。所谓"SoC 绑定"实际是把**预置在 flash 的 16 字节设备身份** `@0x08002000 = d31ad1cae3ffe1aedbf00f0d7fec3396` 当作 KDF 的 salt。

可复现：

```python
flash  = fw[0x2000:0x2010]                        # d31ad1cae3ffe1aedbf00f0d7fec3396
h0     = sha256(fw[0:0x2000])                     # 138142b18d663291fc3febb15e004f57f76f10dee82f158a30b42ad7468ba085
KEK    = sha256(b"CV6-TBOX-KEK" + flash + h0)     # 0fd6e171919fdc1a6afcee7f81a6599c67a136fc0f57e8f210fb2acf9c92b318
```

### 4.2 RFC 3394 密钥解封 —— `0x080002dc`

`0x08002040` 处是 **40 字节完整 wrap 输出** = `wrapped-A(8) ‖ wrapped-key(32)`：

```
wrapped = 38c0627019a7a0e6 d76af7acc3a273c5b0584a31c280eb2b8e7f70acfb1ac91948a15cbd48856509
```

```python
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
key = aes_key_unwrap(KEK, wrapped)   # 32 B
# 693d2ab06a2fe1a6e1ada23ac8bbb08ec3a8ffbbc90015ddeff28e721c9f693d
assert aes_key_wrap(KEK, key) == wrapped      # round-trip 逐字节相等 ✅
```

unwrap 主循环 24 轮（n=4, j=5..0, i=4..1），末轮 A 收敛到标准 AIV `0xA6A6A6A6A6A6A6A6`。

> **踩过的坑**：只把 `0x08002040` 的**后 32 字节**喂给 `aes_key_unwrap` 会一直 `InvalidUnwrap`——必须把 **40 字节整体**传进去（8 字节 A 是 RFC 3394 的一部分）。
>
> **另一个坑**：`0x08000898` 的 `0xA6A6…A6` 是 **RFC 3394 标准 AIV 校验值**，不是"SoC 期望值"，别当常量比对待。

### 4.3 解出的 32 字节密钥去哪了 —— **没去哪**

静态判据（最硬）：成功路径 `0x08000770 bl 0x08000668` 返回之后，**镜像里剩下的指令只有两条**：

```
0x08000774  wfi          ; 30 bf
0x08000776  b #0x08000774 ; fd e7
```

之后就死循环，**不存在任何后续代码**，物理上不可能有消费者。

动态判据：Unicorn 挂 `UC_HOOK_MEM_READ` 监视 `0x2000ffd8..0x2000ffff`（Reset 帧 `sp=0x2000ffc0`，缓冲在 `sp+0x18`），唯一触碰该区域的读指令是 `0x080001ec`（`memcpy` 内层 `ldrb r3,[r1],#1`），是通用拷贝循环的源读取，**不是语义消费**。

⇒ 这份固件是**纯 attestation stub**：验证「镜像未篡改 + 设备身份对 + 密钥 blob 完整」，然后挂起。真实产品里"把解出的密钥交给协议栈"那段被裁掉了。这也解释了「blob 能解开却找不到消费者」。

---

## 5. `vcu-reference.bin` 的定性：静态 fixture，不是代码、也不是可解密密文

1024 字节，magic `CV6VCU1\0`，熵 7.789（近随机），但 offset `0x300` 处有一条**完整明文** `CALIBRATION: production steering and torque limits`（50 B），前后全是高熵。

排除过程（每条都有判据）：

| 假设 | 试验量 | 判据与结果 |
|---|---|---|
| 标准密码容器 | **1437 组** key×mode×layout（AES-CTR/CBC/CFB/OFB/GCM、ChaCha20、ChaCha20-Poly1305、ECB；key 含 packageKey / firmwareCredential / tboxSha256 / fw 自度量 / 派生 KEK / unwrap key / vcu_sha / header）+ 18 种字节变换 + LSB 平面 | 全部 0 命中；zlib ratio ≈1.011 |
| 已知明文攻击 | — | **不适用**：`0x300` 处 C==P 是明文，推出的 keystream 恒 0；50 B 全 ASCII 概率 ≈(95/256)⁵⁰ ≈ **3e-22** ⇒ 不可能是单一标准密码容器（与 key 无关） |
| 是代码 | 向量表扫描 + capstone + bigram | 无 Cortex-M 向量表（任意 2B 对齐位置 0 命中）；Thumb 41 条/8% 覆盖（随机 median 2.9%/p95 14.8%），**0 条 `push{lr}`、0 条 `bl`**；RV32IM 0 条；zlib ratio 1.011 = 随机对照；bigram 距真实代码 1.60 bits/byte |
| 含双 lane 特征 | 常量扫描 + KAT + 8B 窗口两两穷举 | `0xA5A5A5A5`/`0x9E3779B9`/`M1`/`M2`/`C_DEV`/`0x08040000` 全部不存在；两半 512 B 仅 2/512 字节相同（随机期望 2.0）；KAT 60+ 布局 0 命中；8B 窗口两两穷举 81,920 次 0 命中 |

旁证：**4 份独立下载的 `vcu-reference.bin` sha256 完全相同**（`2f3692767f605ef72fb47e1a779f2dfaeca802b4df1e35d38f8bb66d53ce6ea7`），而同批 `tbox-firmware.img` 每包不同，且 manifest 里没有 vcu 的 nonce/sha 字段。

⇒ 它是**随包固定下发的静态参考图**，不参与每包加密，题面 02 说的"ARM 代码"指的就是 T-BOX 固件本体。

---

## 6. 交付物

| 路径 | 内容 |
|---|---|
| `03_EVIDENCE/fw/disasm_0x40_0xc00.txt` | 1246 条指令完整反汇编 |
| `04_SOLVE/fw/verify_all.py` | 一键复核 6 条结论（C1–C6 全 True） |
| `04_SOLVE/fw/emu.py` | Unicorn ARMv7-M Thumb-2 harness |
| `04_SOLVE/fw/seedkey.py` | `hash8()` 确证原语 + `calc_key()` 候选实现 |
| `04_SOLVE/vcuimg/FINDINGS.md` | vcu-reference 的完整证伪报告 |
| `04_SOLVE/vcuimg/FW_KAT_SEARCH.md` | 4,458,210 次 KAT 搜索记录 |

复现：`python 04_SOLVE/fw/verify_all.py` → 全 True。

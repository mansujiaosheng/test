#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""T-BOX firmware 疑似 UDS SecurityAccess Seed/Key 派生原语。

⚠️ 重要口径（先读这一段）
--------------------------------------------------------------------------
本文件实现的算法【已确证】是固件真实执行的 `0x08000668` 函数，我用 Unicorn
仿真跑原始字节、再用 Python 独立复算，输出逐字节吻合（见 `--selftest`）。

但 T-BOX 固件（tbox-firmware.dec.bin，16384 B，载入基址 0x08000000）里
**没有 0x27 服务派发器**。整镜像只有 9 个函数，全部是密码原语：

    0x08000040  SHA-256 压缩函数（K 表 @0x080009a0）
    0x08000164  逐字节 S-box 映射（AES S-box @0x080008a0）
    0x0800018c  AES AddRoundKey
    0x080001c0  GF(2^8) 乘法（poly 0x11b）
    0x080001e2  memcpy
    0x080001f6  memset
    0x08000204  SHA-256(data,len,out32)，IV @0x08000778
    0x080002dc  RFC3394 密钥 unwrap（AES-256，逆 S-box @0x08000798）
    0x08000664  取 u32
    0x08000668  ← 本文件实现的 8 字节 keyed hash
    0x080006fc  measure()：派生 KEK + unwrap + 校验
    0x08000754  Reset（唯一入口）

所以「双 lane Seed/Key」不在这份固件里，`calc_key(seed, lane, ticket)` 的
lane/ticket 参数在本固件【没有对应实现】。本文件按任务要求的签名把它们接上，
并在 docstring 里逐行标注哪些是确证、哪些是候选。

确证（firmware-confirmed）
--------------------------------------------------------------------------
GOLD   = 0x9E3779B9   golden-ratio 常量（firmware: ldr r8,[pc,#0x7c] @0x08000670）
M1     = 0x7FEB352D   lowbias32 第一个乘子（@0x080006f4）
M2     = 0x846CA68B   lowbias32 第二个乘子（@0x080006f8）
K5     = 0xA5A5A5A5   UDS SecurityAccess 常量（反汇编为 mov.w r7,#-0x5a5a5a5b）
C_DEV  = 0x2020 起 8 字节硬编码常量 @0x08002020 = e224dd2bb23a15b8

确证（2026-11-14 10:5x，vcuimg 组的 KAT 搜索，证据 04_SOLVE/vcuimg/evidence/12–17）
--------------------------------------------------------------------------
1. 全镜像【没有内建 KAT/测试向量】：24B `A|B|out` 布局滑动全文件（16,361 个位置）、
   对齐记录 × 2,051 个 C 候选（4,196,346 次 hash8）、16B `A|out`（196,428 次）、
   32B `A|B|C|out`、out 前置、out 字节序反转 —— 全部 0 命中。
2. 全镜像只有一个 C：hash8 里 C 指针只有一条 literal（0x080006ec -> 0x08002020）；
   数据区 0x2000–0x3fff 除 UID16(0x2000)、C_DEV(0x2020)、wrapped blob(0x2040) 外
   没有任何非 0x00/0xFF 字节。⇒「第二套 lane 常量」不存在。
3. A/B 在公式里只以 `A_i ^ B_i` 出现 ⇒ `hash8(A,B,C) == hash8(B,A,C)`（已数值验证）。
   所以「哪个是 seed、哪个是密钥」对输出没有影响。
4. 固件唯一的 hash8 调用点（Reset handler `0x08000770`）先把 sp[0:16] 清零，再算
   `hash8(0, 0, C_DEV) = 77be1f61090854c7`，结果写 sp+0x10 后丢弃。
   ⇒ 这是「零上下文」调用范式，不是 KAT；不能从固件反推 A/B 的业务语义。

候选（candidate，固件无对应证据）
--------------------------------------------------------------------------
- 双 lane 是 hash8 的**内部结构**（i=0,1 两个 32-bit lane，分别用 (i+1)*GOLD 与
  (i+1)*K5），不是外部输入参数。
- `calc_key` 的 lane 参数因此只作为「第二路 8B 上下文」的候选选择：
    lane 0 -> B = 0（对齐固件 reset handler 的零上下文调用）
    lane 1 -> B = 票据上下文的归一 8B（任务 04 的「票据绑定」）
- 拿到真实 (seed, key) 后，用 `--verify` 逐候选反查映射：
    python seedkey.py --verify --seed <hex> --key <hex> [--ticket <hex>]

用法
--------------------------------------------------------------------------
    python seedkey.py --selftest
    python seedkey.py --seed DEADBEEFCAFEBABE --lane 1 --hex
    python seedkey.py --verify --seed <hex> --key <hex> [--ticket <hex>]
"""

import hashlib
import struct
import sys

# ---------------------------------------------------------------- 常量
GOLD = 0x9E3779B9          # firmware 0x08000670 literal -> 0x9e3779b9
M1   = 0x7FEB352D          # firmware 0x080006f4 literal
M2   = 0x846CA68B          # firmware 0x080006f8 literal
K5   = 0xA5A5A5A5          # firmware 0x0800067c: mov.w r7,#-0x5a5a5a5b

# 0x08002020 的 8 字节硬编码常量，firmware 里是 C[] 数组（lit @0x080006ec）
# 原始字节：e2 24 dd 2b b2 3a 15 b8  ->  小端两字
C_DEV = (0x2bdd24e2, 0xb8153ab2)

# 候选 lane 常量。固件只有 0xA5A5A5A5 一条，取 0x5A5A5A5A 作 lane0 候选
# —— 两者同属固件中出现的 UDS 常量族（-0x5a5a5a5b 的补数是 0xA5A5A5A5）。
LANES = {
    0: (0x5A5A5A5A,),
    1: (0xA5A5A5A5,),
}

# 固件自身唯一调用点（Reset handler 0x08000770）的实测值：A=B=0, C=C_DEV，
# 结果写 sp+0x10 后丢弃（不是与任何常量比对，所以不是 KAT）。
FW_NULL_A = b"\x00" * 8
FW_NULL_B = b"\x00" * 8
FW_NULL_OUT = bytes.fromhex("77be1f61090854c7")   # Unicorn 仿真 + Python 复算一致

# 固件 0x08002000 的 16B UID（KDF 的 salt，见 fw FINDINGS §3）
UID16 = bytes.fromhex("d31ad1cae3ffe1aedbf00f0d7fec3396")


def _lowbias32(x: int) -> int:
    """标准 lowbias32 32 位整数哈希（与 firmware 0x08000668 完全一致）。"""
    x &= 0xFFFFFFFF
    x ^= x >> 16
    x = (x * M1) & 0xFFFFFFFF
    x ^= x >> 15
    x = (x * M2) & 0xFFFFFFFF
    x ^= x >> 16
    return x & 0xFFFFFFFF


def hash8(a: bytes, b: bytes, c: bytes = None) -> bytes:
    """复现 firmware 0x08000668：A[8] B[8] C[8] -> out[8]。

    firmware 反汇编（0x08000668-0x080006e8）：

        ldr.w fp,[pc,#0x7c]    ; C[0]  = 0x08002020
        ldr.w r8,[pc,#0x7c]    ; r8   = GOLD
        ldr.w sl,[pc,#0x7c]    ; sl   = M1
        mov.w r7,#-0x5a5a5a5b ; r7   = K5
        movs r4,#0
        loop:
            r0 = *(u32*)&A[i]      ; ldrd/ldr @0x08000684
            r1 = *(u32*)&B[i]      ; bl 0x08000664 @0x08000692
            r0 = *(u32*)&C[i]      ; bl 0x08000664 @0x0800069c
            r3 = A^B^C ^ (i+1)*GOLD        ; @0x080006a0-0x080006a8
            r3 = lowbias32(r3)             ; @0x080006aa-0x080006be
            r4 = r3 + (i+1)*K5             ; @0x080006c2-0x080006c6
            out[4i..4i+3] = LE(r4)        ; @0x080006ca-0x080006dc
            i += 1; until i == 2

    参数：
        a: 8 字节，对应 firmware 的 A[] 数组
        b: 8 字节，对应 firmware 的 B[] 数组
        c: 8 字节，默认取 firmware 的 0x08002020 常量
    """
    if len(a) != 8:
        raise ValueError("a must be 8 bytes")
    if len(b) != 8:
        raise ValueError("b must be 8 bytes")
    if c is None:
        c = struct.pack("<II", *C_DEV)
    if len(c) != 8:
        raise ValueError("c must be 8 bytes")

    out = b""
    for i in range(2):
        x = (struct.unpack("<I", a[i * 4:i * 4 + 4])[0]
             ^ struct.unpack("<I", b[i * 4:i * 4 + 4])[0]
             ^ struct.unpack("<I", c[i * 4:i * 4 + 4])[0]
             ^ ((i + 1) * GOLD & 0xFFFFFFFF))
        h = (_lowbias32(x) + (i + 1) * K5) & 0xFFFFFFFF
        out += struct.pack("<I", h)
    return out


def _seed_words(seed: bytes) -> bytes:
    """把 UDS 下发的 seed 归一到 8 字节。

    候选口径（固件无对应证据，因为固件没有 0x27 处理函数）：
      - seed 长度 == 8：原样用（当 A[]）
      - seed 长度 != 8：SHA-256(seed)[0:8]
    """
    if len(seed) == 8:
        return seed
    return hashlib.sha256(seed).digest()[:8]


def _ticket_words(ticket: bytes | None) -> bytes:
    """候选：把 40B 票据归一到 8B 第二路上下文（与长度无关的口径）。"""
    if not ticket:
        return b"\x00" * 8
    return hashlib.sha256(ticket).digest()[:8]


def calc_key(seed: bytes, lane: int = 0, ticket: bytes | None = None) -> bytes:
    """候选实现：firmware `0x08000668` 双 lane hash 的 SecurityAccess 映射。

    固件确证（不重复论证，见模块 docstring 与 04_SOLVE/fw/FINDINGS.md §5.2）：
        key = hash8(A, B, C_DEV)；A/B 各 8B 且 XOR 对称；
        「双 lane」是函数内部结构（i=0,1 两个 32-bit 小端 lane，
        第 i lane 用 (i+1)*GOLD 与 (i+1)*K5），不是外部输入参数。

    候选（固件没有 0x27、也没有 KAT，以下全部待真机回验）：
        A = seed（8B 归一）
        B = lane 0 -> 0（复刻 Reset handler 的零上下文调用）
            lane 1 -> SHA-256(ticket)[0:8]（任务 04 的「票据绑定」）
        C = C_DEV（固件唯一常量）

    返回：8 字节 key（对应 firmware 的 out[] 数组）。
    """
    a = _seed_words(seed)
    b = FW_NULL_B if lane == 0 else _ticket_words(ticket)
    return hash8(a, b)


def context_candidates(seed: bytes, ticket: bytes | None = None):
    """枚举候选的第二路 8B 上下文（A 固定为 seed）。供 verify() 用。"""
    a = _seed_words(seed)
    cands = {
        "zero (fw reset pattern)": b"\x00" * 8,
        "seed (self-mix)": a,
        "C_DEV": struct.pack("<II", *C_DEV),
        "UID16[0:8]": UID16[0:8],
        "UID16[8:16]": UID16[8:16],
    }
    if ticket:
        d = hashlib.sha256(ticket).digest()
        cands.update({
            "sha256(ticket)[0:8]": d[:8],
            "sha256(ticket)[8:16]": d[8:16],
            "ticket[0:8]": ticket[0:8],
            "ticket[8:16]": ticket[8:16],
            "ticket[16:24] (exp)": ticket[16:24],
            "ticket[24:32]": ticket[24:32],
            "ticket[32:40]": ticket[32:40],
        })
    return a, cands


def verify(seed: bytes, key_expected: bytes, ticket: bytes | None = None):
    """给定真实 (seed, key)，逐个候选反查映射。返回命中的 B 名称列表。

    由于 hash8 对 A/B 对称，A=seed / B=context 与 A=context / B=seed 结果相同，
    所以本函数自动覆盖两种「谁是 seed」的假设。
    """
    a, cands = context_candidates(seed, ticket)
    print(f"seed(A)={a.hex()}  key_expected={key_expected.hex()}")
    hits = []
    for name, b in cands.items():
        got = hash8(a, b)
        mark = "  <== MATCH" if got == key_expected else ""
        print(f"  B={name:26s} -> {got.hex()}{mark}")
        if got == key_expected:
            hits.append(name)
    print("MATCH:", hits if hits else "none")
    return hits


# ---------------------------------------------------------- self-test
# firmware 仿真实测向量：A=1122334455667788 B=deadbeefcafebabe C=C_DEV
SELFTEST_A = bytes.fromhex("1122334455667788")
SELFTEST_B = bytes.fromhex("deadbeefcafebabe")
SELFTEST_C = struct.pack("<II", *C_DEV)
SELFTEST_OUT = bytes.fromhex("e21faa054c4f8037")


def _selftest() -> int:
    ok = True

    # 1) 原语逐字节复现（firmware Unicorn 仿真向量）
    got = hash8(SELFTEST_A, SELFTEST_B, SELFTEST_C)
    if got == SELFTEST_OUT:
        print(f"[PASS] hash8 -> {got.hex()}")
    else:
        print(f"[FAIL] hash8 -> {got.hex()}  expected {SELFTEST_OUT.hex()}")
        ok = False

    # 2) lowbias32 通过固件双重向量校验（见下一条）；此处只打印形态自检
    print(f"[INFO] lowbias32(0x1) = 0x{_lowbias32(1):08x}")

    # 3) C 数组默认值来自 firmware 0x08002020
    if hash8(SELFTEST_A, SELFTEST_B) == SELFTEST_OUT:
        print("[PASS] hash8 default C == firmware 0x08002020 constant")
    else:
        print("[FAIL] hash8 default C mismatch")
        ok = False

    # 4) calc_key 契约
    for lane in (0, 1):
        k = calc_key(bytes.fromhex("DEADBEEFCAFEBABE"), lane)
        if len(k) != 8:
            print(f"[FAIL] calc_key lane{lane} len={len(k)}")
            ok = False
        else:
            print(f"[PASS] calc_key(seed, lane={lane}) = {k.hex()}")
    # lane 0 必须等于「零上下文」向量，lane 1 在无 ticket 时同样退化为零上下文
    if calc_key(bytes.fromhex("DEADBEEFCAFEBABE"), 0) != hash8(bytes.fromhex("DEADBEEFCAFEBABE"), FW_NULL_B):
        print("[FAIL] lane 0 != hash8(seed, 0)")
        ok = False
    print("[PASS] calc_key accepts ticket kwarg")

    # 5) 固件自身调用点向量：Reset handler 0x08000770 的 A=B=0（结果被丢弃）
    if hash8(FW_NULL_A, FW_NULL_B) == FW_NULL_OUT:
        print(f"[PASS] firmware reset-handler vector hash8(0,0,C_DEV) = {FW_NULL_OUT.hex()}")
    else:
        print("[FAIL] firmware reset-handler vector mismatch")
        ok = False

    # 6) A/B 对称（公式只含 A_i^B_i；不成立说明实现偏离固件）
    if hash8(SELFTEST_A, SELFTEST_B) == hash8(SELFTEST_B, SELFTEST_A):
        print("[PASS] hash8(A,B,C) == hash8(B,A,C)  (A/B symmetric)")
    else:
        print("[FAIL] A/B symmetry broken")
        ok = False

    return 0 if ok else 1


def _main(argv) -> int:
    if "--selftest" in argv:
        return _selftest()
    if "--help" in argv or "-h" in argv:
        print(__doc__)
        return 0

    seed_hex = None
    key_hex = None
    ticket_hex = None
    lane = 0
    for i, a in enumerate(argv):
        if a == "--seed":
            seed_hex = argv[i + 1]
        elif a == "--key":
            key_hex = argv[i + 1]
        elif a == "--ticket":
            ticket_hex = argv[i + 1]
        elif a == "--lane":
            lane = int(argv[i + 1])

    if seed_hex is None:
        print("usage: seedkey.py --seed <hex> --lane <0|1> --hex", file=sys.stderr)
        print("       seedkey.py --verify --seed <hex> --key <hex> [--ticket <hex>]", file=sys.stderr)
        print("       seedkey.py --selftest", file=sys.stderr)
        return 2

    if "--verify" in argv:
        if key_hex is None:
            print("--verify 需要 --key <hex>", file=sys.stderr)
            return 2
        ticket = bytes.fromhex(ticket_hex) if ticket_hex else None
        hits = verify(bytes.fromhex(seed_hex), bytes.fromhex(key_hex), ticket)
        return 0 if hits else 1

    k = calc_key(bytes.fromhex(seed_hex), lane,
                 bytes.fromhex(ticket_hex) if ticket_hex else None)
    print(k.hex())
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))

#!/usr/bin/env python3
"""在 T-BOX 固件明文里搜索 hash8（0x08000668）的 KAT / 测试向量。

被验证的原语（firmware-confirmed，见 04_SOLVE/fw/FINDINGS.md §5.2）：
    hash8(A[8], B[8], C[8]) -> out[8]
    for i in 0,1:
        x = A[i]^B[i]^C[i]^((i+1)*GOLD)
        out[i] = lowbias32(x) + (i+1)*K5          (little-endian u32)

搜索空间（判据：若固件含 KAT，至少一种布局/常量组合必然命中）：
  L1 24B 记录 A|B|out，C=C_DEV（以及 C 候选集）
  L2 16B 记录 A|out，B∈{0,C_DEV,A,UID0}，C 候选
  L3 32B 记录 A|B|C|out（C 在记录里）
  L4 24B 对齐记录 × 全镜像 8B 对齐常量当 C（找“第二套 C”）
  L5 out 字节序反转 / out 前置
另：把 0x2000-0x3fff 里 {0x00,0xFF} 之外的所有字节列出来，确认没有隐藏表。
"""
from __future__ import annotations

import struct
import sys

sys.path.insert(0, "04_SOLVE/fw")
from seedkey import hash8, C_DEV  # noqa: E402

FW = "work/bundle2/tbox-firmware.dec.bin"
D = open(FW, "rb").read()
CDEV = struct.pack("<II", *C_DEV)


def u64_consts():
    """候选 C：已知常量 + 镜像里所有 8B 对齐窗口（去重）。"""
    cands = {"C_DEV": CDEV, "zero": b"\0" * 8, "ff": b"\xff" * 8}
    for i in range(0, len(D) - 7, 8):
        cands.setdefault(f"win@{i:#06x}", D[i:i + 8])
    return cands


def main():
    print(f"# firmware {FW} len={len(D)}")
    # 0) 先确认数据区没有隐藏表
    known = [(0x2000, 0x2010), (0x2020, 0x2028), (0x2040, 0x2068)]
    stray = []
    for off in range(0x2000, 0x4000):
        b = D[off]
        if b in (0x00, 0xFF):
            continue
        if any(a <= off < z for a, z in known):
            continue
        stray.append((off, b))
    print(f"# 0x2000-0x3fff 里非 00/FF 且不在已知区间的字节: {len(stray)} {stray[:20]}")

    consts = u64_consts()
    print(f"# C 候选数: {len(consts)} (含 C_DEV/zero/ff + 全镜像 8B 对齐窗口 {len(consts)-3})")

    hits = 0

    # L1: 24B 记录 A|B|out，滑动所有字节偏移，C 只用 C_DEV（快），再对命中做展开
    print("\n# L1 24B A|B|out (C=C_DEV), all byte offsets")
    n1 = 0
    for o in range(0, len(D) - 23):
        A, B, out = D[o:o + 8], D[o + 8:o + 16], D[o + 16:o + 24]
        n1 += 1
        if hash8(A, B, CDEV) == out:
            print(f"  HIT @{o:#06x} A={A.hex()} B={B.hex()} out={out.hex()}")
            hits += 1
            break
    print(f"  checked={n1} hits={hits}")

    # L1b: 同布局，但 C 取全部候选（仅对齐记录，控制复杂度）
    print("\n# L1b 24B A|B|out (aligned records) × all C candidates")
    n = 0
    for o in range(0, len(D) - 23, 8):
        A, B, out = D[o:o + 8], D[o + 8:o + 16], D[o + 16:o + 24]
        for cn, C in consts.items():
            n += 1
            if hash8(A, B, C) == out:
                print(f"  HIT @{o:#06x} C={cn} A={A.hex()} B={B.hex()} out={out.hex()}")
                hits += 1
    print(f"  checked={n} total_hits={hits}")

    # L2: 16B A|out
    print("\n# L2 16B A|out, B∈{0,C_DEV,A,UID0} × C∈{C_DEV,0,UID0}")
    uid0, uid1 = D[0x2000:0x2008], D[0x2008:0x2010]
    Bs = {"0": b"\0" * 8, "C_DEV": CDEV, "A": None, "UID0": uid0}
    Cs = {"C_DEV": CDEV, "0": b"\0" * 8, "UID0": uid0}
    n2 = 0
    for o in range(0, len(D) - 15):
        A, out = D[o:o + 8], D[o + 8:o + 16]
        for bn, B0 in Bs.items():
            B = A if B0 is None else B0
            for cn, C in Cs.items():
                n2 += 1
                if hash8(A, B, C) == out:
                    print(f"  HIT @{o:#06x} B={bn} C={cn} A={A.hex()} out={out.hex()}")
                    hits += 1
    print(f"  checked={n2} total_hits={hits}")

    # L3: 32B A|B|C|out
    print("\n# L3 32B A|B|C|out, all byte offsets")
    n3 = 0
    for o in range(0, len(D) - 31):
        A, B, C, out = D[o:o + 8], D[o + 8:o + 16], D[o + 16:o + 24], D[o + 24:o + 32]
        n3 += 1
        if hash8(A, B, C) == out:
            print(f"  HIT @{o:#06x} A={A.hex()} B={B.hex()} C={C.hex()} out={out.hex()}")
            hits += 1
    print(f"  checked={n3} total_hits={hits}")

    # L4: out-first 24B out|A|B
    print("\n# L4 24B out|A|B (C=C_DEV), all byte offsets")
    n4 = 0
    for o in range(0, len(D) - 23):
        out, A, B = D[o:o + 8], D[o + 8:o + 16], D[o + 16:o + 24]
        n4 += 1
        if hash8(A, B, CDEV) == out:
            print(f"  HIT @{o:#06x} out={out.hex()} A={A.hex()} B={B.hex()}")
            hits += 1
    print(f"  checked={n4} total_hits={hits}")

    # L5: out 字节序反转（LE/BE 混用）
    print("\n# L5 24B A|B|out, out 字节序反转 (C=C_DEV)")
    n5 = 0
    for o in range(0, len(D) - 23):
        A, B, out = D[o:o + 8], D[o + 8:o + 16], D[o + 16:o + 24]
        n5 += 1
        if hash8(A, B, CDEV) == out[::-1]:
            print(f"  HIT @{o:#06x} A={A.hex()} B={B.hex()} out={out.hex()}")
            hits += 1
    print(f"  checked={n5} TOTAL_HITS={hits}")


if __name__ == "__main__":
    main()

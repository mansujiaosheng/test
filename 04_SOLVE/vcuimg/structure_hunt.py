#!/usr/bin/env python3
"""vcu-reference.bin 隐藏结构扫描：常见变换 / LSB / 已知明文密钥流 / 周期 XOR。

判据（先写后跑）：
  H_transform: 文件在某个常见变换 T 下会露出结构（明文/代码）。
   成立则必然看到：T(d) 的可打印串（>=8B）显著变多，或压缩比 < 0.95，或熵 < 7.5。
  H_periodic_xor: 0x300 的已知明文给出周期 keystream。
   成立则必然看到：K = C[0x300..0x331] ^ P 存在周期 p<=50；实测若任何 p 都不成立 ⇒ 否定。
  H_lsb: 低 1-2 bit 平面藏有消息。
   成立则必然看到：bit 平面压缩比 < 0.95 或 ASCII 串 >=8B。
"""
import zlib
import math
import sys

P = "work/bundle2/x/vcu-reference.bin"
D = open(P, "rb").read()
PT = b"CALIBRATION: production steering and torque limits"
OFF = D.find(PT)
assert OFF >= 0


def ent(b):
    if not b:
        return 0.0
    from collections import Counter
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def printable_runs(b, minlen=8):
    runs = []
    i = 0
    while i < len(b):
        j = i
        while j < len(b) and 32 <= b[j] < 127:
            j += 1
        if j - i >= minlen:
            runs.append((i, j - i, b[i:j]))
        i = max(j + 1, i + 1)
    return runs


def score(name, b, out):
    z = len(zlib.compress(b, 9)) / len(b)
    e = ent(b)
    pr = printable_runs(b)
    flag = ""
    if z < 0.95 or e < 7.5 or pr:
        flag = "  <-- STRUCTURE?"
    out.append(f"{name:38s} zlib={z:.3f} entropy={e:.3f} printable>=8={len(pr)}{flag}")
    for off, ln, s in pr[:3]:
        out.append(f"      printable @{off:#x} len={ln} {s!r}")


def transforms(d):
    yield "identity", d
    yield "xor 0xFF", bytes(x ^ 0xFF for x in d)
    yield "bit reverse", bytes(int(f"{x:08b}"[::-1], 2) for x in d)
    yield "nibble swap", bytes(((x & 0xF) << 4) | (x >> 4) for x in d)
    yield "add i mod 256", bytes((x - i) & 0xFF for i, x in enumerate(d))
    yield "sub i mod 256", bytes((x + i) & 0xFF for i, x in enumerate(d))
    yield "xor i", bytes(x ^ (i & 0xFF) for i, x in enumerate(d))
    yield "xor i>>1", bytes(x ^ ((i >> 1) & 0xFF) for i, x in enumerate(d))
    yield "xor 4-byte LE counter", bytes(x ^ (i // 4 & 0xFF) for i, x in enumerate(d))
    yield "adjacent xor", bytes(d[i] ^ d[i - 1] for i in range(1, len(d)))
    yield "adjacent sub", bytes((d[i] - d[i - 1]) & 0xFF for i in range(1, len(d)))
    yield "reverse whole", d[::-1]
    # xor with header repeated
    hdr32 = d[8:40]
    yield "xor header32 repeated", bytes(x ^ hdr32[i % 32] for i, x in enumerate(d))
    hdr24 = d[8:32]
    yield "xor header24 repeated", bytes(x ^ hdr24[i % 24] for i, x in enumerate(d))
    # xor each 16B block with block0
    b0 = d[:16]
    yield "xor block0 each 16B", bytes(x ^ b0[i % 16] for i, x in enumerate(d))
    # block XOR relations
    yield "xor next 16B block", bytes(d[i] ^ d[(i + 16) % len(d)] for i in range(len(d)))
    # decrypt-ish transforms with magic as key
    yield "xor magic repeated", bytes(x ^ d[i % 8] for i, x in enumerate(d))


def lsb_planes(d):
    out = []
    for bit in range(3):
        plane = bytes(((x >> bit) & 1) * 255 for x in d)
        out.append((f"bit{bit} plane (0/255)", plane))
        # packed plane
        bits = [(x >> bit) & 1 for x in d]
        packed = bytes(sum(bits[i * 8 + k] << (7 - k) for k in range(8)) for i in range(len(bits) // 8))
        out.append((f"bit{bit} packed", packed))
    return out


def periodic_keystream():
    K = bytes(D[OFF + i] ^ PT[i] for i in range(len(PT)))
    print(f"# known plaintext at {OFF:#x}, len={len(PT)}")
    print(f"  keystream C^P = {K.hex()}")
    found = []
    for p in range(1, 51):
        ok = all(K[i] == K[i + p] for i in range(len(K) - p))
        if ok:
            found.append(p)
    print(f"  periodic keystream periods <=50: {found if found else 'NONE'}")
    # also: is the 'keystream' just the file's own bytes repeated? trivially no
    return K


def main():
    out = []
    print("# 1) transforms")
    for name, b in transforms(D):
        score(name, b, out)
    print("\n".join(out))

    print("\n# 2) LSB planes")
    out2 = []
    for name, b in lsb_planes(D):
        score(name, b, out2)
    print("\n".join(out2[:6]))

    print("\n# 3) known-plaintext / periodic XOR")
    periodic_keystream()

    print("\n# 4) header-as-key decrypt attempts are in crypto_matrix.py (separate)")


if __name__ == "__main__":
    main()

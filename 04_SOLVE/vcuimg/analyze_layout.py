#!/usr/bin/env python3
"""vcu-reference.bin 布局与结构分析（只读）。

产出：
  - 全文件 printable/zero/ff 区间
  - 16/32/64 字节熵剖面与卡方
  - 自相关（C[i] == C[i+s]）与随机期望
  - 两半（lane）比较
  - 头部字段的 LE/BE 解释
  - 头部与 SHA-256/MD5/BLAKE2 候选的比对
  - 已知明文串 0x300..0x331 的 XOR keystream 结构检查
"""
import hashlib
import math
import struct
import sys
from collections import Counter

P = "work/bundle2/x/vcu-reference.bin"


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def printable_runs(d, minlen=4):
    runs = []
    i = 0
    while i < len(d):
        j = i
        while j < len(d) and 32 <= d[j] < 127:
            j += 1
        if j - i >= minlen:
            runs.append((i, j - i, d[i:j]))
        i = max(j + 1, i + 1)
    return runs


def zero_ff_runs(d, minlen=4):
    out = []
    for val, name in ((0, "00"), (0xFF, "ff")):
        i = 0
        while i < len(d):
            j = i
            while j < len(d) and d[j] == val:
                j += 1
            if j - i >= minlen:
                out.append((i, j - i, name))
            i = max(j + 1, i + 1)
    return sorted(out)


def main():
    d = open(P, "rb").read()
    n = len(d)
    print(f"# file {P} len={n}")
    print("\n## 1. printable / padding runs (>=4)")
    for off, ln, s in printable_runs(d):
        print(f"  {off:#06x} len={ln:3d} {s!r}")
    print("  zero/ff runs:")
    z = zero_ff_runs(d)
    print("   none" if not z else "")
    for off, ln, nm in z:
        print(f"  {off:#06x} len={ln:3d} {nm}")

    print("\n## 2. entropy profile")
    for w in (16, 32, 64):
        print(f"  window {w}: ", end="")
        vals = [ent(d[i:i + w]) for i in range(0, n, w)]
        print(" ".join(f"{v:.2f}" for v in vals))
    print(f"  whole-file entropy = {ent(d):.4f} (n={n})")
    # chi-square vs uniform
    c = Counter(d)
    exp = n / 256
    chi = sum((c.get(b, 0) - exp) ** 2 / exp for b in range(256))
    print(f"  chi-square vs uniform256 = {chi:.1f} (df=255; uniform expectation ~255±22.6)")

    print("\n## 3. autocorrelation: count(C[i]==C[i+s]) vs random expectation (n-s)/256")
    for s in (1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1023):
        eq = sum(1 for i in range(n - s) if d[i] == d[i + s])
        exp = (n - s) / 256
        print(f"  s={s:4d}: eq={eq:4d} exp={exp:7.2f} ratio={eq/exp:.2f}")

    print("\n## 4. lane split (2 x 512)")
    a, b = d[:512], d[512:]
    print(f"  entropy a={ent(a):.3f} b={ent(b):.3f}")
    x = bytes(u ^ v for u, v in zip(a, b))
    print(f"  a^b entropy={ent(x):.3f} printable_runs={printable_runs(x, 4)[:5]}")
    eq = sum(1 for u, v in zip(a, b) if u == v)
    print(f"  byte-equal across halves: {eq}/512 (random exp ~2.0)")

    print("\n## 5. header field interpretations")
    hdr = d[8:40]
    print("  hdr hex (0x08..0x27, 32B):", hdr.hex())
    print("  lead-quoted 24B (0x08..0x1f):", d[8:32].hex())
    print("  as 4 x u64 LE:", [hex(struct.unpack('<Q', hdr[i:i+8])[0]) for i in range(0, 32, 8)])
    print("  as 4 x u64 BE:", [hex(struct.unpack('>Q', hdr[i:i+8])[0]) for i in range(0, 32, 8)])
    print("  as 8 x u32 LE:", [hex(struct.unpack('<I', hdr[i:i+4])[0]) for i in range(0, 32, 4)])
    print("  as 8 x u32 BE:", [hex(struct.unpack('>I', hdr[i:i+4])[0]) for i in range(0, 32, 4)])
    # plausible field values
    for name, val in [("size 1024", 1024), ("size 992", 992), ("size 976", 976), ("size 984", 984),
                      ("off 0x300", 0x300), ("len 50", 50), ("addr 0x08040000", 0x08040000),
                      ("addr 0x08000000", 0x08000000), ("rollback 2", 2)]:
        for fmt in ("<I", ">I", "<Q", ">Q"):
            pat = struct.pack(fmt, val)
            if pat in d:
                print(f"  value {name} ({fmt}) found at {[hex(i) for i in range(len(d)) if d.startswith(pat, i)][:5]}")

    print("\n## 6. header vs hashes of body ranges")
    targets = {"d[8:32]": d[8:32], "d[8:24]": d[8:24], "d[8:40]": d[8:40], "d[0x20:0x40]": d[0x20:0x40]}
    ranges = {"32..end": (32, n), "40..end": (40, n), "0x30..end": (0x30, n), "0x20..end": (0x20, n),
              "0x28..end": (0x28, n), "whole": (0, n), "0x300..": (0x300, n)}
    for rn, (s, e) in ranges.items():
        body = d[s:e]
        for alg in ("sha256", "sha1", "md5", "blake2b", "blake2s"):
            h = hashlib.new(alg, body).digest()
            for tn, t in targets.items():
                if h[:len(t)] == t:
                    print(f"  MATCH {alg}({rn}) == {tn}")
    print("  (no MATCH lines above = header is not a plain hash of those ranges)")

    print("\n## 7. known-plaintext keystream at 0x300")
    off = d.find(b"CALIBRATION")
    print("  CALIBRATION at", hex(off))
    end = off + len(b"CALIBRATION: production steering and torque limits")
    pt = d[off:end]
    ks = bytes(d[off + i] ^ pt[i] for i in range(len(pt)))
    print("  keystream = C ^ P =", ks.hex(), "(must be all-zero if region is plaintext)")
    print("  bytes after string:", d[end:end + 16].hex())

    print("\n## 8. 8-byte / 16-byte record hypotheses")
    for rec in (8, 16, 24, 32):
        for start in (0, 8, 32, 40):
            if (n - start) % rec == 0:
                cnt = (n - start) // rec
                print(f"  start={start:#x} rec={rec}B -> {cnt} records")
    print("\n## 9. 16-byte block XOR relationships")
    blocks = [d[i:i + 16] for i in range(0, n, 16)]
    for s in (1, 2, 16, 32):
        diffs = [bytes(a ^ b for a, b in zip(blocks[i], blocks[i + s])) for i in range(len(blocks) - s)]
        print(f"  block[{i}]^block[{i}+{s}] entropy mean={sum(ent(x) for x in diffs)/len(diffs):.3f} "
              f"dup={len(diffs)-len(set(diffs))}")


if __name__ == "__main__":
    main()

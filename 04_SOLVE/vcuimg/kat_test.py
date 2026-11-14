#!/usr/bin/env python3
"""vcu-reference.bin 与 T-BOX 固件双 lane hash（0x08000668）的关系测试。

两个测试：
  A. 记录布局 KAT：把文件切成 32/24/16 B 记录，尝试 A|B|C|out 的各种字段排布，
     看 hash8(A,B,C) 是否等于记录里的 out（60+ 种布局）。
  B. 两两穷举：把全部 8 B 窗口当 seed/key 候选，5 个常量当 C，
     算 hash8(seed, B, C)，看结果是否等于文件里另一个 8 B 窗口（81,920 次）。

判据：若文件是双 lane hash 的 KAT 表 / seed-key 表，必然至少命中 1 次；
实测 0 命中 ⇒ 文件与该算法无关。
"""
import struct
import sys

sys.path.insert(0, "04_SOLVE/fw")
from seedkey import hash8, C_DEV  # noqa: E402

P = "work/bundle2/x/vcu-reference.bin"
D = open(P, "rb").read()
CDEV = struct.pack("<II", *C_DEV)


def test_layout(name, start, rec, fields):
    hits = 0
    total = 0
    for i in range(start, len(D) - rec + 1, rec):
        rb = D[i:i + rec]
        vals = {}
        ok = True
        for f, off, ln in fields:
            if off + ln > len(rb):
                ok = False
                break
            vals[f] = rb[off:off + ln]
        if not ok:
            continue
        A = vals.get("A", b"\0" * 8)
        B = vals.get("B", b"\0" * 8)
        C = vals.get("C", CDEV)
        if len(A) != 8 or len(B) != 8 or len(C) != 8:
            continue
        total += 1
        if hash8(A, B, C) == vals.get("out"):
            hits += 1
            print(f"  HIT {name} rec@{i:#x}")
    return hits, total


def main():
    print("# selftest:", hash8(bytes.fromhex("1122334455667788"),
                               bytes.fromhex("deadbeefcafebabe"), CDEV).hex(),
          "(expect e21faa054c4f8037)")
    print("\n# A) record-layout KAT")
    any_hit = False
    for start in range(0, 33, 8):
        for name, fields in [
            ("rec32 A,B,C,out", [("A", 0, 8), ("B", 8, 8), ("C", 16, 8), ("out", 24, 8)]),
            ("rec32 A,C,B,out", [("A", 0, 8), ("C", 8, 8), ("B", 16, 8), ("out", 24, 8)]),
            ("rec32 out-first", [("out", 0, 8), ("A", 8, 8), ("B", 16, 8), ("C", 24, 8)]),
            ("rec24 A,C,out", [("A", 0, 8), ("C", 8, 8), ("out", 16, 8)]),
            ("rec16 A,out", [("A", 0, 8), ("out", 8, 8)]),
        ]:
            rec = int(name.split()[0][3:])
            h, t = test_layout(f"{name} start={start:#x}", start, rec, fields)
            any_hit |= bool(h)
            print(f"  {name:18s} start={start:#x} records={t:3d} hits={h}")
    print("  ANY HIT:", any_hit)

    print("\n# B) pairwise 8B window sweep")
    W = [D[i:i + 8] for i in range(0, len(D) - 7, 8)]
    winset = {}
    for i, w in enumerate(W):
        winset.setdefault(w, []).append(i)
    consts = {"C_DEV": CDEV, "zero": b"\0" * 8, "ff": b"\xff" * 8,
              "magic": D[0:8], "K5x2": struct.pack("<II", 0xA5A5A5A5, 0xA5A5A5A5)}
    hits = 0
    for name, C in consts.items():
        for i, seed in enumerate(W):
            for j, B in enumerate(W):
                if hash8(seed, B, C) in winset:
                    hits += 1
                    print("  HIT", name, "seedW", i, "BW", j)
    print(f"  windows={len(W)} evaluations={len(W)*len(W)*len(consts)} hits={hits}")


if __name__ == "__main__":
    main()

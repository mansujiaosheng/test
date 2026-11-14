#!/usr/bin/env python3
"""vcu-reference.bin 是否可能是代码 / 是否含 ARM/RV32 结构 —— 与随机对照的统计判定。

判据设计（先写后跑）：
  H_code: 文件（或其某段）是 ARM Thumb 或 RV32IM 代码。
  若 H_code 成立，必然看到以下之一：
    (a) Cortex-M 向量表：某个 4 字节对齐位置 w0 ∈ 0x2000_0000-0x2000_FFFF 且
        w1 ∈ 0x0800_0000-0x0807_FFFF 且 w1 为奇数（Thumb 入口）；
    (b) 函数序言密度显著高于随机：Thumb `push {...,lr}` = 0xB5xx 16-bit，
        `push.w` = E92D xxxx；RV32 `addi sp,sp,-N` = 0x??010113，`sw ra` = 0x??112E23；
    (c) 反汇编出的 32-bit 指令占比 / 合法指令率显著高于随机。
  实测若与 200 份等长随机对照同分布 ⇒ [否定] H_code。

运行：python code_plausibility.py
"""
import random
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_ARCH_RISCV, CS_MODE_RISCV32

P = "work/bundle2/x/vcu-reference.bin"


def vector_table_hits(d):
    hits = []
    for off in range(0, len(d) - 8 + 1, 2):
        w0, w1 = struct.unpack_from("<II", d, off)
        if 0x20000000 <= w0 <= 0x2000FFFF and 0x08000000 <= w1 <= 0x0807FFFF and (w1 & 1):
            hits.append((off, w0, w1))
    return hits


def thumb_stats(d, base=0x08040000):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = False
    ins = list(md.disasm(d, base))
    n = len(ins)
    # 统计常见序言/结构
    push_lr = sum(1 for i in ins if i.mnemonic == "push" and "lr" in i.op_str)
    push_w = sum(1 for i in ins if i.mnemonic == "push.w" or (i.mnemonic == "push" and "r" in i.op_str))
    bl = sum(1 for i in ins if i.mnemonic.startswith("bl"))
    ldr_lit = sum(1 for i in ins if i.mnemonic.startswith("ldr") and "pc" in i.op_str)
    wide = sum(1 for i in ins if i.size == 4)
    # 指令覆盖率：被反汇编器接受为合法指令的字节比例
    covered = sum(i.size for i in ins)
    return {"insns": n, "push_lr": push_lr, "bl": bl, "ldr_pc": ldr_lit,
            "wide": wide, "wide_ratio": wide / n if n else 0, "coverage": covered / len(d)}


def rv_stats(d, base=0x08040000):
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
    md.detail = False
    ins = list(md.disasm(d, base))
    n = len(ins)
    sp_adj = sum(1 for i in ins if i.mnemonic == "addi" and i.op_str.startswith("sp, sp, -"))
    sw_ra = sum(1 for i in ins if i.mnemonic in ("sw", "sd") and "ra" in i.op_str and "sp" in i.op_str)
    ret = sum(1 for i in ins if i.mnemonic in ("ret", "jalr") and "zero" in i.op_str)
    covered = sum(i.size for i in ins)
    return {"insns": n, "sp_adj": sp_adj, "sw_ra": sw_ra, "ret": ret,
            "coverage": covered / len(d)}


def summarize(name, d):
    t = thumb_stats(d)
    r = rv_stats(d)
    v = vector_table_hits(d)
    return (f"{name}: ARM_insns={t['insns']} push_lr={t['push_lr']} bl={t['bl']} "
            f"ldr_pc={t['ldr_pc']} wide={t['wide']}({t['wide_ratio']:.2f}) cov={t['coverage']:.2f} | "
            f"RV_insns={r['insns']} sp_adj={r['sp_adj']} sw_ra={r['sw_ra']} ret={r['ret']} "
            f"cov={r['coverage']:.2f} | vec={v}")


def main():
    d = open(P, "rb").read()
    print("# 1) real file")
    print("  " + summarize("vcu-reference", d))
    print()
    print("# 2) 200 random 1024B controls (same metrics)")
    random.seed(1234)
    for key in ["push_lr", "bl", "ldr_pc", "wide_ratio", "coverage"]:
        vals = []
        for _ in range(200):
            r = bytes(random.getrandbits(8) for _ in range(1024))
            vals.append(thumb_stats(r)[key])
        vals.sort()
        mine = thumb_stats(d)[key]
        rank = sum(1 for v in vals if v <= mine)
        print(f"  {key:12s} mine={mine:.3f} random[min={vals[0]:.3f} p05={vals[10]:.3f} "
              f"median={vals[100]:.3f} p95={vals[190]:.3f} max={vals[-1]:.3f}] pctile={rank/2:.1f}%")
    print()
    print("# 3) random control vector-table false positives")
    fp = 0
    for _ in range(200):
        r = bytes(random.getrandbits(8) for _ in range(1024))
        if vector_table_hits(r):
            fp += 1
    print(f"  random controls with any vector-table hit: {fp}/200; real file: {vector_table_hits(d)}")


if __name__ == "__main__":
    main()

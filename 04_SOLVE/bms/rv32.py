#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rv32.py -- RV32IM 镜像分析器（赛题 08：从 BMS 固件里挖 root key）

能力
----
    --disasm       反汇编（优先 capstone，缺失/不可用时走内置手写解码器）
    --strings      >=4 字节可打印 ASCII 串
    --entropy      256 字节分块熵，标出高熵区（加密/压缩/密钥区）
    --find-const   滑动窗口找高熵定长常量（16/32 字节 = 候选 key）
    --sha256       整文件 + 各分段 SHA256
    --analyze      判定"这是不是 RV32IM 镜像"并给分项证据（默认动作）

RV32 判定依据（本文件实现的就是这一组判据）
-------------------------------------------
    1. 4 字节对齐字里低 2 位 == 0b11 的比例（无 C 扩展时 RV32IM 指令恒为该形态；
       随机数据约 25%，真实代码段接近 100%）。
    2. `13 00 00 00`（nop = addi x0,x0,0）与 `67 80 00 00`（ret = jalr x0,0(x1)）
       的出现频度 —— 这两个 32 位常量在随机数据里基本不可能出现。
    3. `0x73` 结尾（SYSTEM opcode）的 ecall/ebreak/mret 计数。
    4. opcode 分布里 load(0x03)/store(0x23)/OP(0x33)/OP-IMM(0x13) 是否成规模，
       以及 M 扩展（funct7==0x01 的 mul/div 族）是否出现 → 区分 RV32I 与 RV32IM。
    5. 合法指令率（手写解码器逐字判定）。

用法
----
    python rv32.py --self-test
    python rv32.py bms.bin --analyze
    python rv32.py --disasm bms.bin --base 0x80000000 --start 0 --count 80
    python rv32.py bms.bin --entropy --find-const --size 32 --strings --sha256
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from collections import Counter

VERSION = "1.0"

REGS = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
        "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6"]

OPCODE_NAMES = {
    0x37: "LUI", 0x17: "AUIPC", 0x6F: "JAL", 0x67: "JALR",
    0x63: "BRANCH", 0x03: "LOAD", 0x23: "STORE", 0x13: "OP-IMM",
    0x33: "OP", 0x0F: "MISC-MEM", 0x73: "SYSTEM", 0x1B: "OP-IMM-32(RV64)",
    0x3B: "OP-32(RV64)",
}


# --------------------------------------------------------------------------- #
# 熵 / 工具
# --------------------------------------------------------------------------- #

def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in Counter(data).values())


def word_entropy_ok(win: bytes, ratio: float = 0.90, allow_printable: bool = False) -> bool:
    if not win:
        return False
    if shannon(win) < ratio * math.log2(min(len(win), 256)):
        return False
    if len(set(win)) < max(2, int(len(win) * 0.60)):
        return False
    if not allow_printable and all(0x20 <= b < 0x7F for b in win):
        return False
    return True


# --------------------------------------------------------------------------- #
# RV32IM 手写解码器（兜底路径，也是"合法指令率"判据的实现）
# --------------------------------------------------------------------------- #

def _sext(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def _hi(value: int) -> str:
    """统一十六进制格式，负数带 -0x。"""
    return ("-0x%x" % -value) if value < 0 else ("0x%x" % value)


def _r(rd, rs1, rs2):
    return "%s, %s, %s" % (REGS[rd], REGS[rs1], REGS[rs2])


def _i(rd, rs1, imm):
    return "%s, %s, %s" % (REGS[rd], REGS[rs1], _hi(imm))


def _mem(imm, rs1):
    """内存操作数 imm(rs1)。"""
    return "%s(%s)" % (_hi(imm) if imm else "0", REGS[rs1])


def _load(rd, imm, rs1):
    return "%s, %s" % (REGS[rd], _mem(imm, rs1))


def _store(rs2, imm, rs1):
    return "%s, %s" % (REGS[rs2], _mem(imm, rs1))


def decode_word(w: int, pc: int = 0):
    """解码一个 32 位 RV32IM 指令。

    返回 dict：{mnemonic, operands, size, kind, note} 或 None（非法/非 RV32IM）。
    kind ∈ nop/ret/ecall/ebreak/mret/jump/branch/load/store/alu/csr/fence/other
    """
    if (w & 0x3) != 0x3:
        # 低 2 位不是 11 → 16 位压缩指令（C 扩展）或对齐垃圾
        return {"mnemonic": ".hword", "operands": "0x%04x" % (w & 0xFFFF),
                "size": 2, "kind": "compressed",
                "note": "16-bit（C 扩展或非指令数据）"}

    op = w & 0x7F
    rd = (w >> 7) & 0x1F
    f3 = (w >> 12) & 0x7
    rs1 = (w >> 15) & 0x1F
    rs2 = (w >> 20) & 0x1F
    f7 = (w >> 25) & 0x7F
    imm_i = _sext(w >> 20, 12)
    imm_s = _sext(((w >> 25) << 5) | ((w >> 7) & 0x1F), 12)
    imm_b = _sext((((w >> 31) & 1) << 12) | (((w >> 7) & 1) << 11) |
                  (((w >> 25) & 0x3F) << 5) | (((w >> 8) & 0xF) << 1), 13)
    imm_u = w & 0xFFFFF000
    imm_j = _sext((((w >> 31) & 1) << 20) | (((w >> 12) & 0xFF) << 12) |
                  (((w >> 20) & 1) << 11) | (((w >> 21) & 0x3FF) << 1), 21)

    def mk(m, o, kind, note=""):
        return {"mnemonic": m, "operands": o, "size": 4, "kind": kind, "note": note}

    if op == 0x37:
        return mk("lui", "%s, %s" % (REGS[rd], _hi(w >> 12)), "alu")
    if op == 0x17:
        return mk("auipc", "%s, %s" % (REGS[rd], _hi(w >> 12)), "alu")

    if op == 0x6F:
        target = pc + imm_j
        if rd == 0:
            # jal x0, off 的标准伪指令就是 j off（无论 off 是否为 0）
            return mk("j", _hi(target), "jump")
        if rd == 1:
            return mk("jal", _hi(target), "jump")
        return mk("jal", "%s, %s" % (REGS[rd], _hi(target)), "jump")

    if op == 0x67:
        if f3 != 0:
            return None
        if rd == 0 and rs1 == 1 and imm_i == 0:
            return mk("ret", "", "ret")
        if rd == 0:
            return mk("jr", _mem(imm_i, rs1), "jump")
        return mk("jalr", "%s, %s" % (REGS[rd], _mem(imm_i, rs1)), "jump")

    if op == 0x63:
        names = {0: "beq", 1: "bne", 4: "blt", 5: "bge", 6: "bltu", 7: "bgeu"}
        if f3 not in names:
            return None
        return mk(names[f3], "%s, %s, %s" % (REGS[rs1], REGS[rs2], _hi(pc + imm_b)),
                  "branch")

    if op == 0x03:
        names = {0: "lb", 1: "lh", 2: "lw", 4: "lbu", 5: "lhu"}
        if f3 not in names:
            return None
        return mk(names[f3], _load(rd, imm_i, rs1), "load")

    if op == 0x23:
        names = {0: "sb", 1: "sh", 2: "sw"}
        if f3 not in names:
            return None
        return mk(names[f3], _store(rs2, imm_s, rs1), "store")

    if op == 0x13:
        if f3 == 0:
            if rd == 0 and rs1 == 0 and imm_i == 0:
                return mk("nop", "", "nop")
            if rd == 0 and imm_i == 0:
                return mk("mv", REGS[rs1], "alu")  # 便捷：addi x0,rs,0 不是标准 mv
            return mk("addi", _i(rd, rs1, imm_i), "alu")
        if f3 == 2:
            return mk("slti", _i(rd, rs1, imm_i), "alu")
        if f3 == 3:
            return mk("sltiu", _i(rd, rs1, imm_i), "alu")
        if f3 == 4:
            return mk("xori", _i(rd, rs1, imm_i), "alu")
        if f3 == 6:
            return mk("ori", _i(rd, rs1, imm_i), "alu")
        if f3 == 7:
            return mk("andi", _i(rd, rs1, imm_i), "alu")
        if f3 == 1:
            if f7 != 0:
                return None
            return mk("slli", _i(rd, rs1, (w >> 20) & 0x1F), "alu")
        if f3 == 5:
            sh = (w >> 20) & 0x1F
            if f7 == 0x00:
                return mk("srli", _i(rd, rs1, sh), "alu")
            if f7 == 0x20:
                return mk("srai", _i(rd, rs1, sh), "alu")
            return None
        return None

    if op == 0x33:
        if f7 == 0x00:
            names = {0: "add", 1: "sll", 2: "slt", 3: "sltu",
                     4: "xor", 5: "srl", 6: "or", 7: "and"}
            return mk(names[f3], _r(rd, rs1, rs2), "alu")
        if f7 == 0x20:
            if f3 == 0:
                return mk("sub", _r(rd, rs1, rs2), "alu")
            if f3 == 5:
                return mk("sra", _r(rd, rs1, rs2), "alu")
            return None
        if f7 == 0x01:
            names = {0: "mul", 1: "mulh", 2: "mulhsu", 3: "mulhu",
                     4: "div", 5: "divu", 6: "rem", 7: "remu"}
            return mk(names[f3], _r(rd, rs1, rs2), "alu", note="M 扩展")
        return None

    if op == 0x0F:
        if f3 == 0:
            pred = (w >> 24) & 0xF
            succ = (w >> 20) & 0xF
            bits = ""
            for i, nm in ((3, "i"), (2, "o"), (1, "r"), (0, "w")):
                if pred & (1 << i):
                    bits += nm
            out = ""
            for i, nm in ((3, "i"), (2, "o"), (1, "r"), (0, "w")):
                if succ & (1 << i):
                    out += nm
            return mk("fence", "%s, %s" % (bits or "0", out or "0"), "fence")
        if f3 == 1:
            return mk("fence.i", "", "fence")
        return None

    if op == 0x73:
        csr = w >> 20
        if f3 == 0:
            if rd == 0 and rs1 == 0:
                if csr == 0x000:
                    return mk("ecall", "", "ecall")
                if csr == 0x001:
                    return mk("ebreak", "", "ebreak")
                if csr == 0x302:
                    return mk("mret", "", "mret")
                if csr == 0x102:
                    return mk("sret", "", "mret")
                if csr == 0x105:
                    return mk("wfi", "", "other")
                return mk("system", _hi(csr), "other", note="SYSTEM 保留编码")
            return None
        names = {1: "csrrw", 2: "csrrs", 3: "csrrc",
                 5: "csrrwi", 6: "csrrsi", 7: "csrrci"}
        if f3 in names:
            src = _hi(csr) + (", " + str(rs1) if f3 >= 5 else ", " + REGS[rs1])
            return mk(names[f3], "%s, %s" % (REGS[rd], src), "csr")
        return None

    if op in (0x1B, 0x3B):
        return None  # RV64 专用，RV32 上非法

    return None


def opcode_of(w: int) -> int:
    return w & 0x7F


# --------------------------------------------------------------------------- #
# capstone 路径
# --------------------------------------------------------------------------- #

def capstone_available() -> bool:
    try:
        from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def disasm_capstone(data: bytes, base: int = 0, start: int = 0, count: int = 64):
    """逐条反汇编。

    注意：capstone 的 `md.disasm()` 遇到第一条非法编码就**整体停止**（线性扫描语义），
    直接用它扫固件会在第一段数据/常量池处静默截断。这里改成逐条喂 4 字节，
    非法字记为 `.word` 并跳过，保证覆盖到文件末尾。
    """
    try:
        from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32
    except Exception:  # noqa: BLE001
        return None
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
    md.detail = False
    out = []
    off = start
    n = len(data)
    while off < n and len(out) < count:
        addr = base + off
        if (data[off] & 0x3) != 0x3:
            if off + 2 > n:
                break
            hw = int.from_bytes(data[off:off + 2], "little")
            out.append({"addr": addr, "size": 2, "bytes": data[off:off + 2].hex(),
                        "text": ".hword 0x%04x" % hw, "mnemonic": ".hword",
                        "op_str": "0x%04x" % hw, "valid": False})
            off += 2
            continue
        if off + 4 > n:
            break
        chunk = data[off:off + 4]
        ins = next(iter(md.disasm(chunk, addr)), None)
        if ins is None:
            w = int.from_bytes(chunk, "little")
            out.append({"addr": addr, "size": 4, "bytes": chunk.hex(),
                        "text": ".word 0x%08x" % w, "mnemonic": ".word",
                        "op_str": "0x%08x" % w, "valid": False})
            off += 4
            continue
        out.append({"addr": addr, "size": ins.size, "bytes": ins.bytes.hex(),
                    "text": ins.mnemonic + ((" " + ins.op_str) if ins.op_str else ""),
                    "mnemonic": ins.mnemonic, "op_str": ins.op_str, "valid": True})
        off += (ins.size or 4)
    return out


def disasm_manual(data: bytes, base: int = 0, start: int = 0, count: int = 64):
    out = []
    off = start
    pc = base + start
    n = len(data)
    while off + 2 <= n and len(out) < count:
        if (data[off] & 0x3) != 0x3:
            w16 = int.from_bytes(data[off:off + 2], "little")
            d = {"mnemonic": ".hword", "operands": "0x%04x" % w16, "size": 2,
                 "kind": "compressed", "note": "16-bit"}
            raw = data[off:off + 2].hex()
        else:
            if off + 4 > n:
                break
            w = int.from_bytes(data[off:off + 4], "little")
            d = decode_word(w, pc)
            raw = data[off:off + 4].hex()
            if d is None:
                d = {"mnemonic": ".word", "operands": "0x%08x" % w, "size": 4,
                     "kind": "invalid", "note": "非法/非 RV32IM 编码"}
        out.append({"addr": pc, "size": d["size"], "bytes": raw,
                    "text": d["mnemonic"] + ((" " + d["operands"]) if d["operands"] else ""),
                    "mnemonic": d["mnemonic"], "op_str": d["operands"],
                    "kind": d["kind"], "note": d.get("note", "")})
        off += d["size"]
        pc += d["size"]
    return out


# --------------------------------------------------------------------------- #
# 分析动作
# --------------------------------------------------------------------------- #

def extract_strings(data: bytes, min_len: int = 4, limit: int = 0):
    out = []
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F or b in (0x09,):
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append({"offset": start, "len": len(cur),
                            "text": cur.decode("latin-1")})
                if limit and len(out) >= limit:
                    return out
            cur = bytearray()
    if len(cur) >= min_len:
        out.append({"offset": start, "len": len(cur), "text": cur.decode("latin-1")})
    return out


def block_entropy(data: bytes, block: int = 256):
    out = []
    for off in range(0, len(data), block):
        chunk = data[off:off + block]
        out.append({"offset": off, "len": len(chunk),
                    "entropy": shannon(chunk), "hi": shannon(chunk) >= 7.0})
    return out


def high_entropy_ranges(blocks, min_blocks: int = 1):
    ranges = []
    cur = None
    for b in blocks:
        if b["hi"]:
            if cur is None:
                cur = {"start": b["offset"], "end": b["offset"] + b["len"]}
            else:
                cur["end"] = b["offset"] + b["len"]
        else:
            if cur is not None:
                ranges.append(cur)
                cur = None
    if cur is not None:
        ranges.append(cur)
    return [r for r in ranges if (r["end"] - r["start"]) >= min_blocks * 1]


def _snap_aligned(data: bytes, i: int, size: int, ratio: float):
    """16 字节对齐优先：命中点附近若有更好对齐且熵更高的窗口，就吸附过去。

    动机：常量池里的 32 字节 key 是 16 对齐的，而滑动窗口会先在
    "4 字节零 + 28 字节 key" 这种跨边界窗口上命中（熵略低但仍过阈）。
    吸附后拿到的才是**真实常量起点**，否则后续 grow/切分都会偏。
    """
    best, best_e = i, shannon(data[i:i + size])
    base = (i // 16) * 16
    for cand in (base, base + 16):
        if cand == i or cand < 0 or cand + size > len(data):
            continue
        win = data[cand:cand + size]
        if not word_entropy_ok(win, ratio):
            continue
        e = shannon(win)
        if e > best_e:
            best, best_e = cand, e
    return best


def find_constants(data: bytes, size: int = 16, step: int = 4,
                   ratio: float = 0.95, limit: int = 0):
    """滑动窗口找高熵定长常量（候选 key）。命中后跳过整窗，避免同常量刷出上百副本。"""
    out = []
    n = len(data)
    i = 0
    while i + size <= n:
        win = data[i:i + size]
        if word_entropy_ok(win, ratio):
            pos = _snap_aligned(data, i, size, ratio)
            out.append({"offset": pos, "value": data[pos:pos + size].hex(),
                        "entropy": shannon(data[pos:pos + size]),
                        "aligned16": (pos % 16 == 0)})
            i = pos + size
            if limit and len(out) >= limit:
                break
        else:
            i += step
    return out


def sha256_report(data: bytes, blocks: int = 0):
    rep = {"whole": {"len": len(data), "sha256": hashlib.sha256(data).hexdigest()},
           "segments": [], "blocks": []}
    hl = tl = None
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import derive_key  # 复用同一套结构探测，保证 salt 分界与 derive_key 一致
        st = derive_key.probe_structure(data)
        hl, tl = st.get("header_len"), st.get("trailer_len") or 0
        if hl:
            rep["segments"].append({"name": "header", "offset": 0, "len": hl,
                                    "sha256": hashlib.sha256(data[:hl]).hexdigest()})
            end = len(data) - tl if tl else len(data)
            rep["segments"].append({"name": "payload", "offset": hl, "len": max(0, end - hl),
                                    "sha256": hashlib.sha256(data[hl:end]).hexdigest()})
            if tl:
                rep["segments"].append({"name": "trailer", "offset": len(data) - tl, "len": tl,
                                        "sha256": hashlib.sha256(data[len(data) - tl:]).hexdigest()})
    except Exception as e:  # noqa: BLE001
        rep["segments"].append({"name": "probe_error", "error": str(e)})
    if blocks:
        for off in range(0, len(data), blocks):
            chunk = data[off:off + blocks]
            rep["blocks"].append({"offset": off, "len": len(chunk),
                                  "sha256": hashlib.sha256(chunk).hexdigest()})
    return rep


def analyze_rv32(data: bytes, base: int = 0):
    """判定是不是 RV32IM 镜像，输出分项证据与结论。"""
    n = len(data)
    nwords = n // 4
    rep = {"size": n, "n_words": nwords, "evidence": {}, "verdict": "", "score": 0}

    if nwords == 0:
        rep["verdict"] = "文件不足 4 字节，无法判定"
        return rep

    words = [int.from_bytes(data[i * 4:i * 4 + 4], "little") for i in range(nwords)]
    p32 = sum(1 for w in words if (w & 3) == 3) / nwords
    nop = sum(1 for w in words if w == 0x00000013)
    ret = sum(1 for w in words if w == 0x00008067)
    two_op = sum(1 for w in words if w in (0x00000013, 0x00008067))
    system = sum(1 for w in words if (w & 0x7F) == 0x73)
    m_ext = sum(1 for w in words if (w & 0x7F) == 0x33 and ((w >> 25) & 0x7F) == 0x01)
    loads = sum(1 for w in words if (w & 0x7F) == 0x03)
    stores = sum(1 for w in words if (w & 0x7F) == 0x23)
    op_imm = sum(1 for w in words if (w & 0x7F) == 0x13)
    op = sum(1 for w in words if (w & 0x7F) == 0x33)
    branches = sum(1 for w in words if (w & 0x7F) == 0x63)
    jumps = sum(1 for w in words if (w & 0x7F) in (0x6F, 0x67))

    legal = 0
    for i, w in enumerate(words):
        if (w & 3) != 3:
            continue
        if decode_word(w, base + i * 4) is not None:
            legal += 1
    legal_rate = legal / nwords

    op_hist = Counter()
    for w in words:
        op_hist[OPCODE_NAMES.get(w & 0x7F, "0x%02x" % (w & 0x7F))] += 1

    rep["evidence"] = {
        "p_align32": round(p32, 4),
        "nop_13_00_00_00": nop,
        "ret_67_80_00_00": ret,
        "system_0x73": system,
        "m_ext_funct7_0x01": m_ext,
        "load_0x03": loads,
        "store_0x23": stores,
        "op_imm_0x13": op_imm,
        "op_0x33": op,
        "branch_0x63": branches,
        "jump_0x6f_0x67": jumps,
        "legal_rate": round(legal_rate, 4),
        "opcode_hist": dict(op_hist.most_common(10)),
    }

    score = 0
    reasons = []
    if p32 >= 0.98:
        score += 3
        reasons.append("4 字节对齐字 100%% 呈 0b11 形态（p=%.4f）" % p32)
    elif p32 >= 0.90:
        score += 2
        reasons.append("对齐率 %.2f ≥ 0.90" % p32)
    elif p32 <= 0.30:
        reasons.append("对齐率 %.2f ≈ 随机数据水平（0.25）→ 非 RV32 代码" % p32)
    if two_op >= 2:
        score += 3
        reasons.append("出现 nop(%d) / ret(%d) 两个 RV32 特有 32 位常量" % (nop, ret))
    elif p32 >= 0.9:
        score += 1
        reasons.append("对齐率够高但 nop/ret 未命中（可能是数据段或被裁剪）")
    if system >= 1:
        score += 1
        reasons.append("出现 SYSTEM(0x73) 指令 %d 条" % system)
    if loads + stores >= max(2, nwords // 100):
        score += 1
        reasons.append("load/store 合计 %d 条，成规模" % (loads + stores))
    if legal_rate >= 0.95:
        score += 2
        reasons.append("手写解码器合法率 %.2f" % legal_rate)
    elif legal_rate >= 0.80:
        score += 1
        reasons.append("合法率 %.2f" % legal_rate)
    rep["score"] = score
    rep["reasons"] = reasons

    if p32 <= 0.35 and two_op == 0:
        rep["verdict"] = "不是 RV32 代码（高熵/非代码数据）"
    elif score >= 7:
        rep["verdict"] = ("是 RV32%s 镜像（置信度高，score=%d）"
                          % ("IM" if m_ext else "I", score))
    elif score >= 4:
        rep["verdict"] = "疑似 RV32%s 镜像（置信度中，score=%d；建议看 --disasm 抽查）" % (
            "IM" if m_ext else "I", score)
    else:
        rep["verdict"] = "无法判定（score=%d，证据不足）" % score
    return rep


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #
# 注意：下面的编码函数按 RISC-V 规范字段布局**独立**手写，不复用解码器的抽取逻辑，
# 这样"编码器→解码器"往返才有一定独立性；再用 capstone 做第三方交叉校验。

def _enc_r(f7, rs2, rs1, f3, rd, op=0x33):
    return (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op


def _enc_i(imm, rs1, f3, rd, op):
    return ((imm & 0xFFF) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op


def _enc_s(imm, rs2, rs1, f3, op=0x23):
    imm &= 0xFFF
    return (((imm >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15) | \
           (f3 << 12) | ((imm & 0x1F) << 7) | op


def _enc_b(imm, rs2, rs1, f3, op=0x63):
    imm &= 0x1FFF
    return (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3F) << 25) | (rs2 << 20) | \
           (rs1 << 15) | (f3 << 12) | (((imm >> 1) & 0xF) << 8) | \
           (((imm >> 11) & 1) << 7) | op


def _enc_u(imm20, rd, op):
    return ((imm20 & 0xFFFFF) << 12) | (rd << 7) | op


def _enc_j(imm, rd, op=0x6F):
    imm &= 0x1FFFFF
    return (((imm >> 20) & 1) << 31) | (((imm >> 1) & 0x3FF) << 21) | \
           (((imm >> 11) & 1) << 20) | (((imm >> 12) & 0xFF) << 12) | (rd << 7) | op


class Fail(AssertionError):
    pass


def run_self_test() -> int:
    results = []

    def check(label, fn):
        try:
            fn()
            results.append((label, "PASS", ""))
        except Fail as e:
            results.append((label, "FAIL", str(e)))
        except Exception as e:  # noqa: BLE001
            results.append((label, "ERROR", "%s: %s" % (type(e).__name__, e)))

    def dec(w, pc=0):
        d = decode_word(w, pc)
        if d is None:
            return None
        return d["mnemonic"] + ((" " + d["operands"]) if d["operands"] else "")

    # ---- 1. 固定向量：RV32 特有形态 ----
    def t_fixed():
        cases = [
            (0x00000013, "nop"),
            (0x00008067, "ret"),
            (0x00000073, "ecall"),
            (0x00100073, "ebreak"),
            (0x30200073, "mret"),
        ]
        for w, want in cases:
            got = dec(w)
            if got != want:
                raise Fail("word 0x%08x: got %r want %r" % (w, got, want))
    check("固定向量 nop/ret/ecall/ebreak/mret", t_fixed)

    # ---- 2. 编码器 → 解码器 往返（RV32I 全覆盖 + M 扩展）----
    def t_roundtrip():
        table = []
        # R-type ALU
        for f3, nm in ((0, "add"), (1, "sll"), (2, "slt"), (3, "sltu"),
                       (4, "xor"), (5, "srl"), (6, "or"), (7, "and")):
            table.append((_enc_r(0x00, 3, 2, f3, 5), "%s t0, sp, gp" % nm))
        table.append((_enc_r(0x20, 3, 2, 0, 5), "sub t0, sp, gp"))
        table.append((_enc_r(0x20, 3, 2, 5, 5), "sra t0, sp, gp"))
        # M 扩展
        for f3, nm in ((0, "mul"), (1, "mulh"), (2, "mulhsu"), (3, "mulhu"),
                       (4, "div"), (5, "divu"), (6, "rem"), (7, "remu")):
            table.append((_enc_r(0x01, 3, 2, f3, 5), "%s t0, sp, gp" % nm))
        # I-type
        table.append((_enc_i(4, 2, 0, 5, 0x13), "addi t0, sp, 0x4"))
        table.append((_enc_i(-8, 2, 0, 5, 0x13), "addi t0, sp, -0x8"))
        table.append((_enc_i(0x1F, 2, 1, 5, 0x13), "slli t0, sp, 0x1f"))
        table.append((_enc_i(0x00, 2, 5, 5, 0x13), "srli t0, sp, 0x0"))
        table.append((_enc_i(0x400 | 3, 2, 5, 5, 0x13), "srai t0, sp, 0x3"))
        table.append((_enc_i(7, 2, 7, 5, 0x13), "andi t0, sp, 0x7"))
        # load / store
        table.append((_enc_i(4, 3, 2, 1, 0x03), "lw ra, 0x4(gp)"))
        table.append((_enc_i(0, 3, 0, 10, 0x03), "lb a0, 0(gp)"))
        table.append((_enc_i(-4, 3, 1, 11, 0x03), "lh a1, -0x4(gp)"))
        table.append((_enc_s(8, 5, 3, 2), "sw t0, 0x8(gp)"))
        table.append((_enc_s(0, 5, 3, 0), "sb t0, 0(gp)"))
        # branch / jump
        table.append((_enc_b(16, 3, 2, 0), "beq sp, gp, 0x10"))
        table.append((_enc_b(-4, 3, 2, 1), "bne sp, gp, -0x4"))
        table.append((_enc_j(0x20, 1), "jal 0x20"))
        table.append((_enc_j(0x20, 0), "j 0x20"))
        table.append((_enc_j(0, 0), "j 0x0"))
        table.append((_enc_i(0, 1, 0, 0, 0x67), "ret"))
        table.append((_enc_i(0, 1, 0, 1, 0x67), "jalr ra, 0(ra)"))
        # U-type
        table.append((_enc_u(0x12345, 5, 0x37), "lui t0, 0x12345"))
        table.append((_enc_u(0x12345, 5, 0x17), "auipc t0, 0x12345"))
        # SYSTEM
        table.append((_enc_i(0x000, 0, 0, 0, 0x73), "ecall"))
        table.append((_enc_i(0x001, 0, 0, 0, 0x73), "ebreak"))
        table.append((_enc_i(0x302, 0, 0, 0, 0x73), "mret"))
        table.append((_enc_i(0x300, 0, 1, 5, 0x73), "csrrw t0, 0x300, zero"))
        # FENCE
        table.append((_enc_i(0x0FF, 0, 0, 0, 0x0F), "fence iorw, iorw"))

        bad = []
        for w, want in table:
            got = dec(w)
            if got != want:
                bad.append("0x%08x: got %r want %r" % (w, got, want))
        if bad:
            raise Fail("%d/%d 条往返不符:\n  %s"
                       % (len(bad), len(table), "\n  ".join(bad)))
    check("编码器→解码器 往返（RV32I 全覆盖 + M 扩展）", t_roundtrip)

    # ---- 3. 非法编码必须被拒（RV64 专用 opcode / 保留 funct3）----
    def t_illegal():
        cases = [
            (_enc_r(0x02, 3, 2, 0, 5, op=0x33), "OP funct7=0x02 保留"),
            (_enc_i(0, 2, 3, 5, 0x03), "load funct3=3 保留（LD 是 RV64）"),
            (_enc_i(0x400, 2, 1, 5, 0x13), "slli funct7!=0 保留"),
            (_enc_i(0x420, 2, 5, 5, 0x13), "srli/srai funct7=0x21 保留"),
            (_enc_b(0, 3, 2, 2), "branch funct3=2 保留"),
            (_enc_r(0, 3, 2, 0, 5, op=0x3B), "RV64 OP-32"),
            (_enc_i(0, 0, 0, 0, 0x1B), "RV64 OP-IMM-32"),
        ]
        for w, why in cases:
            if decode_word(w, 0) is not None:
                raise Fail("0x%08x (%s) 应判非法，实际解码为 %r"
                           % (w, why, dec(w)))
        # 反向守卫：sltiu 是合法的（我曾把它误当保留编码，这里钉住）
        if dec(_enc_i(0, 2, 3, 5, 0x13)) != "sltiu t0, sp, 0x0":
            raise Fail("sltiu（OP-IMM funct3=3）必须合法")
    check("非法/非 RV32IM 编码必须被拒", t_illegal)

    # ---- 4. 与 capstone 交叉校验（第三方实现）----
    def t_capstone():
        if not capstone_available():
            return  # 未装则跳过，不是失败
        import random
        rnd = random.Random(0xB5)
        ops = [0x37, 0x17, 0x6F, 0x67, 0x63, 0x03, 0x23, 0x13, 0x33, 0x0F, 0x73]
        corpus = []
        for _ in range(400):
            o = rnd.choice(ops)
            w = (rnd.getrandbits(25) << 7) | o | 0x3
            corpus.append(w)
        # 补上确定性的高频形态
        corpus += [0x00000013, 0x00008067, 0x00000073, 0x30200073,
                   0xFE010113, 0x00112E23, 0x00813023, 0x0000006F]
        blob = b"".join(w.to_bytes(4, "little") for w in corpus)
        cap = disasm_capstone(blob, 0, 0, len(corpus))
        man = disasm_manual(blob, 0, 0, len(corpus))
        if cap is None:
            return
        # 比对"两边都认为是合法 RV32 指令"的项。
        # 归一化处理（否则会把表示法差异误报成解码错误，掩盖真问题）：
        #   - capstone 会把 blt zero,rs / bge zero,rs 打印成 bgtz/blez 伪指令
        #   - capstone 把 jr imm(rs1) 打印成 jalr zero, rs1, imm（三操作数）
        #   - capstone 分支偏移是**相对值**，本解码器给的是**绝对目标地址**
        import re as _re

        ALIAS = {"bgtz": ("blt", True), "blez": ("bge", True),
                 "beqz": ("beq", False), "bnez": ("bne", False),
                 "bltz": ("blt", False), "bgez": ("bge", False),
                 "mv": ("addi", False)}

        def regs_of(txt):
            return set(x for x in txt.replace(",", " ").replace("(", " ")
                       .replace(")", " ").split() if x in REGS)

        def nums_of(txt):
            return [int(t, 0) for t in _re.findall(r"-?0x[0-9a-fA-F]+|-?\d+", txt)]

        def key_of(mnem, regs):
            if mnem == "jr":                    # jr imm(rs1) == jalr zero, imm(rs1)
                return ("jalr", frozenset(set(regs) | {"zero"}))
            if mnem == "ret":                   # ret == jalr zero, 0(ra)
                return ("jalr", frozenset({"zero", "ra"}))
            if mnem == "j":
                return ("jal", frozenset(set(regs) | {"zero"}))
            if mnem in ALIAS:
                base, _zf = ALIAS[mnem]
                return (base, frozenset(set(regs) | {"zero"}))
            return (mnem, frozenset(regs))

        checked = 0
        mism = []
        for c, m in zip(cap, man):
            if m["kind"] == "invalid" or not c.get("valid"):
                continue
            ck = key_of(c["mnemonic"], regs_of(c["op_str"]))
            mk = key_of(m["mnemonic"], regs_of(m["op_str"]))
            if ck != mk:
                mism.append("@0x%x key cap=%r man=%r (text cap=%r man=%r)"
                            % (c["addr"], ck, mk, c["text"], m["text"]))
                continue
            # 立即数：ALU/load/store 必须逐值一致；branch 允许相对/绝对两种表示
            if m["kind"] in ("alu", "load", "store"):
                if nums_of(m["op_str"]) != nums_of(c["op_str"]):
                    mism.append("@0x%x imm cap=%s man=%s (%r vs %r)"
                                % (c["addr"], nums_of(c["op_str"]),
                                   nums_of(m["op_str"]), c["text"], m["text"]))
                    continue
            elif m["kind"] == "branch":
                mn, cn = nums_of(m["op_str"]), nums_of(c["op_str"])
                if mn and cn:
                    rel = mn[-1] - c["addr"]
                    if cn[-1] not in (rel, mn[-1]):
                        mism.append("@0x%x branch off cap=%s man=%s(rel=%s)"
                                    % (c["addr"], cn[-1], mn[-1], rel))
                        continue
            checked += 1
        if mism:
            raise Fail("%d 处不一致（共比对 %d 条）:\n  %s"
                       % (len(mism), checked + len(mism), "\n  ".join(mism[:8])))
        if checked < 100:
            raise Fail("可比对样本过少（%d 条），交叉校验没有意义" % checked)
    check("与 capstone 交叉校验（助记符 + 寄存器集合）", t_capstone)

    # ---- 5. RV32IM 判定：真代码 vs 随机数据 ----
    def t_detect():
        # 造一段"像真的" RV32IM 代码：函数序言/尾声 + load/store + M 扩展 + nop 填充
        code = [
            _enc_i(-16, 2, 0, 2, 0x13),        # addi sp, sp, -16
            _enc_s(12, 1, 2, 2),               # sw ra, 12(sp)
            _enc_s(8, 8, 2, 2),                # sw s0, 8(sp)
            _enc_i(16, 2, 0, 8, 0x13),         # addi s0, sp, 16
            _enc_i(0, 8, 2, 10, 0x03),         # lw a0, 0(s0)
            _enc_r(0x01, 11, 10, 0, 10),       # mul a0, a0, a1
            _enc_r(0x01, 11, 10, 4, 11),       # div a1, a0, a1
            _enc_r(0x00, 11, 10, 0, 10),       # add a0, a0, a1
            _enc_b(8, 0, 10, 0),               # beq a0, zero, +8
            _enc_i(0x000, 0, 0, 0, 0x73),      # ecall
            _enc_i(12, 2, 2, 1, 0x03),         # lw ra, 12(sp)
            _enc_s(12, 1, 2, 2),               # sw ra, 12(sp)
            _enc_i(16, 2, 0, 2, 0x13),         # addi sp, sp, 16
            _enc_i(0, 1, 0, 0, 0x67),          # ret
        ]
        body = code + [0x00000013] * 40 + code + [0x00000013] * 40 + code
        blob = b"".join(w.to_bytes(4, "little") for w in body)
        rep = analyze_rv32(blob, 0x80000000)
        if rep["evidence"]["p_align32"] < 0.99:
            raise Fail("真代码 p_align32=%.3f 应接近 1.0" % rep["evidence"]["p_align32"])
        if rep["evidence"]["nop_13_00_00_00"] != 80:
            raise Fail("nop 计数 %d != 80" % rep["evidence"]["nop_13_00_00_00"])
        if rep["evidence"]["ret_67_80_00_00"] != 3:
            raise Fail("ret 计数 %d != 3" % rep["evidence"]["ret_67_80_00_00"])
        if rep["evidence"]["m_ext_funct7_0x01"] != 6:
            raise Fail("M 扩展计数 %d != 6" % rep["evidence"]["m_ext_funct7_0x01"])
        if rep["score"] < 7:
            raise Fail("真代码 score=%d 应 ≥7（判据太弱）" % rep["score"])
        if "RV32IM" not in rep["verdict"]:
            raise Fail("真代码应判 RV32IM，实际 %r" % rep["verdict"])

        # 随机数据必须判否（这里用确定性 PRNG，不用 os.urandom 保证可重放）
        rnd = __import__("random").Random(1234)
        rand = bytes(rnd.getrandbits(8) for _ in range(4096))
        rep2 = analyze_rv32(rand, 0)
        if "不是 RV32" not in rep2["verdict"]:
            raise Fail("随机数据应判否，实际 %r (score=%d, p32=%.3f)"
                       % (rep2["verdict"], rep2["score"], rep2["evidence"]["p_align32"]))
    check("RV32IM 判定（真代码必须判是 / 随机数据必须判否）", t_detect)

    # ---- 6. 熵：随机≈8、全零=0、纯 ASCII 明显偏低 ----
    def t_entropy():
        rnd = __import__("random").Random(99)
        rand = bytes(rnd.getrandbits(8) for _ in range(256))
        e_rand = shannon(rand)
        e_zero = shannon(b"\x00" * 256)
        e_ascii = shannon(bytes((0x41 + (i % 26)) for i in range(256)))
        if not (7.0 <= e_rand <= 8.0):
            raise Fail("随机块熵 %.3f 不在 [7,8]" % e_rand)
        if e_zero != 0.0:
            raise Fail("全零块熵 %.3f != 0" % e_zero)
        if e_ascii >= 5.0:
            raise Fail("ASCII 块熵 %.3f 应 < 5" % e_ascii)
        # 高熵区间识别
        blob = b"\x00" * 512 + rand + b"\x00" * 512 + rand
        blocks = block_entropy(blob, 256)
        rngs = high_entropy_ranges(blocks)
        if len(rngs) != 2:
            raise Fail("应识别出 2 段高熵区，实际 %d: %r" % (len(rngs), rngs))
        if rngs[0]["start"] != 512:
            raise Fail("首段高熵区起点 %d != 512" % rngs[0]["start"])
    check("熵计算与高熵区间识别", t_entropy)

    # ---- 7. strings / find-const ----
    def t_extract():
        blob = (b"\x00\x00\x00" + b"BMS_ROOT_KEY_V1" + b"\x00\x01\x02"
                + b"ab" + b"\x00" + b"CV6FF52FEE9EDDD86" + b"\xff")
        ss = [s["text"] for s in extract_strings(blob, 4)]
        if "BMS_ROOT_KEY_V1" not in ss:
            raise Fail("漏掉长串: %r" % ss)
        if "CV6FF52FEE9EDDD86" not in ss:
            raise Fail("漏掉 VIN 串: %r" % ss)
        if "ab" in ss:
            raise Fail("短于 min_len 的 'ab' 不该出现: %r" % ss)

        key = bytes.fromhex("8f3a1c07d95b24e6af0813cd7b520e94"
                            "c1d7a30825fb6e9147cc2d0a6b9358e1")
        # 关键回归：key 前面是零填充，滑动窗口会先在 60 处（4 零 + 28 字节 key）
        # 命中；必须吸附到 16 对齐的 64，且值必须逐字节等于原 key。
        fw = b"\x00" * 64 + key + b"\x00" * 64
        found = find_constants(fw, 32, step=4)
        if not found:
            raise Fail("32 字节常量未找到")
        if found[0]["offset"] != 64:
            raise Fail("32 字节常量应吸附到 16 对齐的 64，实际 %d" % found[0]["offset"])
        if found[0]["value"] != key.hex():
            raise Fail("常量值被边界污染：%s" % found[0]["value"])
        if not found[0]["aligned16"]:
            raise Fail("应标记 aligned16=True")
        if len(find_constants(b"\x00" * 256, 32, step=4)) != 0:
            raise Fail("全零数据不该产出常量")
        # 16 字节常量同样要准
        fw16 = b"\x00" * 32 + key[:16] + b"\x00" * 32
        f16 = find_constants(fw16, 16, step=1)
        if not f16 or f16[0]["offset"] != 32 or f16[0]["value"] != key[:16].hex():
            raise Fail("16 字节常量定位/取值错: %r" % (f16[:1],))
    check("strings 提取与高熵常量定位（含跨边界窗口吸附回归）", t_extract)

    width = max(len(l) for l, _, _ in results)
    print("rv32.py %s self-test" % VERSION)
    print("=" * (width + 12))
    bad = 0
    for label, status, detail in results:
        print("%-*s  %s" % (width, label, status))
        if status != "PASS":
            bad += 1
            for line in str(detail).splitlines():
                print("    " + line)
    print("-" * (width + 12))
    print("%d/%d passed" % (len(results) - bad, len(results)))
    if bad:
        print("RESULT: FAIL —— 不许交付")
        return 1
    print("RESULT: PASS")
    return 0


# --------------------------------------------------------------------------- #
# 渲染
# --------------------------------------------------------------------------- #

def render_analyze(rep):
    ev = rep["evidence"]
    print("--- RV32 形态判定 ---")
    print("size=%d  n_words=%d" % (rep["size"], rep["n_words"]))
    rows = [
        ("p_align32（低2位==0b11 比例）", "%.4f" % ev["p_align32"]),
        ("nop  (13 00 00 00)", str(ev["nop_13_00_00_00"])),
        ("ret  (67 80 00 00)", str(ev["ret_67_80_00_00"])),
        ("SYSTEM 0x73", str(ev["system_0x73"])),
        ("M 扩展 funct7==0x01", str(ev["m_ext_funct7_0x01"])),
        ("load 0x03 / store 0x23", "%d / %d" % (ev["load_0x03"], ev["store_0x23"])),
        ("OP-IMM 0x13 / OP 0x33", "%d / %d" % (ev["op_imm_0x13"], ev["op_0x33"])),
        ("branch 0x63 / jump", "%d / %d" % (ev["branch_0x63"], ev["jump_0x6f_0x67"])),
        ("手写解码器合法率", "%.4f" % ev["legal_rate"]),
        ("score", str(rep["score"])),
    ]
    _tbl(["指标", "值"], rows)
    print()
    print("opcode 分布 top10: %s" % ev["opcode_hist"])
    print()
    for r in rep.get("reasons", []):
        print("  + %s" % r)
    print()
    print("结论：%s" % rep["verdict"])


def _tbl(headers, rows):
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(str(c)))
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("-" * len(line))
    for r in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)))


def render_entropy(blocks, top=8):
    print("--- 分块熵（%d 字节/块，共 %d 块）---" % (blocks[0]["len"] if blocks else 0,
                                                   len(blocks)))
    _tbl(["offset", "len", "entropy", "bar", "flag"],
         [["0x%06x" % b["offset"], str(b["len"]), "%.3f" % b["entropy"],
           "#" * int(round(b["entropy"] / 8 * 32)),
           "HI" if b["hi"] else ""] for b in blocks])
    rngs = high_entropy_ranges(blocks)
    print()
    print("--- 高熵区（>=7.0 bit/B，疑似加密/压缩/密钥/签名区）共 %d 段 ---" % len(rngs))
    if not rngs:
        print("  (无)")
    for r in rngs:
        ln = r["end"] - r["start"]
        print("  0x%06x - 0x%06x  (%d bytes)" % (r["start"], r["end"], ln))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass

    ap = argparse.ArgumentParser(
        description="RV32IM 镜像分析器（反汇编/字符串/熵/常量/摘要/形态判定）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例： python rv32.py bms.bin --analyze --entropy --find-const --size 32")
    ap.add_argument("file", nargs="?", help="待分析镜像路径")
    ap.add_argument("--disasm", nargs="?", const=True, metavar="BIN",
                    help="反汇编（可同时给路径：--disasm bms.bin）")
    ap.add_argument("--strings", action="store_true", help="提取 >=4 字节 ASCII 串")
    ap.add_argument("--entropy", action="store_true", help="分块熵 + 高熵区")
    ap.add_argument("--find-const", dest="find_const", action="store_true",
                    help="滑动窗口找高熵定长常量")
    ap.add_argument("--sha256", action="store_true", help="整文件与各分段 SHA256")
    ap.add_argument("--analyze", action="store_true", help="RV32IM 形态判定（默认动作）")
    ap.add_argument("--self-test", action="store_true", help="用固定向量与 capstone 自校验")
    ap.add_argument("--base", default="0x0", help="反汇编基址（默认 0x0）")
    ap.add_argument("--start", type=int, default=0, help="起始字节偏移")
    ap.add_argument("--count", type=int, default=64, help="反汇编指令数上限")
    ap.add_argument("--size", type=int, default=16, choices=[16, 32],
                    help="--find-const 的常量长度（16 或 32）")
    ap.add_argument("--step", type=int, default=4, help="--find-const 滑动步长")
    ap.add_argument("--block", type=int, default=256, help="--entropy 块大小")
    ap.add_argument("--min-len", type=int, default=4, help="--strings 最短长度")
    ap.add_argument("--blocks", type=int, default=0,
                    help="--sha256 附带按该字节数的分块摘要（0=不做）")
    ap.add_argument("--no-capstone", action="store_true", help="强制走内置手写解码器")
    ap.add_argument("--limit", type=int, default=200, help="输出行数上限（0=不限）")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    ap.add_argument("--version", action="version", version="rv32.py " + VERSION)
    args = ap.parse_args(argv)

    if args.self_test:
        return run_self_test()

    path = args.file
    if isinstance(args.disasm, str):
        path = path or args.disasm
    if not path:
        ap.error("需要镜像路径（位置参数或 --disasm <BIN>，或用 --self-test）")
    if not os.path.isfile(path):
        print("ERROR: 文件不存在: %s" % path, file=sys.stderr)
        print("       当前状态：待固件。拿到 BMS 镜像后重跑即可。", file=sys.stderr)
        return 2
    with open(path, "rb") as f:
        data = f.read()
    if not data:
        print("ERROR: 文件为空: %s" % path, file=sys.stderr)
        return 2

    try:
        base = int(str(args.base), 0)
    except ValueError:
        ap.error("--base 不是合法整数：%r" % args.base)

    any_action = any([args.disasm, args.strings, args.entropy, args.find_const,
                      args.sha256, args.analyze])
    if not any_action:
        args.analyze = True

    out = {"file": path, "size": len(data)}

    if args.analyze:
        out["analyze"] = analyze_rv32(data, base)

    if args.disasm:
        cap = None if args.no_capstone else disasm_capstone(
            data, base, args.start, args.count)
        if cap is None:
            out["disasm_engine"] = "manual(RV32IM)"
            out["disasm"] = disasm_manual(data, base, args.start, args.count)
        else:
            out["disasm_engine"] = "capstone"
            out["disasm"] = cap

    if args.strings:
        out["strings"] = extract_strings(data, args.min_len,
                                         args.limit or 0)

    if args.entropy:
        out["entropy"] = block_entropy(data, args.block)
        out["high_entropy_ranges"] = high_entropy_ranges(out["entropy"])

    if args.find_const:
        out["constants"] = find_constants(data, args.size, args.step,
                                          limit=args.limit or 0)

    if args.sha256:
        out["sha256"] = sha256_report(data, args.blocks)

    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=1))
        return 0

    # ---- 文本渲染 ----
    print("=" * 78)
    print("rv32.py %s — %s (%d bytes)" % (VERSION, path, len(data)))
    print("=" * 78)

    if "analyze" in out:
        render_analyze(out["analyze"])
        print()

    if "disasm" in out:
        print("--- 反汇编（engine=%s，base=0x%x，start=%d）---"
              % (out["disasm_engine"], base, args.start))
        for i in out["disasm"]:
            note = ("  ; " + i["note"]) if i.get("note") else ""
            print("  0x%08x  %-8s  %-28s %s%s"
                  % (i["addr"], i["bytes"], i["mnemonic"], i["op_str"], note))
        print()

    if "strings" in out:
        print("--- ASCII 串（>=%d 字节）共 %d 条 ---" % (args.min_len, len(out["strings"])))
        for s in out["strings"]:
            print("  0x%06x  len=%-4d %r" % (s["offset"], s["len"], s["text"]))
        print()

    if "entropy" in out:
        render_entropy(out["entropy"])
        print()

    if "constants" in out:
        print("--- 高熵常量（size=%d, step=%d）共 %d 个 ---"
              % (args.size, args.step, len(out["constants"])))
        for c in out["constants"]:
            print("  0x%06x  ent=%.3f  al16=%-5s %s"
                  % (c["offset"], c["entropy"], c["aligned16"], c["value"]))
        print()

    if "sha256" in out:
        sh = out["sha256"]
        print("--- SHA256 ---")
        _tbl(["目标", "len", "sha256"],
             [["whole", str(sh["whole"]["len"]), sh["whole"]["sha256"]]] +
             [[s.get("name", "?"), str(s.get("len", "-")), s.get("sha256", s.get("error", ""))]
              for s in sh["segments"]] +
             [["block@0x%x" % b["offset"], str(b["len"]), b["sha256"]]
              for b in sh["blocks"]])
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

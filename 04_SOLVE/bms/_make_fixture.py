#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_make_fixture.py -- 造一个**合成** RV32IM 镜像，用于验证 rv32.py / derive_key.py。

⚠ 这不是真实 BMS 固件。包里所有"密钥"都是本脚本按固定 PRNG 现编的，
  存在的唯一目的是让 rv32.py 的每个动作都有可复核的输入输出对照。

镜像布局（模拟常见车规固件：
    [0x00000] header  : "CYBR" + u32 payload_len + 4 reserved      (12 B)
    [0x0000C] code    : 若干 RV32IM 函数（序言/尾声/load/store/M扩展/ecall）
    [...]     rodata  : 字符串表（含 ROOT_KEY 标记与 VIN）
    [...]     cpool   : 16 字节 IV + 32 字节候选 key（16 对齐）
    [末尾]     trailer : 256 字节"签名"（高熵，确定性生成）

用法： python _make_fixture.py <输出路径>
"""

import random
import struct
import sys

# --- 编码器（按 RISC-V 字段布局手写）---
# 每个字段都按位宽掩码，避免 f3=11 这类越界值污染相邻字段（踩过一次）
def R(f7, rs2, rs1, f3, rd, op=0x33):
    return ((f7 & 0x7F) << 25) | ((rs2 & 0x1F) << 20) | ((rs1 & 0x1F) << 15) | \
           ((f3 & 0x7) << 12) | ((rd & 0x1F) << 7) | (op & 0x7F)

def I(imm, rs1, f3, rd, op):
    return ((imm & 0xFFF) << 20) | ((rs1 & 0x1F) << 15) | ((f3 & 0x7) << 12) | \
           ((rd & 0x1F) << 7) | (op & 0x7F)

def S(imm, rs2, rs1, f3, op=0x23):
    imm &= 0xFFF
    return (((imm >> 5) & 0x7F) << 25) | ((rs2 & 0x1F) << 20) | ((rs1 & 0x1F) << 15) | \
           ((f3 & 0x7) << 12) | ((imm & 0x1F) << 7) | (op & 0x7F)

def B(imm, rs2, rs1, f3, op=0x63):
    imm &= 0x1FFF
    return (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3F) << 25) | \
           ((rs2 & 0x1F) << 20) | ((rs1 & 0x1F) << 15) | ((f3 & 0x7) << 12) | \
           (((imm >> 1) & 0xF) << 8) | (((imm >> 11) & 1) << 7) | (op & 0x7F)

def U(imm20, rd, op):
    return ((imm20 & 0xFFFFF) << 12) | ((rd & 0x1F) << 7) | (op & 0x7F)

def J(imm, rd, op=0x6F):
    imm &= 0x1FFFFF
    return (((imm >> 20) & 1) << 31) | (((imm >> 1) & 0x3FF) << 21) | \
           (((imm >> 11) & 1) << 20) | (((imm >> 12) & 0xFF) << 12) | \
           ((rd & 0x1F) << 7) | (op & 0x7F)

NOP = 0x00000013
RET = 0x00008067


def function_body(rnd, use_m_ext=True):
    """一个"像真的"函数：序言 → 计算 → 分支 → 尾声。"""
    c = [
        I(-24, 2, 0, 2, 0x13),      # addi sp, sp, -24
        S(20, 1, 2, 2),             # sw   ra, 20(sp)
        S(16, 8, 2, 2),             # sw   s0, 16(sp)
        I(24, 2, 0, 8, 0x13),       # addi s0, sp, 24
        I(0, 8, 2, 10, 0x03),       # lw   a0, 0(s0)
        I(4, 8, 2, 11, 0x03),       # lh   a1, 4(s0)
        U(0x00012, 5, 0x37),        # lui  t0, 0x12
        I(0x034, 5, 0, 5, 0x13),    # addi t0, t0, 0x34
        I(0x1F, 10, 1, 6, 0x13),    # slli t1, a0, 31
    ]
    if use_m_ext:
        c += [
            R(0x01, 11, 10, 0, 12),   # mul  a2, a0, a1
            R(0x01, 12, 10, 4, 13),   # div  a3, a0, a2
            R(0x01, 11, 10, 7, 14),   # remu a4, a0, a1
        ]
    c += [
        R(0x00, 11, 10, 0, 15),       # add  a5, a0, a1
        R(0x20, 11, 10, 0, 15),       # sub  a5, a0, a1
        I(0x400 | 3, 10, 5, 16, 0x13),  # srai a6, a0, 3
        B(12, 0, 10, 0),              # beq  a0, zero, +12
        S(8, 15, 2, 2),               # sw   a5, 8(sp)
        I(0x000, 0, 0, 0, 0x73),      # ecall
        J(8, 1),                      # jal  ra, +8
        I(20, 2, 2, 1, 0x03),         # lw   ra, 20(sp)
        I(24, 2, 0, 2, 0x13),         # addi sp, sp, 24
        RET,
    ]
    return c


def main(out_path):
    rnd = random.Random(0xC7B5)   # 固定种子 → 可重放

    # ---- code ----
    code = []
    for i in range(6):
        code += function_body(rnd, use_m_ext=(i % 3 != 0))
        code += [NOP] * rnd.choice([3, 5, 8])
        code += [J(0, 1)]                       # jal ra, +0（占位调用点）
    code_bytes = b"".join(w.to_bytes(4, "little") for w in code)

    # ---- rodata：字符串表（含 RK5 需要的标记）----
    rodata = (
        b"BMS_FW_v2.1.0\x00"
        b"CYBERCAR/BMS\x00"
        b"ROOT_KEY\x00"
        b"CV6FF52FEE9EDDD86\x00"      # 线上实测 VIN 字节，全大写
        b"CV6FF52FEe9EDDD86\x00"      # 题述变体，留给 I2 对照
        b"HMAC-SHA256\x00"
        b"AES-128-CMAC\x00"
        b"seed="
    )
    # 16 对齐
    rodata = rodata + b"\x00" * ((16 - len(rodata) % 16) % 16)

    # ---- cpool：IV(16) + 32 字节候选 key，均 16 对齐 ----
    iv = bytes(rnd.getrandbits(8) for _ in range(16))
    key32 = bytes(rnd.getrandbits(8) for _ in range(32))
    cpool = iv + key32
    cpool += b"\x00" * ((16 - len(cpool) % 16) % 16)

    # ---- 末尾填充到 4 对齐 ----
    body = code_bytes + rodata + cpool
    body += b"\x00" * ((4 - len(body) % 4) % 4)

    # ---- header：magic + payload_len + 4 reserved ----
    header = b"CYBR" + struct.pack("<I", len(body)) + b"\x00" * 4

    # ---- trailer：256 字节确定性"签名" ----
    trailer = bytes(rnd.getrandbits(8) for _ in range(256))

    img = header + body + trailer
    with open(out_path, "wb") as f:
        f.write(img)

    import hashlib
    print("wrote %s" % out_path)
    print("  size      = %d" % len(img))
    print("  sha256    = %s" % hashlib.sha256(img).hexdigest())
    print("  header    = %r + len=%d" % (header[:4], len(body)))
    print("  code      = %d B @0x%x .. 0x%x" % (len(code_bytes), 12, 12 + len(code_bytes)))
    print("  rodata    = %d B @0x%x" % (len(rodata), 12 + len(code_bytes)))
    print("  cpool     = %d B @0x%x (iv=%s)" % (len(cpool), 12 + len(code_bytes) + len(rodata),
                                                iv.hex()))
    print("  key32     = %s" % key32.hex())
    print("  trailer   = 256 B 尾块")
    print()
    print("  ⚠ 合成数据，key32 是 PRNG 现编的，不是任何真实 root key")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "fixture_rv32im.bin")

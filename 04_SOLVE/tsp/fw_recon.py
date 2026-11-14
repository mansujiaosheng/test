#!/usr/bin/env python3
"""
Static analysis of the decrypted CV6 T-BOX firmware (ARMv7-M Thumb-2, base 0x08000000).

Goals, in the order the task chain needs them:
  1. vector table / entry points
  2. strings and literal pools
  3. "SoC binding measurement" — reads of a device-unique id / cpuid / flash-size register
  4. RFC 3394 AES key-wrap evidence — 0xA6A6A6A6A6A6A6A6 IV, a 16/24/32-byte wrapped blob,
     or an unwrap call site
  5. anything flag-shaped

Usage: python fw_recon.py <firmware.bin> [base_hex]
"""
import re
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

FW = sys.argv[1] if len(sys.argv) > 1 else \
    "01_TARGETS/tsp/engineering-bundle/tbox-firmware.dec.bin"
BASE = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x08000000

data = open(FW, "rb").read()
print("=" * 78)
print(f"firmware : {FW}")
print(f"size     : {len(data)} B   base: 0x{BASE:08x}   end: 0x{BASE+len(data):08x}")
print("=" * 78)

# ---------------------------------------------------------------- vector table
print("\n[1] vector table")
words = struct.unpack("<%dI" % (min(len(data), 64 * 4) // 4), data[:min(len(data), 256)])
print(f"  SP           = 0x{words[0]:08x}")
names = ["Reset", "NMI", "HardFault", "MemManage", "BusFault", "UsageFault",
         "-", "-", "-", "-", "SVC", "DebugMon", "-", "PendSV", "SysTick"]
for i, n in enumerate(names, 1):
    if i < len(words):
        print(f"  [{i:2d}] {n:11s} = 0x{words[i]:08x}")
print(f"  ... total non-zero vector words: "
      f"{sum(1 for w in words if w)}/{len(words)}")
uniq = sorted({w for w in words[1:] if w})
print(f"  distinct handler words: {[hex(x) for x in uniq]}")

# ---------------------------------------------------------------- strings
print("\n[2] strings (len>=5, printable)")
strs = []
for m in re.finditer(rb"[\x20-\x7e]{5,}", data):
    s = m.group().decode()
    strs.append((BASE + m.start(), s))
for a, s in strs:
    print(f"  0x{a:08x}  {s!r}")
if not strs:
    print("  (none)")

# ---------------------------------------------------------------- disassembly
print("\n[3] disassembly (Thumb, first 4000 insns)")
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)
md.detail = True
insns = []
for ins in md.disasm(data, BASE):
    insns.append(ins)
    if len(insns) >= 4000:
        break
print(f"  decoded {len(insns)} instructions "
      f"({len(insns)*2} B of {len(data)} B)")

# branch targets / calls
calls = sorted({i.operands[0].imm for i in insns
                if i.mnemonic in ("bl", "blx") and i.operands
                and i.operands[0].type == ARM_OP_IMM})
print(f"  call targets ({len(calls)}): {[hex(c) for c in calls][:40]}")

# literal loads (ldr rX, [pc, #imm]) -> literal pools
lits = []
for i in insns:
    if i.mnemonic.startswith("ldr") and len(i.operands) >= 2:
        op = i.operands[1]
        if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
            # pc-relative literal
            addr = (i.address + 4) & ~3
            tgt = addr + op.mem.disp
            if BASE <= tgt < BASE + len(data) - 4:
                val = struct.unpack("<I", data[tgt - BASE: tgt - BASE + 4])[0]
                lits.append((i.address, i.mnemonic, tgt, val))
print(f"\n[4] PC-relative literal loads: {len(lits)}")
seen = set()
for a, mn, tgt, val in lits:
    key = (tgt, val)
    if key in seen:
        continue
    seen.add(key)
    note = ""
    if 0x08000000 <= val < 0x08000000 + len(data):
        note = "  <-- code pointer"
    elif 0x20000000 <= val < 0x20020000:
        note = "  <-- RAM pointer"
    elif 0x40000000 <= val < 0x60000000:
        note = "  <-- PERIPHERAL (MMIO)"
    elif val == 0xA6A6A6A6:
        note = "  <-- *** RFC 3394 IV ***"
    print(f"  0x{a:08x}  {mn:6s} pool@0x{tgt:08x} = 0x{val:08x}{note}")

# ---------------------------------------------------------------- RFC3394 hunt
print("\n[5] RFC 3394 / AES-key-wrap hunt")
IV32 = 0xA6A6A6A6
print(f"  searching for 0xA6A6A6A6 (u32), 0xA6A6A6A6A6A6A6A6 (u64), and 8x0xA6 runs")
hits = []
for i in range(0, len(data) - 8, 2):
    if struct.unpack("<I", data[i:i + 4])[0] == IV32:
        hits.append(("u32", BASE + i, data[i:i + 8].hex()))
    if data[i:i + 8] == b"\xa6" * 8:
        hits.append(("u64", BASE + i, data[i:i + 8].hex()))
for h in hits[:20]:
    print(f"  HIT {h[0]} @0x{h[1]:08x} bytes={h[2]}")
if not hits:
    print("  no A6 pattern")
print(f"  runs of exactly 16/24/32 high-entropy bytes (candidate wrapped keys) are "
      f"better found with entropy scan -> see below")

print("\n[6] entropy blocks (16-byte windows, byte-entropy > 7.0 bits)")
import math
def ent(b):
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    n = len(b)
    return -sum((k / n) * math.log2(k / n) for k in c if k)
blocks = []
for off in range(0, len(data) - 16, 16):
    e = ent(data[off:off + 16])
    if e > 7.0:
        blocks.append((off, e))
# merge consecutive
runs = []
for off, e in blocks:
    if runs and off == runs[-1][1]:
        runs[-1] = (runs[-1][0], off + 16, min(runs[-1][2], e))
    else:
        runs.append((off, off + 16, e))
print(f"  {len(runs)} high-entropy runs:")
for a, b, e in runs[:40]:
    print(f"    0x{BASE+a:08x}..0x{BASE+b:08x}  {b-a:5d} B  ent>={e:.2f}")

# ---------------------------------------------------------------- flag hunt
print("\n[7] flag-shaped strings")
pat = re.compile(rb"[A-Za-z0-9_]{2,20}\{[ -~]{1,120}\}")
found = [m.group() for m in pat.finditer(data)]
print("  ", found if found else "(none)")

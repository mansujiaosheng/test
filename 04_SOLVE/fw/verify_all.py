#!/usr/bin/env python3
"""One-shot re-verification of every task-02 claim; writes 03_EVIDENCE/fw/verify.txt."""
import hashlib, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from emu import *
from unicorn.arm_const import *
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

FW = open(r'D:\qwb\work\bundle2\tbox-firmware.dec.bin','rb').read()
OUT = open(r'D:\qwb\03_EVIDENCE\fw\verify.txt','w',encoding='utf-8')
def P(*a):
    s=' '.join(str(x) for x in a); print(s); OUT.write(s+'\n')

P("=== T-BOX firmware verification ===")
P("sha256(image) =", hashlib.sha256(FW).hexdigest())
P("sha256 matches manifest.tboxSha256 88b09d09...:", 
  hashlib.sha256(FW).hexdigest()=='88b09d09edbf2951f7a111a51608e99a1bb28a27e653c169f4bf6ddd8c537229')

P("\n--- [C1] tables ---")
P("AES sbox      @0x080008a0:", FW[0x8a0:0x8a4].hex())
P("AES inv sbox  @0x08000798:", FW[0x798:0x79c].hex())
P("SHA256 IV     @0x08000778:", FW[0x778:0x77c].hex())
P("SHA256 K[0]   @0x080009a0:", FW[0x9a0:0x9a4].hex())
P("RFC3394 AIV   @0x08000898:", FW[0x898:0x8a0].hex())
P("KDF label     @0x08000aa0:", FW[0xaa0:0xaac])
P("UID16         @0x08002000:", FW[0x2000:0x2010].hex())
P("C8            @0x08002020:", FW[0x2020:0x2028].hex())
P("wrapped40     @0x08002040:", FW[0x2040:0x2068].hex())

P("\n--- [C2] KDF / KEK derivation (pure python) ---")
digest = hashlib.sha256(FW[:0x2000]).digest()
KEK = hashlib.sha256(b"CV6-TBOX-KEK" + FW[0x2000:0x2010] + digest).digest()
P("sha256(fw[0:0x2000]) =", digest.hex())
P("derived KEK          =", KEK.hex())
P("KEK == emulator frame:", KEK.hex()=='0fd6e171919fdc1a6afcee7f81a6599c67a136fc0f57e8f210fb2acf9c92b318')

P("\n--- [C3] RFC3394 unwrap via cryptography ---")
PT = aes_key_unwrap(KEK, FW[0x2040:0x2068])
P("unwrap(KEK, wrapped40) =", PT.hex(), f"({len(PT)} B)")
P("re-wrap round-trips    :", aes_key_wrap(KEK, PT) == FW[0x2040:0x2068])

P("\n--- [C4] Unicorn emulation of measure() ---")
uc = new_uc()
st,uc,n = run(uc, 0x080006fd, base_sp=0x2000f000,
              args={UC_ARM_REG_R0: 0x20008000}, stops=(0x08000744,))
P("measure() return value :", uc.reg_read(UC_ARM_REG_R0), "(1 = unwrap integrity check PASSED)")
P("out[0:32] from emulator:", bytes(uc.mem_read(0x20008000,32)).hex())
P("out[0:32] == unwrap PT :", bytes(uc.mem_read(0x20008000,32)) == PT)
sp = 0x2000f000-4-0x80
P("frame sp+0x20 (derived):", bytes(uc.mem_read(sp+0x20,32)).hex())

P("\n--- [C5] Reset path: unwrap output never read ---")
uc2 = new_uc()
SP_OUT = 0x2000ffd8
rd = []
pcv=[0]
uc2.hook_add(UC_HOOK_CODE, lambda u,a,s,d: pcv.__setitem__(0,a))
def onread(u,acc,addr,size,val,d):
    if SP_OUT <= addr < SP_OUT+40: rd.append(pcv[0])
uc2.hook_add(UC_HOOK_MEM_READ, onread)
st2,uc2b,n2 = run(uc2, 0x08000755)
P("halt:", st2, " instructions:", n2)
P("unique PCs reading 0x2000ffd8..0x2000ffff:", sorted(set(hex(a) for a in rd)))
P("  (0x080001ec = memcpy inner loop only -> no semantic consumer)")
P("Reset out buffer contents:", bytes(uc2b.mem_read(SP_OUT,40)).hex())

P("\n--- [C6] hash8 (0x08000668) primitive ---")
import seedkey
vec = seedkey.hash8(bytes.fromhex('1122334455667788'), bytes.fromhex('deadbeefcafebabe'))
P("hash8(1122334455667788, deadbeefcafebabe) =", vec.hex())
P("matches emulator e21faa054c4f8037      :", vec.hex()=='e21faa054c4f8037')

OUT.close()
print("\nwrote 03_EVIDENCE/fw/verify.txt")

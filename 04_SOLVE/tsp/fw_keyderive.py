#!/usr/bin/env python3
"""
Reimplement the T-BOX firmware's key derivation offline (from static analysis of
0x080006fc / 0x08000204 / 0x080002dc).

Recovered logic
---------------
  H   = SHA256( flash[0x0000 : 0x2000] )                  ; "SoC binding measurement"
                                                          ;   (cleartext firmware self-hash)
  KEK = SHA256( "CV6-TBOX-KEK" || blob16@0x08002000 || H ) ; 12 + 16 + 32 = 60 = 0x3c bytes
  K   = RFC3394_AES_unwrap( KEK, blob40@0x08002040 )       ; 0x28 = 40 bytes = IV(8) + key(32)

Static evidence
---------------
  0x080006fc  ldr r1,[pc] -> 0x08000aa0 = "CV6-TBOX-KEK"   (memcpy r2=0xc)
              movs r2,#0x10 ; memcpy from 0x08002000       (SoC blob, 16 B)
              movs r2,#0x20 ; memcpy from sp+4             (the SHA-256 digest, 32 B)
              movs r1,#0x3c ; bl 0x08000204                (SHA-256 over 60 B)
              ldr r1,[pc] -> 0x08002040 ; movs r2,#0x28 ; bl 0x080002dc   (unwrap 40 B)
  0x08000898  0xa6a6a6a6a6a6a6a6  = RFC 3394 default IV
  0x080008a0  637c777bf26b6fc5... = AES S-box
  0x080009a0  428a2f98 71374491 ... = SHA-256 K[0..63]
  0x08000778  6a09e667 bb67ae85 ... = SHA-256 H0..H7
"""
import hashlib
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401  (not used)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FW = "01_TARGETS/tsp/engineering-bundle/tbox-firmware.dec.bin"
BASE = 0x08000000
data = open(FW, "rb").read()


def rd(addr, n):
    return data[addr - BASE: addr - BASE + n]


def aes_kw_unwrap(kek: bytes, wrapped: bytes) -> tuple[bytes, bytes]:
    """RFC 3394 AES Key Unwrap. Returns (plaintext, final_iv)."""
    if len(wrapped) % 8 or len(wrapped) < 24:
        raise ValueError("bad wrapped length")
    n = len(wrapped) // 8 - 1
    A = wrapped[:8]
    R = [wrapped[8 + i * 8: 16 + i * 8] for i in range(n)]
    cipher = Cipher(algorithms.AES(kek), modes.ECB())
    dec = cipher.decryptor()
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            t = n * j + i
            A = struct.pack(">Q", struct.unpack(">Q", A)[0] ^ t)
            block = dec.update(A + R[i - 1])
            A, R[i - 1] = block[:8], block[8:]
    return b"".join(R), A


def aes_kw_wrap(kek: bytes, pt: bytes) -> bytes:
    """RFC 3394 AES Key Wrap (for self-check against the firmware's expectation)."""
    n = len(pt) // 8
    A = b"\xa6" * 8
    R = [pt[i * 8: 8 + i * 8] for i in range(n)]
    cipher = Cipher(algorithms.AES(kek), modes.ECB())
    enc = cipher.encryptor()
    for j in range(6):
        for i in range(1, n + 1):
            t = n * j + i
            b = enc.update(A + R[i - 1])
            A = struct.pack(">Q", struct.unpack(">Q", b[:8])[0] ^ t)
            R[i - 1] = b[8:]
    return A + b"".join(R)


print("=" * 78)
print("T-BOX firmware key derivation — offline reimplementation")
print("=" * 78)
label = rd(0x08000aa0, 12)
blob16 = rd(0x08002000, 16)
blob40 = rd(0x08002040, 40)
print(f"  label      @0x08000aa0 = {label!r}")
print(f"  soc blob16 @0x08002000 = {blob16.hex()}")
print(f"  wrapped40  @0x08002040 = {blob40.hex()}")
print()

H = hashlib.sha256(rd(0x08000000, 0x2000)).digest()
print(f"[1] measurement H = SHA256(flash[0:0x2000])")
print(f"    = {H.hex()}")
print()
kek_material = label + blob16 + H
print(f"[2] KEK material = label || blob16 || H   ({len(kek_material)} bytes, firmware uses 0x3c=60)")
print(f"    = {kek_material.hex()}")
KEK = hashlib.sha256(kek_material).digest()
print(f"    KEK = SHA256(...) = {KEK.hex()}")
print()

print("[3] RFC 3394 unwrap blob40 with KEK")
pt, fin_iv = aes_kw_unwrap(KEK, blob40)
print(f"    plaintext ({len(pt)} B) = {pt.hex()}")
print(f"    final IV              = {fin_iv.hex()}   (RFC3394 wants a6a6a6a6a6a6a6a6)")
print(f"    integrity check       = {'PASS' if fin_iv == b'\\xa6'*8 else 'FAIL'}")
print()

if fin_iv == b"\xa6" * 8:
    print("[4] self-check: re-wrap the recovered key and compare to the blob")
    rewrapped = aes_kw_wrap(KEK, pt)
    print(f"    rewrap == blob40 : {rewrapped == blob40}")
    print()
    print("[5] recovered 32-byte key")
    print(f"    hex   : {pt.hex()}")
    print(f"    ascii : {''.join(chr(c) if 32 <= c < 127 else '.' for c in pt)}")
    open("01_TARGETS/tsp/engineering-bundle/tbox-image-key.bin", "wb").write(pt)
    print("    -> 01_TARGETS/tsp/engineering-bundle/tbox-image-key.bin")
    print()
    print("[6] what is it for? try it against the other blobs in the image")
    for addr, n, name in ((0x08002000, 16, "blob@0x08002000"),
                          (0x08002020, 8, "blob@0x08002020"),
                          (0x08000000, 16, "vector table head")):
        b = rd(addr, n)
        print(f"    {name:22s} = {b.hex()}")
else:
    print("!! unwrap did not produce the RFC3394 IV — derivation assumption wrong")
    print("   nearby variants to try: label len 11/12/13, blob at 0x08002010, H over 0x2000/0x4000")

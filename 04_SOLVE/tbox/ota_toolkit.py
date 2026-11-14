#!/usr/bin/env python3
"""OTA analysis toolkit skeleton for T02 (fill in once the OTA ZIP arrives).

Capabilities:
  - inspect a ZIP / raw blob: find magic, entropy, embedded ARMv7-M vectors
  - AES-256-GCM decrypt with a candidate key/nonce/AAD
  - RFC 3394 AES key unwrap (KEK -> DEK)
  - ARMv7-M Thumb-2 disassembly via capstone
Usage:
  python ota_toolkit.py inspect <file>
  python ota_toolkit.py gcm <file> --key <hex> --nonce <hex> [--aad <hex>] [--tag <hex>] [--offset N]
  python ota_toolkit.py unwrap <hex> --kek <hex>
  python ota_toolkit.py thumb <file> [--base 0x8000000] [--offset 0] [--count 200]
"""
import argparse, binascii, hashlib, math, os, struct, sys
from collections import Counter

MAGICS = {
    b"PK\x03\x04": "zip",
    b"\x1f\x8b": "gzip",
    b"\x7fELF": "elf",
    b"\x4d\x44\x43\x46": "MDCF(legacy)",
    b"OTA!": "OTA!",
}

def entropy(b):
    if not b: return 0.0
    c = Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def inspect(path):
    d = open(path,'rb').read()
    print(f"file={path} size={len(d)} sha256={hashlib.sha256(d).hexdigest()}")
    print("head32:", d[:32].hex(" "))
    for m,name in MAGICS.items():
        if d.startswith(m): print("magic:", name)
    # scan for zip local headers and PEM
    offs=[i for i in range(len(d)-4) if d[i:i+4]==b'PK\x03\x04']
    if offs: print("zip local headers at:", offs[:10], "count=", len(offs))
    for pat in (b'-----BEGIN', b'\x30\x82', b'\x7fELF', b'\x00\x00\x02\x20' ):
        idx=[i for i in range(len(d)-len(pat)) if d[i:i+len(pat)]==pat]
        if idx: print(f"pattern {pat!r} at", idx[:10], "count", len(idx))
    print("entropy overall:", round(entropy(d),3))
    # entropy per 4K block
    for i in range(0, min(len(d), 65536), 4096):
        blk=d[i:i+4096]
        print(f"  block {i:06x} ent={entropy(blk):.2f} head={blk[:8].hex(' ')}")

def gcm(path, key, nonce, aad, tag, offset, out):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    d=open(path,'rb').read()[offset:]
    key=bytes.fromhex(key); nonce=bytes.fromhex(nonce); aad=bytes.fromhex(aad) if aad else None
    if tag is None:
        ct, tag = d[:-16], d[-16:]
    else:
        ct, tag = d, bytes.fromhex(tag)
    pt=AESGCM(key).decrypt(nonce, ct+tag, aad)
    open(out,'wb').write(pt)
    print("plaintext len", len(pt), "sha256", hashlib.sha256(pt).hexdigest())
    print(pt[:64].hex(' '))

def unwrap(hexdata, kek):
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
    wrapped=bytes.fromhex(hexdata); kekb=bytes.fromhex(kek)
    dek=aes_key_unwrap(kekb, wrapped)
    print("DEK:", dek.hex())

def thumb(path, base, offset, count):
    import capstone
    md=capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    d=open(path,'rb').read()
    for ins in md.disasm(d[offset:], base+offset):
        print(f"{ins.address:08x}: {ins.bytes.hex():<10} {ins.mnemonic} {ins.op_str}")
        count-=1
        if count<=0: break

def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest='cmd', required=True)
    p=sub.add_parser('inspect'); p.add_argument('file'); p.set_defaults(fn=lambda a: inspect(a.file))
    p=sub.add_parser('gcm'); p.add_argument('file'); p.add_argument('--key', required=True); p.add_argument('--nonce', required=True)
    p.add_argument('--aad'); p.add_argument('--tag'); p.add_argument('--offset', type=int, default=0); p.add_argument('--out', default='pt.bin')
    p.set_defaults(fn=lambda a: gcm(a.file,a.key,a.nonce,a.aad,a.tag,a.offset,a.out))
    p=sub.add_parser('unwrap'); p.add_argument('hex'); p.add_argument('--kek', required=True); p.set_defaults(fn=lambda a: unwrap(a.hex,a.kek))
    p=sub.add_parser('thumb'); p.add_argument('file'); p.add_argument('--base', type=lambda x:int(x,0), default=0x8000000)
    p.add_argument('--offset', type=lambda x:int(x,0), default=0); p.add_argument('--count', type=int, default=200)
    p.set_defaults(fn=lambda a: thumb(a.file,a.base,a.offset,a.count))
    a=ap.parse_args(); a.fn(a)

if __name__=='__main__': main()

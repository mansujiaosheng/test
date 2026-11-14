#!/usr/bin/env python3
"""vcu-reference.bin 的加密假设穷举（用手里全部 key 材料）。

判据（先写后跑）：
  若文件是某个标准容器（AES-GCM/CTR/CBC/CFB/OFB/ECB、ChaCha20、XOR），
  用正确 key + layout 解密后，必然出现下面至少一项：
    S1 明文里出现已知串 "CALIBRATION: production steering and torque limits"
    S2 解密结果可压缩（zlib ratio < 0.95）或熵 < 7.5（代码/文本）
    S3 解密结果出现 >=8 字节可打印串
  实测若所有 (key, mode, layout) 组合都 S1/S2/S3 全否 ⇒ [否定] 标准容器假设。

注意一个与 key 无关的判据（写进 FINDINGS）：
  文件在 0x300..0x331 的实际字节 == 明文 ASCII。任何标准流/块密码的密文在该位置
  应近似均匀随机，50 字节全落在 ASCII 的概率约 (95/256)^50 ≈ 2e-22。
  ⇒ **该区间是明文，不是密文**；因此整文件不可能是单一标准密码容器。
"""
import base64
import hashlib
import json
import math
import struct
import zlib
from collections import Counter

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

P = "work/bundle2/x/vcu-reference.bin"
D = open(P, "rb").read()
MARKER = b"CALIBRATION: production steering and torque limits"


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def printable_runs(b, minlen=8):
    out = []
    i = 0
    while i < len(b):
        j = i
        while j < len(b) and 32 <= b[j] < 127:
            j += 1
        if j - i >= minlen:
            out.append((i, j - i, b[i:j]))
        i = max(j + 1, i + 1)
    return out


def score(name, b, results):
    z = len(zlib.compress(b, 9)) / len(b) if b else 9
    e = ent(b)
    pr = printable_runs(b)
    hit = MARKER in b
    s2 = z < 0.95 or e < 7.5
    # S3 需“强”证据：>=16B 可打印串，或可打印总量>=40，或 >=3 条 >=8B 串且可压缩
    s3 = any(ln >= 16 for _, ln, _ in pr) or sum(ln for _, ln, _ in pr) >= 40 \
         or (len(pr) >= 3 and z < 0.98)
    flag = ""
    if hit:
        flag += " S1"
    if s2:
        flag += " S2"
    if s3:
        flag += " S3"
    results.append((name, z, e, len(pr), hit, flag, pr[:2]))
    return bool(flag)


def load_keys():
    keys = {}
    keys["packageKey"] = bytes.fromhex("3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0")
    keys["firmwareCredential"] = bytes.fromhex("5e7f07b4a81153ecd5868cc02557f823")
    keys["tbox_sha256"] = bytes.fromhex("88b09d09edbf2951f7a111a51608e99a1bb28a27e653c169f4bf6ddd8c537229")
    keys["fw_self_digest"] = bytes.fromhex("138142b18d663291fc3febb15e004f57f76f10dee82f158a30b42ad7468ba085")
    keys["derived_KEK"] = bytes.fromhex("0fd6e171919fdc1a6afcee7f81a6599c67a136fc0f57e8f210fb2acf9c92b318")
    keys["unwrapped_key"] = bytes.fromhex("693d2ab06a2fe1a6e1ada23ac8bbb08ec3a8ffbbc90015ddeff28e721c9f693d")
    keys["vcu_sha256"] = hashlib.sha256(D).digest()
    keys["vcu_header32"] = D[8:40]
    keys["vcu_header24"] = D[8:32]
    keys["C_DEV16"] = bytes.fromhex("e224dd2bb23a15b8")
    keys["UID16"] = bytes.fromhex("d31ad1cae3ffe1aedbf00f0d7fec3396")
    keys["zero32"] = b"\x00" * 32
    keys["marker_sha256"] = hashlib.sha256(MARKER).digest()
    keys["magic_sha256"] = hashlib.sha256(b"CV6VCU1\0").digest()
    return keys


def ivs():
    out = {}
    out["hdr8_12"] = D[8:20]
    out["hdr8_16"] = D[8:24]
    out["hdr16_16"] = D[16:32]
    out["hdr32_12"] = D[8:20]
    out["zero16"] = b"\x00" * 16
    out["zero12"] = b"\x00" * 12
    out["vcu_sha_16"] = hashlib.sha256(D).digest()[:16]
    out["vcu_sha_12"] = hashlib.sha256(D).digest()[:12]
    try:
        man = json.load(open("work/bundle2/x/manifest.json"))
        nb = base64.b64decode(man["nonce"])
        out["manifest_nonce"] = nb
    except Exception:
        pass
    return out


def try_symmetric(results):
    keys = load_keys()
    ivs_ = ivs()
    # body candidates
    bodies = {"body@0x28": D[0x28:], "body@0x08": D[0x08:], "whole": D, "ct@0x14": D[0x14:],
              "ct@0x18": D[0x18:], "tail@0x40": D[0x40:]}
    for kname, key in keys.items():
        for kl in (16, 32):
            k = key[:kl] if len(key) >= kl else None
            if not k:
                continue
            for iname, iv in ivs_.items():
                iv16 = (iv + b"\x00" * 16)[:16]
                for mname, mode in [("CTR", modes.CTR(iv16)),
                                    ("CBC", modes.CBC(iv16)),
                                    ("CFB", modes.CFB(iv16)),
                                    ("OFB", modes.OFB(iv16))]:
                    try:
                        dec = Cipher(algorithms.AES(k), mode).decryptor()
                    except Exception:
                        continue
                    for bname, body in bodies.items():
                        ln = len(body) - len(body) % 16 if mname in ("CBC",) else len(body)
                        try:
                            pt = dec.update(body[:ln]) + dec.finalize()
                        except Exception:
                            continue
                        score(f"AES-{mname} k={kname} iv={iname} {bname}", pt, results)
    # ChaCha20 (12-byte nonce, counter 0)
    for kname, key in keys.items():
        if len(key) < 32:
            continue
        for iname, iv in ivs_.items():
            nonce = (iv + b"\x00" * 12)[:12]
            for bname, body in bodies.items():
                try:
                    c = algorithms.ChaCha20(key[:32], nonce + b"\x00" * 4)
                    dec = Cipher(c, mode=None).decryptor()
                    pt = dec.update(body)
                except Exception:
                    continue
                score(f"ChaCha20 k={kname} iv={iname} {bname}", pt, results)


def try_gcm(results):
    """GCM layouts: magic(8) + nonce(12/16) + ct + tag(16)."""
    keys = load_keys()
    layouts = []
    for noff, nlen in ((8, 12), (8, 16), (8, 8), (0, 12)):
        for toff in (-16, 0x3F0):
            layouts.append((f"nonce@{noff:#x} len={nlen} tag@{toff:#x}", noff, nlen, toff))
    for kname, key in keys.items():
        if len(key) not in (16, 32):
            continue
        for name, noff, nlen, toff in layouts:
            nonce = D[noff:noff + nlen]
            tag = D[toff:toff + 16]
            ct = D[noff + nlen:toff] if toff > 0 else D[noff + nlen:len(D) - 16]
            if len(tag) != 16 or len(ct) < 1:
                continue
            try:
                pt = AESGCM(key).decrypt(nonce, ct + tag, None)
                score(f"AES-GCM k={kname} {name}", pt, results)
            except Exception:
                pass
            # also ChaCha20-Poly1305
            try:
                pt = ChaCha20Poly1305(key).decrypt(nonce[:12], ct + tag, None)
                score(f"ChaCha20Poly1305 k={kname} {name}", pt, results)
            except Exception:
                pass


def try_ecb(results):
    keys = load_keys()
    for kname, key in keys.items():
        for kl in (16, 32):
            if len(key) < kl:
                continue
            try:
                dec = Cipher(algorithms.AES(key[:kl]), modes.ECB()).decryptor()
                pt = dec.update(D[:len(D) - len(D) % 16]) + dec.finalize()
            except Exception:
                continue
            for off in (0, 8, 0x28):
                score(f"AES-ECB k={kname} shift={off}", pt[off:], results)


def main():
    results = []
    try_symmetric(results)
    try_gcm(results)
    try_ecb(results)
    hits = [r for r in results if r[5]]
    print(f"# total candidates = {len(results)}")
    print(f"# candidates scoring S1/S2/S3 = {len(hits)}")
    for r in hits[:20]:
        print("  HIT", r[:5], r[6])
    print("\n# sample of 12 candidates (all non-hits unless listed above):")
    for r in results[:12]:
        print(f"  {r[0]:58s} zlib={r[1]:.3f} H={r[2]:.3f} pr={r[3]} S1={r[4]}")
    # baseline: what do the *correct* answers look like?
    print("\n# reference scores")
    score("BASELINE marker-containing plaintext", MARKER + bytes(200), results)
    print("  (marker+zeros ->", results[-1][1:5], ")")


if __name__ == "__main__":
    main()

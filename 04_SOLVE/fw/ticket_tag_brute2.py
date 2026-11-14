#!/usr/bin/env python3
"""Wider sweep for the diagnostic-ticket 16-byte tag (v2)."""
import hashlib, hmac, sys
sys.path.insert(0, r'D:\qwb\04_SOLVE\fw')
from seedkey import hash8
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

FW = open(r'D:\qwb\work\bundle2\tbox-firmware.dec.bin','rb').read()
UNW = bytes.fromhex('693d2ab06a2fe1a6e1ada23ac8bbb08ec3a8ffbbc90015ddeff28e721c9f693d')
DER = bytes.fromhex('0fd6e171919fdc1a6afcee7f81a6599c67a136fc0f57e8f210fb2acf9c92b318')
PKG = bytes.fromhex('3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0')
FC  = bytes.fromhex('5e7f07b4a81153ecd5868cc02557f823')

RAW_KEYS = {
 'unw': UNW, 'der': DER, 'pkg': PKG, 'fwcred': FC,
 'uid16': FW[0x2000:0x2010], 'c8': FW[0x2020:0x2028],
 'wrap40': FW[0x2040:0x2068], 'wrapA8': FW[0x2040:0x2048], 'wrapR32': FW[0x2048:0x2068],
 'label': b'CV6-TBOX-KEK',
}
KEYS = dict(RAW_KEYS)
# derived key variants
for n, k in list(RAW_KEYS.items()):
    KEYS[f'sha256({n})'] = hashlib.sha256(k).digest()
    KEYS[f'{n}[:16]'] = k[:16]
    if len(k) >= 32:
        KEYS[f'{n}[:32]'] = k[:32]

T = {
 'sample': (bytes.fromhex('dc8fad542b164df4aaa9913e66baac42'),
            bytes.fromhex('000000006af7c7a6'),
            bytes.fromhex('2c0950f5ab55f983bbd690b175827070')),
 'fresh' : (bytes.fromhex('1b7cebd023f9b4c31279c330d3ed7e31'),
            bytes.fromhex('000000006af7cb5d'),
            bytes.fromhex('0341afd25f89dc4add1229961f36486d')),
}

def M(nonce, exp):
    d = {}
    d['nonce'] = nonce; d['exp'] = exp
    d['nonce||exp'] = nonce + exp; d['exp||nonce'] = exp + nonce
    d['exp_be_hi'] = exp[4:]; d['nonce||exp8le'] = nonce + exp[::-1]
    d['nonce||bE442'] = nonce + b'E442'
    d['bE442||nonce'] = b'E442' + nonce
    d['nonce||exp||bE442'] = nonce + exp + b'E442'
    d['nonce||expASCII'] = nonce + str(int.from_bytes(exp, 'big')).encode()
    d['nonce&exp'] = nonce + exp[::-1]
    return d

def constructions(k, m, nonce, exp):
    if len(k) >= 16:
        yield 'hmac256[:16]', hmac.new(k, m, hashlib.sha256).digest()[:16]
        yield 'hmac256[-16:]', hmac.new(k, m, hashlib.sha256).digest()[16:]
    if len(k) >= 16:
        yield 'sha256(k||m)[:16]', hashlib.sha256(k + m).digest()[:16]
        yield 'sha256(m||k)[:16]', hashlib.sha256(m + k).digest()[:16]
        yield 'sha256(k||m)[16:]', hashlib.sha256(k + m).digest()[16:]
    if len(k) in (16, 24, 32):
        # AES-GCM tag with IV from nonce, AAD/plaintext variants
        for pt_n, pt in (('empty', b''), ('exp', exp), ('nonce', nonce)):
            for aad_n, aad in (('none', None), ('exp', exp), ('nonce', nonce)):
                try:
                    iv = nonce[:12]
                    enc = Cipher(algorithms.AES(k), modes.GCM(iv)).encryptor()
                    if aad: enc.authenticate_additional_data(aad)
                    enc.update(pt); enc.finalize()
                    yield f'gcm(iv=nonce12,aad={aad_n},pt={pt_n})', enc.tag
                except Exception: pass
        # CMAC
        try:
            c = CMAC(algorithms.AES(k)); c.update(m); yield 'cmac[:16]', c.finalize()[:16]
        except Exception: pass
        # CBC-MAC over m padded
        try:
            for ivn, iv in (('zero', bytes(16)), ('nonce', nonce)):
                data = m + b'\x80' + bytes((16 - (len(m)+1) % 16) % 16)
                c = Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor()
                out = c.update(data[:len(data)//16*16]) + c.finalize()
                yield f'cbcmac(iv={ivn})', out[-16:]
        except Exception: pass
    # firmware hash8 family -> 16 bytes
    for kn, kk in (('k', k[:8] if len(k) >= 8 else k.ljust(8, b'\0')),
                   ('ksha', hashlib.sha256(k).digest()[:8]),
                   ('krev', k[:8][::-1] if len(k) >= 8 else k.ljust(8, b'\0'))):
        for mn, mm in (('m0', m[:8].ljust(8, b'\0')), ('m1', m[8:16].ljust(8, b'\0')),
                       ('nonce0', nonce[:8]), ('nonce1', nonce[8:16]), ('exp', exp)):
            for cn, cc in (('C8', FW[0x2020:0x2028]), ('uid0', FW[0x2000:0x2008]),
                           ('uid1', FW[0x2008:0x2010]), ('zero8', bytes(8))):
                try:
                    h1 = hash8(mm, kk, cc)
                    h2 = hash8(kk, cc, mm)
                except Exception:
                    continue
                yield f'hash8({mn},{kn},{cn})||0', h1 + h2[:8]
                yield f'0||hash8({mn},{kn},{cn})', h1[::-1] + h2[::-1]

hits = []
seen = 0
for kn, k in KEYS.items():
    for tn, (nonce, exp, tag) in T.items():
        for mn, m in M(nonce, exp).items():
            for cn, c in constructions(k, m, nonce, exp):
                seen += 1
                if c is None or len(c) < 16: continue
                if c[:16] == tag:
                    hits.append((tn, kn, mn, cn, c[:16].hex()))
print("keys:", len(KEYS), " candidates evaluated:", seen)
print("HITS:", len(hits))
for h in hits: print("  ", h)

# structural probes: is tag a function of nonce only? compare across tickets via XOR
n1, e1, g1 = T['sample']; n2, e2, g2 = T['fresh']
print("\n--- structural probes ---")
print("tag1^tag2      :", bytes(x^y for x, y in zip(g1, g2)).hex())
print("nonce1^nonce2  :", bytes(x^y for x, y in zip(n1, n2)).hex())
print("exp1^exp2      :", bytes(x^y for x, y in zip(e1, e2)).hex())
print("tag^nonce  #1  :", bytes(x^y for x, y in zip(g1, n1)).hex())
print("tag^nonce  #2  :", bytes(x^y for x, y in zip(g2, n2)).hex())
print("tag^exp|exp    :", (bytes(x^y for x, y in zip(g1[:8], e1)) + bytes(x^y for x, y in zip(g1[8:], e1))).hex())

#!/usr/bin/env python3
"""Brute-force the diagnostic-ticket 16-byte tag against firmware-derived key material."""
import hashlib, hmac, itertools, struct, sys
sys.path.insert(0, r'D:\qwb\04_SOLVE\fw')
from seedkey import hash8, C_DEV

FW = open(r'D:\qwb\work\bundle2\tbox-firmware.dec.bin','rb').read()
UNWRAPPED = bytes.fromhex('693d2ab06a2fe1a6e1ada23ac8bbb08ec3a8ffbbc90015ddeff28e721c9f693d')
DERIVED   = bytes.fromhex('0fd6e171919fdc1a6afcee7f81a6599c67a136fc0f57e8f210fb2acf9c92b318')
UID16     = FW[0x2000:0x2010]
C8        = FW[0x2020:0x2028]
WRAP40    = FW[0x2040:0x2068]
PKGKEY    = bytes.fromhex('3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0')
FWCRED    = bytes.fromhex('5e7f07b4a81153ecd5868cc02557f823')
LABEL     = b'CV6-TBOX-KEK'

TICKETS = {
 'sample': (bytes.fromhex('dc8fad542b164df4aaa9913e66baac42'),
            bytes.fromhex('000000006af7c7a6'),
            bytes.fromhex('2c0950f5ab55f983bbd690b175827070')),
 'fresh' : (bytes.fromhex('1b7cebd023f9b4c31279c330d3ed7e31'),
            bytes.fromhex('000000006af7cb5d'),
            bytes.fromhex('0341afd25f89dc4add1229961f36486d')),
}
TARGET = {k: v[2] for k, v in TICKETS.items()}

KEYS = {}
for n, v in [('unwrapped32', UNWRAPPED), ('derivedKEK32', DERIVED), ('uid16', UID16),
             ('c8', C8), ('wrap40', WRAP40), ('wrapA8', WRAP40[:8]), ('wrapR32', WRAP40[8:]),
             ('pkgkey32', PKGKEY), ('fwcred16', FWCRED), ('label12', LABEL),
             ('uid16+label', UID16 + LABEL)]:
    KEYS[n] = v

def msgs(nonce, exp):
    M = {}
    M['nonce'] = nonce
    M['exp'] = exp
    M['nonce||exp'] = nonce + exp
    M['exp||nonce'] = exp + nonce
    M['nonce^exp'] = bytes(a ^ b for a, b in zip(nonce, exp + exp))
    return M

def cands(k, m, nonce, exp):
    """Yield (name, bytes) 16-byte tag candidates."""
    yield 'hmac-sha256[:16]', hmac.new(k, m, hashlib.sha256).digest()[:16]
    yield 'sha256(k||m)[:16]', hashlib.sha256(k + m).digest()[:16]
    yield 'sha256(m||k)[:16]', hashlib.sha256(m + k).digest()[:16]
    yield 'sha256(k||m)[16:]', hashlib.sha256(k + m).digest()[16:]
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        if len(k) in (16, 24, 32):
            for mode_name, mode in (('ecb', modes.ECB()), ('cbc', modes.CBC(bytes(16)))):
                c = Cipher(algorithms.AES(k), mode).encryptor()
                yield f'aes{mode_name}(k,m)[:16]', (c.update(m.ljust(16, b'\0')[:16]) + c.finalize())
    except Exception:
        pass
    # firmware hash8 (8 bytes) -- test low / high / doubled
    if len(k) >= 8:
        for tagn, tagv in (('k8=first', k[:8]), ('k8=last', k[-8:])):
            for msg8n, msg8 in (('m8=b0', m[:8]), ('m8=e0', m[-8:]), ('m8=nonce8', m[:8])):
                try:
                    h = hash8(msg8, tagv)
                except Exception:
                    continue
                yield f'hash8({msg8n},{tagn})low8', h
                yield f'hash8({msg8n},{tagn})high8', h[::-1]
                yield f'hash8({msg8n},{tagn})x2', h + h

hits = []
for kn, k in KEYS.items():
    for tn, (nonce, exp, tag) in TICKETS.items():
        for mn, m in msgs(nonce, exp).items():
            for cn, c in cands(k, m, nonce, exp):
                if c is None or len(c) < 16:
                    continue
                if c[:16] == tag:
                    hits.append((tn, kn, mn, cn, c[:16].hex()))
print("tickets:", list(TICKETS))
print("keys tested:", len(KEYS))
print("HITS:", len(hits))
for h in hits:
    print("  ", h)

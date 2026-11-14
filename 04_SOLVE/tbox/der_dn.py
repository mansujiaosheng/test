#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Byte-level DN / SKI / AKI facts for the T-BOX mTLS bypass tests.

The "naive validation" hypotheses are all about *string/byte* comparison (issuer
DN, subject DN, SKI). Asserting "the forged DN is byte-identical to the real
root DN" needs the raw DER of the Name, not the `openssl x509 -subject`
rendering -- and crucially the printable-string TAG (0x13 PrintableString vs
0x0C UTF8String) is part of those bytes.

This parses the DER itself so claims are checkable.

Usage:
  python der_dn.py <cert.pem> [...]          # per-cert subject/issuer DER + SKI + AKI
  python der_dn.py --cmp a.pem b.pem         # a.issuer vs b.subject, a.AKI vs b.SKI
"""
import base64
import re
import sys


# --- DER helpers: rd() -> (tag, content_start, content_len, next_offset) --------
def rd(buf, off):
    tag = buf[off]
    l = buf[off + 1]
    cs = off + 2
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(buf[cs:cs + n], "big")
        cs += n
    return tag, cs, l, cs + l


def walk(buf, off, want):
    """Return (tag, start, len, next) of the `want`-th child of the SEQUENCE at off."""
    tag, cs, l, nxt = rd(buf, off)
    assert tag in (0x30, 0x31, 0xA0), "not a constructed tag: 0x%02x" % tag
    p = cs
    i = 0
    while p < nxt:
        t, s, ln, nx = rd(buf, p)
        if i == want:
            return t, s, ln, nx
        p = nx
        i += 1
    raise IndexError("no child %d" % want)


def pem_to_der(path):
    data = open(path, "rb").read()
    if b"-----BEGIN" not in data:
        return data
    m = re.search(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", data, re.S)
    return base64.b64decode(re.sub(rb"\s", b"", m.group(1)))


def extensions_OF(der, tbs_off, tbs_next):
    """Return list of (oid_dotted, extnValue_bytes) for the cert's extensions."""
    out = []
    p = tbs_off
    while p < tbs_next:
        t, s, ln, nx = rd(der, p)
        if t == 0xA3:                     # [3] EXPLICIT Extensions
            _, es, el, _ = rd(der, s)     # SEQUENCE OF Extension
            q = es
            while q < es + el:
                _, xs, xl, xq = rd(der, q)
                ot, os_, ol, onx = rd(der, xs)
                oid = der[os_:os_ + ol]
                vt, vs, vl, _ = rd(der, onx)   # extnValue OCTET STRING
                out.append((oid.hex(), der[vs:vs + vl]))
                q = xq
        p = nx
    return out


OID_SKI = "551d0e"
OID_AKI = "551d23"
OID_CN = bytes.fromhex("550403")


def name_dn(der, off):
    """Offsets of the Name TLV that starts at off -> raw DER slice."""
    t, s, ln, nx = rd(der, off)
    return der[off:nx]


def parse_cert(path):
    der = pem_to_der(path)
    _, cert_cs, _, cert_nx = rd(der, 0)            # Certificate SEQUENCE
    _, tbs_cs, tbs_len, tbs_nx = rd(der, cert_cs)  # tbsCertificate SEQUENCE
    p = tbs_cs
    t, s, ln, nx = rd(der, p)
    if t == 0xA0:                                   # [0] version
        p = nx
    p = rd(der, p)[3]                               # serialNumber
    p = rd(der, p)[3]                               # signature algorithm
    issuer_off = p
    p = rd(der, p)[3]                               # issuer Name
    p = rd(der, p)[3]                               # validity
    subject_off = p
    p = rd(der, p)[3]                               # subject Name
    spki_off = p                                    # subjectPublicKeyInfo
    exts = extensions_OF(der, tbs_cs, tbs_nx)
    ski = aki = None
    for oid, val in exts:
        if oid == OID_SKI:
            # SubjectKeyIdentifier ::= OCTET STRING  (extnValue wraps it)
            t2, s2, l2, _ = rd(val, 0)
            ski = val[s2:s2 + l2]
        elif oid == OID_AKI:
            # AuthorityKeyIdentifier ::= SEQUENCE { [0] keyIdentifier OCTET STRING OPTIONAL ... }
            _, ss, sl, _ = rd(val, 0)
            q = ss
            while q < ss + sl:
                t3, s3, l3, q3 = rd(val, q)
                if t3 == 0x80:
                    aki = val[s3:s3 + l3]
                    break
                q = q3
    return {"der": der, "subject": name_dn(der, subject_off),
            "issuer": name_dn(der, issuer_off), "ski": ski, "aki": aki,
            "spki": der[spki_off:rd(der, spki_off)[3]]}


def cn_tag(dn):
    i = dn.find(OID_CN)
    return dn[i + 3] if i >= 0 else None


def show(path):
    c = parse_cert(path)
    t = cn_tag(c["subject"])
    print("=== %s" % path)
    print("  subject DN DER : %s" % c["subject"].hex())
    print("  issuer  DN DER : %s" % c["issuer"].hex())
    print("  SKI            : %s" % (c["ski"].hex() if c["ski"] else "(absent)"))
    print("  AKI            : %s" % (c["aki"].hex() if c["aki"] else "(absent)"))
    print("  CN string tag  : %s" % (
        "0x%02x PrintableString" % t if t == 0x13 else
        "0x%02x UTF8String" % t if t == 0x0C else "0x%02x" % t if t else "(no CN)"))


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--cmp":
        a, b = parse_cert(sys.argv[2]), parse_cert(sys.argv[3])
        print("A (%s) issuer  DN : %s" % (sys.argv[2], a["issuer"].hex()))
        print("B (%s) subject DN : %s" % (sys.argv[3], b["subject"].hex()))
        print("ISSUER_DN == SUBJECT_DN : %s" % (a["issuer"] == b["subject"]))
        print("A AKI : %s" % (a["aki"].hex() if a["aki"] else "(absent)"))
        print("B SKI : %s" % (b["ski"].hex() if b["ski"] else "(absent)"))
        print("AKI == SKI : %s" % (a["aki"] is not None and a["aki"] == b["ski"]))
    elif len(sys.argv) > 1:
        for p in sys.argv[1:]:
            show(p)
    else:
        print(__doc__)

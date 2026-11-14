#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal DER RDNSequence parser + byte-equality cross-check.

Used to prove exactly what DN the T-BOX 8443 server puts in the TLS1.3
CertificateRequest `certificate_authorities` extension, with no dependency on
private cryptography APIs.
"""
import sys

OID_NAMES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
    "2.5.4.9": "street", "2.5.4.17": "postalCode", "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID", "1.2.840.113549.1.9.1": "emailAddress",
}
STR_TAGS = {0x0C: "UTF8String", 0x13: "PrintableString", 0x16: "IA5String",
            0x14: "T61String", 0x1E: "BMPString", 0x1A: "VisibleString"}


def read_tlv(buf, i):
    tag = buf[i]
    i += 1
    ln = buf[i]
    i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[i:i + n], "big")
        i += n
    return tag, buf[i:i + ln], i + ln


def decode_oid(b):
    if not b:
        return ""
    vals = []
    first = b[0]
    vals.append(str(first // 40))
    vals.append(str(first % 40))
    v = 0
    for byte in b[1:]:
        v = (v << 7) | (byte & 0x7F)
        if not byte & 0x80:
            vals.append(str(v))
            v = 0
    return ".".join(vals)


def parse_name(der):
    """RDNSequence -> list of (oid, value)."""
    tag, seq, _ = read_tlv(der, 0)
    assert tag == 0x30, f"expect SEQUENCE, got 0x{tag:02x}"
    out = []
    i = 0
    while i < len(seq):
        tag, aset, i = read_tlv(seq, i)
        assert tag == 0x31, f"expect SET, got 0x{tag:02x}"
        j = 0
        while j < len(aset):
            tag, trio, j = read_tlv(aset, j)
            assert tag == 0x30, f"expect SEQUENCE, got 0x{tag:02x}"
            k = 0
            tag, oidb, k = read_tlv(trio, k)
            tag2, valb, k = read_tlv(trio, k)
            out.append((decode_oid(oidb),
                        STR_TAGS.get(tag2, f"tag0x{tag2:02x}"),
                        valb.decode("utf-8", "replace")))
    return out


def main():
    hexder = sys.argv[1] if len(sys.argv) > 1 else (
        "3025312330210603550403131a43563620466c65657420446961676e6f737469637320526f6f74")
    der = bytes.fromhex(hexder)
    print(f"# DER ({len(der)} bytes): {der.hex()}")
    attrs = parse_name(der)
    print(f"# RDN attribute count = {len(attrs)}")
    for oid, tname, val in attrs:
        print(f"  {OID_NAMES.get(oid, oid)} ({oid}) [{tname}] = {val!r}")

    # cross-check: rebuild the same DN with cryptography and compare bytes
    try:
        from cryptography import x509
        from cryptography.x509.oid import ObjectIdentifier
        name = x509.Name([
            x509.RelativeDistinguishedName([
                x509.NameAttribute(ObjectIdentifier(oid), val)
            ]) for oid, tname, val in attrs
        ])
        rebuilt = name.public_bytes() if hasattr(name, "public_bytes") else None
        if rebuilt is None:
            from cryptography.hazmat.primitives.serialization import Encoding
            try:
                rebuilt = name.public_bytes(_backend=None)  # type: ignore
            except TypeError:
                rebuilt = name.public_bytes(None)  # type: ignore
        print(f"# rebuilt DER: {rebuilt.hex() if rebuilt else 'n/a'}")
        print(f"# BYTE-EQUAL: {rebuilt == der}")
    except Exception as e:
        print(f"# rebuild skipped: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Decode the TLS1.3 CertificateRequest sent by 10.230.164.3:8443 straight out of
an `openssl s_client -msg` hex dump, so we know exactly what CA the server
trusts (full DN, DER bytes) and what extensions it advertises.

Input : a capture file produced by -msg (e.g. 0009_hs_nocert.txt)
Output: decoded structure on stdout
"""
import re
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


def grab_handshake(path, want):
    """Return (length, bytes) of the first handshake message named `want`."""
    txt = open(path, encoding="utf-8", errors="replace").read()
    lines = txt.splitlines()
    # locate the ">>> TLS 1.3, Handshake [length xxxx], CertificateRequest" line
    # the server's messages are '<<<'
    pat = re.compile(r"^<<< TLS 1\.3, Handshake \[length ([0-9a-f]{4})\], %s\b" % re.escape(want))
    start = None
    length = None
    for i, ln in enumerate(lines):
        m = pat.match(ln.strip())
        if m:
            start = i + 1
            length = int(m.group(1), 16)
            break
    if start is None:
        return None, None
    hexbytes = []
    for ln in lines[start:]:
        s = ln.strip()
        if s.startswith("<<<") or s.startswith(">>>") or s.startswith("SSL_connect") or s.startswith("---"):
            break
        # openssl 3.0 -msg dumps either "0000 - 02 01 .." or bare "  02 01 ..";
        # strip an optional leading offset, then take pure hex-pair lines only.
        m = re.match(r"^(?:[0-9a-f]{4} - )?((?:[0-9a-f]{2})(?: [0-9a-f]{2})*)$", s)
        if not m:
            if not s:
                continue
            break
        hexbytes.extend(m.group(1).split())
    raw = bytes.fromhex("".join(hexbytes))
    # raw includes the 4-byte handshake header (type + 3-byte length); drop it
    if len(raw) >= 4 and raw[0] in (0x0b, 0x0d, 0x02, 0x08):
        declared = int.from_bytes(raw[1:4], "big")
        if declared == len(raw) - 4:
            return length, raw[4:]
    return length, raw


def name_to_str(der):
    try:
        n = x509.Name.from_der  # not available; parse via CertificateBuilder trick
    except AttributeError:
        pass
    return None


def parse_dn(der):
    """Minimal DER RDNSequence parser -> list of (oid, value) using cryptography."""
    # x509.Name has no public from_der; use the private API if present
    try:
        from cryptography.x509.name import _parse_name  # type: ignore
        return _parse_name(der)
    except Exception:
        return None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else r"D:\qwb\03_EVIDENCE\tbox\0009_hs_nocert.txt"
    length, body = grab_handshake(path, "CertificateRequest")
    print(f"# source: {path}")
    if body is None:
        print("!! CertificateRequest not found")
        return 1
    print(f"# handshake length field: {length} (0x{length:04x}), captured {len(body)} bytes")
    print(f"# raw DER: {body.hex()}")
    print()

    # CertificateRequest (TLS 1.3, RFC 8446 4.3.2):
    #   opaque certificate_request_context<0..2^8-1>;
    #   Extension extensions<2..2^16-1>;
    i = 0
    ctx_len = body[i]
    i += 1
    ctx = body[i:i + ctx_len]
    i += ctx_len
    print(f"certificate_request_context: len={ctx_len} value={ctx.hex() or '(empty)'}")

    ext_total = int.from_bytes(body[i:i + 2], "big")
    i += 2
    print(f"extensions: total_len={ext_total}")
    end = i + ext_total
    EXT_NAMES = {
        0x0000: "server_name",
        0x0001: "max_fragment_length",
        0x0005: "status_request",
        0x000a: "supported_groups",
        0x000b: "ec_point_formats",
        0x000d: "signature_algorithms",
        0x000e: "use_srtp",
        0x0010: "application_layer_protocol_negotiation",
        0x0012: "signed_certificate_timestamp",
        0x0015: "padding",
        0x0016: "encrypt_then_mac",
        0x0017: "extended_master_secret",
        0x0023: "session_ticket",
        0x002b: "supported_versions",
        0x002c: "psk_key_exchange_modes",
        0x002d: "psk_key_exchange_modes",
        0x002f: "certificate_authorities",
        0x0032: "signature_algorithms_cert",
        0x0033: "key_share",
    }
    SIG = {
        0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384",
        0x0603: "ecdsa_secp521r1_sha512", 0x0401: "rsa_pkcs1_sha256",
        0x0501: "rsa_pkcs1_sha384", 0x0601: "rsa_pkcs1_sha512",
        0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384",
        0x0806: "rsa_pss_rsae_sha512", 0x0807: "ed25519", 0x0808: "ed448",
        0x0809: "rsa_pss_pss_sha256", 0x080a: "rsa_pss_pss_sha384",
        0x080b: "rsa_pss_pss_sha512", 0x0201: "rsa_pkcs1_sha1",
        0x0203: "ecdsa_sha1",
    }
    while i < end:
        etype = int.from_bytes(body[i:i + 2], "big")
        elen = int.from_bytes(body[i + 2:i + 4], "big")
        edata = body[i + 4:i + 4 + elen]
        nm = EXT_NAMES.get(etype, f"unknown(0x{etype:04x})")
        print(f"  - ext 0x{etype:04x} {nm}  len={elen}  data={edata.hex()}")
        if etype == 0x002f:  # certificate_authorities
            j = 0
            total = int.from_bytes(edata[j:j + 2], "big")
            j += 2
            print(f"      distinguished_names total_len={total}")
            k = 0
            while j < 2 + total:
                dnlen = int.from_bytes(edata[j:j + 2], "big")
                j += 2
                dn = edata[j:j + dnlen]
                j += dnlen
                k += 1
                print(f"      [{k}] len={dnlen} DER={dn.hex()}")
                parsed = parse_dn(dn)
                if parsed is not None:
                    print(f"      [{k}] DN={parsed.rfc4514_string()}")
                    for attr in parsed:
                        print(f"            {attr.oid._name}({attr.oid.dotted_string}) = {attr.value!r}")
        elif etype in (0x000d, 0x0032):  # signature_algorithms / _cert
            j = 0
            total = int.from_bytes(edata[j:j + 2], "big")
            j += 2
            algos = []
            while j + 2 <= 2 + total:
                v = int.from_bytes(edata[j:j + 2], "big")
                algos.append(SIG.get(v, f"0x{v:04x}"))
                j += 2
            print(f"      count={len(algos)}: {', '.join(algos)}")
        i += 4 + elen
    return 0


if __name__ == "__main__":
    sys.exit(main())

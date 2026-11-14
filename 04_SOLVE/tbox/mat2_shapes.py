#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Odd-shaped self-signed client certs (w5..w9) for the 8443 mTLS bypass tests.

w5 empty subject DN            -> does the server even parse a DN-less cert?
w6 200-char CN                 -> RFC5280 caps CN at 64; is that enforced?
w7 not-yet-valid (2030)        -> expired/not-yet-valid discrimination
w8 expired (2020)              -> baseline for alert 45 certificate_expired
w9 self-signed but *named* exactly like the root, SKI = real root SKI,
   offered as the client certificate -> tests "identity by name" checks
"""
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REAL_ROOT_SKI = "476e90164f6470bb1c807236ab3c547003781099"


def emit(tag, cert, key):
    open(tag + ".pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(tag + ".key", "wb").write(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))


now = datetime.datetime.now(datetime.timezone.utc)


def build(subject, key, nb, na, san=("tbox",)):
    b = (x509.CertificateBuilder()
         .subject_name(subject).issuer_name(subject)
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                                      encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False)
    return b.sign(key, hashes.SHA256())


# w5: completely empty subject DN
k = ec.generate_private_key(ec.SECP256R1())
emit("w5_empty_subject", build(x509.Name([]), k, now - datetime.timedelta(days=1),
                               now + datetime.timedelta(days=60)), k)

# w6: 200-char CN (bypassing the library's 64-byte guard, which is exactly what a
# hand-rolled attacker cert would do)
k = ec.generate_private_key(ec.SECP256R1())
long_cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t" * 200, _validate=False)])
emit("w6_long_cn", build(long_cn, k, now - datetime.timedelta(days=1),
                         now + datetime.timedelta(days=60)), k)

# w7: not-yet-valid
k = ec.generate_private_key(ec.SECP256R1())
emit("w7_future", build(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "diag-eng-01")]), k,
                        datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
                        datetime.datetime(2031, 1, 1, tzinfo=datetime.timezone.utc)), k)

# w8: expired
k = ec.generate_private_key(ec.SECP256R1())
emit("w8_expired", build(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "diag-eng-01")]), k,
                         datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
                         datetime.datetime(2020, 6, 1, tzinfo=datetime.timezone.utc)), k)

# w9: named exactly like the root, SKI = real root SKI, handed over as the CLIENT cert
k = ec.generate_private_key(ec.SECP256R1())
root_dn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CV6 Fleet Diagnostics Root")])
c = (x509.CertificateBuilder().subject_name(root_dn).issuer_name(root_dn)
     .public_key(k.public_key()).serial_number(x509.random_serial_number())
     .not_valid_before(now - datetime.timedelta(days=1))
     .not_valid_after(now + datetime.timedelta(days=90))
     .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
     .add_extension(x509.SubjectKeyIdentifier(digest=bytes.fromhex(REAL_ROOT_SKI)), critical=False)
     .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
     .sign(k, hashes.SHA256()))
emit("w9_root_named_ski", c, k)

print("built w5 w6 w7 w8 w9")

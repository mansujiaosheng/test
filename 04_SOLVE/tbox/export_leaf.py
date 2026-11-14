#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Export everything that is actually obtainable about the 10.230.164.3:8443
certificate chain, and prove it matches the live server.

Important: the server sends ONLY its leaf (chain length 1). The issuer
"CV6 Fleet Diagnostics Root" is never transmitted — neither as a certificate
nor inside CertificateRequest (which carries the CA *name* only). So a "root CA
PEM export" is not possible from the wire; what we can export is the leaf plus
every field that references the root (issuer DN, AKI = root SKI).
"""
import hashlib
import socket
import ssl

HOST, PORT = "10.230.164.3", 8443
OUT_PEM = r"D:\qwb\03_EVIDENCE\tbox\0014_srv_leaf_tbox.pem"
OUT_DER = r"D:\qwb\03_EVIDENCE\tbox\0014_srv_leaf_tbox.der"

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
raw = socket.create_connection((HOST, PORT), timeout=8)
s = ctx.wrap_socket(raw, server_hostname="tbox")
der = s.getpeercert(binary_form=True)
print("live peer cert sha256:", hashlib.sha256(der).hexdigest())
print("live tls:", s.version(), s.cipher()[0])
open(OUT_DER, "wb").write(der)
pem = ssl.DER_cert_to_PEM_cert(der)
open(OUT_PEM, "w", encoding="ascii", newline="\n").write(pem)
print("wrote", OUT_PEM)
print("wrote", OUT_DER)
s.close()

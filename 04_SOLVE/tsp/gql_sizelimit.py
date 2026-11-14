#!/usr/bin/env python3
"""
Pin down the exact /graphql body-size limit -> identifies http.MaxBytesReader(w,r.Body,1<<20).
Also probe a few residual parser tricks. Read-only.
"""
import json
import sys

import requests

T = "http://10.230.164.2:8080/graphql"
H = {"Content-Type": "application/json"}
S = requests.Session()


def post(data):
    r = S.post(T, data=data, headers=H, timeout=20)
    return r.status_code, r.content


def body_of_total(n):
    """valid JSON object whose total encoded size is exactly n bytes."""
    # {"pad":"..."}  -> 9 overhead chars: {"pad":" + "}
    over = 9
    if n < over:
        raise ValueError
    return b'{"pad":"' + b"A" * (n - over) + b'"}'


print("=" * 74)
print("/graphql body size limit search (valid JSON, single 'pad' string key)")
print("=" * 74)
print("hypothesis: http.MaxBytesReader(w, r.Body, 1<<20) => 1048576 works, 1048577 fails")
print()
for n in (1024, 65536, 1048570, 1048575, 1048576, 1048577, 1048580, 1048600, 2000000):
    b = body_of_total(n)
    sc, ct = post(b)
    print(f"  len={n:>9}  -> {sc}  {ct[:90]!r}")

print()
print("--- confirm boundary by bisection between 100000 and 2000000 ---")
lo, hi = 1, 2_000_000
# lo is known-good, hi known-bad
while lo + 1 < hi:
    mid = (lo + hi) // 2
    sc, ct = post(body_of_total(mid))
    good = (sc == 200)
    if good:
        lo = mid
    else:
        hi = mid
print(f"  largest accepted body = {lo} bytes (HTTP 200)")
print(f"  smallest rejected     = {hi} bytes")
print(f"  1<<20 = {1 << 20}")
print(f"  1<<20 - 1 = {(1 << 20) - 1}")
print(f"  lo == 1<<20 ? {lo == (1 << 20)}   lo == (1<<20)-1 ? {lo == (1 << 20) - 1}")

print()
print("=" * 74)
print("residual parser tricks")
print("=" * 74)
cases = [
    ("empty body", b""),
    ("whitespace only", b"   \n\t "),
    ("json with comments", b'{"query":"a"} // c'),
    ("single quote", b"{'query':'a'}"),
    ("query true", b'{"query":true}'),
    ("query float", b'{"query":1.5}'),
    ("query empty arr str", b'{"query":[]}'),
    ("deep 9000", b'{"a":' * 9000 + b"1" + b"}" * 9000),
    ("utf8 overlong", b'{"query":"\xc0\x80"}'),
    ("nul in string", b'{"query":"a\x00b"}'),
    ("exponent int", b'{"query":1e3}'),
    ("big int str field", b'{"query":99999999999999999999}'),
]
for name, d in cases:
    try:
        sc, ct = post(d)
        print(f"  {name:22s} -> {sc} {ct[:100]!r}")
    except Exception as e:
        print(f"  {name:22s} -> EXC {type(e).__name__}: {e}")

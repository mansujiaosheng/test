# -*- coding: utf-8 -*-
import sys, hashlib, time, json
sys.path.insert(0, "04_SOLVE/tsp")
from httpc import request, request_raw

H, P = "10.230.164.2", 8080
OUT = []
def p(s):
    print(s, flush=True); OUT.append(s)

p("="*84)
p("0403  Router fingerprint on 10.230.164.2:8080  (301=net/http ServeMux | 307=RedirectFixedPath)")
p(f"      run at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
p("="*84)

cases = [
    # (method, path, note)
    ("GET",  "/graphql",            "exact route"),
    ("POST", "/graphql",            "exact route"),
    ("GET",  "/ota/../graphql",     "clean-path -> MATCHES existing route"),
    ("POST", "/ota/../graphql",     "clean-path -> MATCHES existing route"),
    ("HEAD", "/ota/../graphql",     "clean-path -> MATCHES existing route"),
    ("GET",  "/ota/../nope",        "clean-path -> does NOT match any route"),
    ("POST", "/ota/../nope",        "clean-path -> does NOT match any route"),
    ("GET",  "/./graphql",          "dot segment -> matches"),
    ("GET",  "/GraphQL",            "case variant -> matches case-insensitively?"),
    ("POST", "/GraphQL",            "case variant"),
    ("GET",  "/GRAPHQL",            "case variant"),
    ("GET",  "/graphql/",           "trailing slash"),
    ("POST", "/graphql/",           "trailing slash"),
    ("GET",  "//graphql",           "double slash"),
    ("GET",  "/graphql/../ota",     "clean -> /ota (no such route)"),
    ("GET",  "/ota/../graphql?a=1", "clean + query string preservation"),
    ("GET",  "/healthz/../graphql", "clean via healthz"),
    ("GET",  "/OTA/../graphql",     "clean + case"),
]
p(f"{'method':<7}{'path':<26}{'status':<7}{'Location':<16}note")
p("-"*84)
for m, pa, note in cases:
    try:
        r = request(H, P, m, pa, headers=[("Content-Type","application/json")], body=b"{}" if m in ("POST",) else b"")
        p(f"{m:<7}{pa:<26}{r.status:<7}{(r.h('location') or '-'):<16}{note}")
        p(f"        allow={r.h('allow')!r} body={r.body[:70]!r}")
    except Exception as e:
        p(f"{m:<7}{pa:<26}ERR    -               {note}  {e!r}")

p("")
p("="*84)
p("0403-B  405 response header set on /graphql (custom JSON vs httprouter default)")
p("="*84)
r = request(H, P, "GET", "/graphql")
p(f"  status={r.status} headers={r.headers}")
p(f"  body={r.body!r}")
r = request(H, P, "PUT", "/graphql")
p(f"  PUT status={r.status} allow={r.h('allow')!r} body={r.body!r}")

p("")
p("="*84)
p("0403-C  determinism: 25 identical POST /graphql, sha256 of decoded body")
p("="*84)
hs = {}
for i in range(25):
    r = request(H, P, "POST", "/graphql", headers=[("Content-Type","application/json")],
                body=b'{"query":"{vehicles{vin}}"}')
    h = hashlib.sha256(r.body).hexdigest()[:16]
    hs[h] = hs.get(h, 0) + 1
    if i < 3: p(f"  [{i}] status={r.status} len={len(r.body)} {r.body!r}")
p(f"  distinct={len(hs)} -> {hs}")
p(f"  reference sha256(full)={hashlib.sha256(b'{\"data\":{\"vehicles\":[{\"label\":\"Guest demo vehicle\",\"vin\":\"CV6000000DEMO0001\"}]}}\\n').hexdigest()[:16]}")

p("")
p("="*84)
p("0403-D  'still a stub' probes: semantically illegal GraphQL must not error")
p("="*84)
bodies = [
    b'{"query":"{ ) }"}',
    b'{"query":"this is not graphql at all"}',
    b'{"query":"subscription{__typename}"}',
    b'{"query":"{ vehicles { vin label { sub } } }"}',
    b'{"query":"{__schema{types{name}}}"}',
    b'{"query":"mutation{__typename}"}',
]
for b in bodies:
    r = request(H, P, "POST", "/graphql", headers=[("Content-Type","application/json")], body=b)
    p(f"  {b.decode()[:56]:<58} -> {r.status} {r.body[:96]!r}")

open("03_EVIDENCE/tsp/0403_router_fingerprint.txt","w",encoding="utf-8").write("\n".join(OUT)+"\n")

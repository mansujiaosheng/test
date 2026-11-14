#!/usr/bin/env python3
"""Internal-API discovery on TSP 10.230.164.2:8080.

Oracle discovered at 09:36:
  unregistered path  -> 404 'text/plain' body exactly "404 page not found\n"   (Go ServeMux default)
  registered API path-> 404 'application/json' body '{"error":"not found"}\n'  (handler's own 404)

So: any response that is NOT the Go default 404 proves a route exists.
Sweep /internal/*, /api/*, /public/* and friends, GET + POST, report anything
that is not the plain-text default 404.

Rate-limited: 8 workers, one connection per request, no keep-alive reuse.
"""
import http.client, json, sys, time
from concurrent.futures import ThreadPoolExecutor

HOST, PORT = "10.230.164.2", 8080
DEFAULT_404 = b"404 page not found\n"

WORDS = """
audit audits
sign signer signing signature
ota ota/update ota/packages ota/package ota/campaign ota/campaigns ota/manifest
campaign campaigns
vehicle vehicles vin vins
release releases release/create release/generate releases/create releases/generate
image images image/new image/build
firmware package packages artifact artifacts bundle bundles
key keys cert certs pki ca
diag diagnostics dtc report reports
log logs event events trace traces
health status info version config
metrics debug admin users user me token tokens auth
interfaces routes schema graphql
engine engineering project projects build builds flash flash/request
update updates check poll job jobs task tasks queue
""".split()

PREFIXES = ["/internal/", "/api/", "/api/v1/", "/api/v2/", "/public/", "/v1/", "/v2/", "/"]

PATHS = []
for pre in PREFIXES:
    for w in WORDS:
        PATHS.append(pre + w)
# a few explicit extras
PATHS += ["/internal/audit", "/internal", "/public/signer/sign", "/api/v2/releases/create"]

PATHS = list(dict.fromkeys(PATHS))


def probe(path, method="GET", body=None, timeout=6.0):
    c = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    hdrs = {"Accept": "application/json", "Connection": "close"}
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    try:
        c.request(method, path, body=body, headers=hdrs)
        r = c.getresponse()
        data = r.read(4096)
        return r.status, r.getheader("Content-Type"), data
    except Exception as e:
        return -1, "<%s>" % type(e).__name__, str(e)[:80].encode()
    finally:
        try: c.close()
        except Exception: pass


def work(args):
    path, method, body = args
    st, ct, data = probe(path, method, body)
    return path, method, st, ct, data


jobs = [(p, "GET", None) for p in PATHS]
print("probing %d GET paths, oracle = response != %r" % (len(jobs), DEFAULT_404), flush=True)
t0 = time.time()
hits = []
with ThreadPoolExecutor(max_workers=8) as ex:
    for path, method, st, ct, data in ex.map(work, jobs):
        is_default = (st == 404 and data == DEFAULT_404)
        if not is_default:
            hits.append((path, method, st, ct, data))
            print("HIT %s %-6s %s ct=%s body=%r" % (method, path, st, ct, data[:200]), flush=True)
print("--- GET done %.1fs, hits=%d" % (time.time() - t0, len(hits)), flush=True)

# Now POST to every hit (and to the known /internal/audit) with a few bodies
targets = sorted({h[0] for h in hits} | {"/internal/audit"})
bodies = [None, b"{}", b'{"vin":"CV6FF52FEE9EDDD86"}', b'{"vehicle":"CV6FF52FEE9EDDD86"}']
print("\n--- POST phase on %d targets ---" % len(targets), flush=True)
post_hits = []
for t in targets:
    for b in bodies:
        path, method, st, ct, data = work((t, "POST", b))
        tag = "SAME" if (st == 404 and data.startswith(b'{"error":"not found"')) else "DIFF"
        if tag == "DIFF":
            post_hits.append((path, b, st, data))
        print("POST %-40s body=%-40r -> %s %r  [%s]" % (path, b, st, data[:120], tag), flush=True)

json.dump({"get_hits": [{"path": p, "method": m, "status": s, "ct": c,
                        "body": d.decode("utf-8", "replace")} for p, m, s, c, d in hits],
           "post_hits": [{"path": p, "body": (b.decode() if b else None),
                          "status": s, "resp": d.decode("utf-8", "replace")}
                         for p, b, s, d in post_hits]},
          open("D:/qwb/03_EVIDENCE/tsp/0320_internal_api_discovery.json", "w"), indent=1)
print("total hits GET=%d POST=%d" % (len(hits), len(post_hits)))

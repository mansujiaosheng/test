#!/usr/bin/env python3
"""T-09 / tbox: targeted 8080 route hunt (two-phase).

Why this is not a repeat of the earlier 1576-path sweep:
  Go >= 1.22 ServeMux registers method-scoped patterns such as "POST /ota/download".
  A request with an unregistered METHOD still matches the path and returns
  405 + Allow:, not 404.  So a HEAD-only sweep already surfaces every registered
  path regardless of which method it wants, and phase 2 then enumerates methods.

Vocabulary is derived from the task text itself:
  address / plaintext length / encrypted-package length / rollback /
  TransferData block length / Programming Session / UDS / DoIP / OTA.
"""
import http.client, json, sys, itertools, time
from concurrent.futures import ThreadPoolExecutor

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.230.164.3"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
OUT = sys.argv[3] if len(sys.argv) > 3 else "out"
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

BASES = [
    "session", "sessions", "programming", "programmingsession", "programming-session",
    "programming_session", "enter", "start", "download", "requestdownload",
    "request-download", "request_download", "transferdata", "transfer-data",
    "transfer", "upload", "block", "blocks", "blocklength", "block-length",
    "maxblock", "rollback", "antirollback", "address", "offset", "length", "size",
    "plaintext", "encrypted", "ciphertext", "firmware", "fw", "ota", "update",
    "upgrade", "package", "pkg", "image", "manifest", "metadata", "descriptor",
    "bundle", "payload", "signature", "sign", "verify", "sig", "hash", "digest",
    "cert", "certs", "certificate", "ca", "ca.pem", "ca.crt", "client.pem",
    "client.crt", "client.key", "tls", "mtls", "pki", "trust", "truststore",
    "keystore", "provision", "provisioning", "diagnostics", "diagnostic", "diag",
    "uds", "doip", "vin", "ecu", "ecus", "vcu", "bcm", "bms", "tbox", "cgw",
    "gateway", "campaign", "job", "jobs", "task", "flash", "status", "state",
    "info", "health", "version", "config", "debug", "metrics", "admin", "internal",
    "api", "v1", "v2", "graphql", "ws", "events", "enroll", "issue", "csr",
    "scep", "est", "crl", "device", "devices", "vehicle", "vehicles", "fleet",
    "cv6", "key", "keys", "token", "auth", "login", "unlock", "factory",
]
PREFIXES = ["", "api/", "api/v1/", "v1/", "tbox/", "cv6/", "fleet/", "diag/",
            "ota/", "uds/", "internal/", "admin/", "api/v1/tbox/"]
SUFFIXES = ["", "/", "/request", "/start", "/status", "/0"]

VIN = "CV6FF52FEE9EDDD86"
EXTRA = [
    "/healthz", "/", "/ota", "/api", "/api/", "/api/v1", "/v1",
    f"/vehicles/{VIN}", f"/vehicle/{VIN}", f"/api/v1/vehicles/{VIN}",
    f"/api/vehicles/{VIN}", f"/vin/{VIN}", f"/cv6/{VIN}",
    f"/vehicles/{VIN}/ota", f"/vehicles/{VIN}/download",
    f"/vehicles/{VIN}/diagnostics", f"/vehicles/{VIN}/firmware",
    "/vehicles/CV6000000DEMO0001", "/download/0", "/ota/0", "/firmware/0",
    "/programming/session", "/uds/session", "/health", "/healthz/",
]


def build():
    seen, paths = set(), []
    for p in EXTRA:
        if p not in seen:
            seen.add(p); paths.append(p)
    for pre, base, suf in itertools.product(PREFIXES, BASES, SUFFIXES):
        p = "/" + pre + base + suf
        if len(p) > 110 or p in seen:
            continue
        seen.add(p); paths.append(p)
    return paths


def req(method, path, body=None):
    c = http.client.HTTPConnection(HOST, PORT, timeout=8)
    hdrs = {"User-Agent": "t09-tbox-routehunt/1.1", "Connection": "close"}
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    try:
        c.request(method, path, body=body, headers=hdrs)
        r = c.getresponse()
        data = r.read(400)
        return r.status, dict(r.getheaders()), data
    except Exception as e:
        return None, {}, repr(e).encode()
    finally:
        try: c.close()
        except Exception: pass


def head_probe(p):
    st, hd, body = req("HEAD", p)
    neg = (st == 404 and (body == b"" or b"404 page not found" in body))
    return None if neg else {"p": p, "st": st, "allow": hd.get("Allow"),
                             "ct": hd.get("Content-Type"), "len": hd.get("Content-Length")}


def main():
    paths = build()
    print(f"# phase1 HEAD preset over {len(paths)} paths on {HOST}:{PORT}", flush=True)
    t0 = time.time()
    hits = []
    with ThreadPoolExecutor(max_workers=24) as ex:
        for r in ex.map(head_probe, paths):
            if r:
                hits.append(r)
                print(f"HIT {r['st']} {r['p']}  Allow={r['allow']} ct={r['ct']} len={r['len']}", flush=True)
    print(f"=== phase1: {len(paths)} HEAD in {time.time()-t0:.0f}s, {len(hits)} non-404 ===", flush=True)

    print("# phase2 full method matrix on hits", flush=True)
    full = []
    with open(OUT + "_methods.txt", "w", encoding="utf-8") as f:
        for h in hits:
            for m in METHODS:
                body = b"{}" if m in ("POST", "PUT", "PATCH") else None
                st, hd, data = req(m, h["p"], body)
                rec = {"m": m, "p": h["p"], "st": st, "allow": hd.get("Allow"),
                       "ct": hd.get("Content-Type"), "len": hd.get("Content-Length"),
                       "body": data[:200].decode("latin1")}
                full.append(rec)
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    with open(OUT + ".hits.json", "w", encoding="utf-8") as f:
        json.dump({"head_hits": hits, "methods": full}, f, indent=1, ensure_ascii=False)
    print(f"=== done: {len(hits)} paths exposed ===")


if __name__ == "__main__":
    main()

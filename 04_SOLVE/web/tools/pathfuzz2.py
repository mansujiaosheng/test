#!/usr/bin/env python3
"""Concurrent path discovery for Go-style services (404 page not found baseline).
Tries GET and POST, records non-404 responses. Usage:
  python pathfuzz2.py http://10.230.164.2:8080 [wordlist]
"""
import sys, json, threading, queue, urllib.request, urllib.error, ssl

TARGET = sys.argv[1].rstrip('/')
WL = sys.argv[2] if len(sys.argv) > 2 else None

CORE = """healthz health healthcheck graphql api v1 v2 api/v1 api/v2
ota ota/v1 otas update updates firmware fw package packages pkg bundle bundles
manifest manifests release releases rollout rollouts campaign campaigns
engineering eng engpkg diagnostic diagnostics diag diags ticket tickets session sessions
sign signer signing signature verify verification verify_ota validate
auth login token tokens oauth oauth2 oidc jwks keys key ca pki certs certificates enroll enrollment bootstrap
vehicle vehicles fleet fleets device devices tbox tboxs vin vins
download downloads upload uploads files file static assets media
admin debug internal devops ops metrics pprof status version info config settings
can doip uds secoc bcm bms vcu gw gateway ecu ecus
provision provisioning claim claims activate activation
seed seeds challenge nonce pair pairing
report reports logs log audit
user users account profile me
test sandbox demo sample samples example examples
swagger openapi docs redoc api-docs openapi.json swagger.json
monitor monitoring telemetry ingest data dataset
service services svc rpc grpc call invoke
util utils system sys env vars
cron job jobs task tasks queue worker
webhook webhooks callback notify
""".split()

SUFFIX = ["", "/", "/list", "/all", "/info", "/status", "/latest", "/current", "/default",
          "/package", "/download", "/manifest", "/ticket", "/sign", "/verify", "/create",
          "/upload", "/enroll", "/issue", "/get", "/query", "/0", "/1", "/v1", "/v2"]

def words():
    seen = set()
    def add(w):
        w = w.strip('/')
        if w and w not in seen:
            seen.add(w); out.append(w)
    out = []
    for c in CORE:
        for s in SUFFIX:
            add(c + s)
    return out

def probe(path):
    res = []
    for method in ("GET", "POST"):
        for base in (TARGET,):
            url = f"{base}/{path}"
            try:
                req = urllib.request.Request(url, method=method,
                                             data=b'{}' if method == 'POST' else None,
                                             headers={'Content-Type': 'application/json',
                                                      'User-Agent': 'curl/8.22.0'})
                ctx = ssl._create_unverified_context()
                with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                    body = r.read(400)
                    res.append((method, path, r.status, len(body), dict(r.headers), body))
            except urllib.error.HTTPError as e:
                body = e.read(400)
                res.append((method, path, e.code, len(body), dict(e.headers), body))
            except Exception as e:
                res.append((method, path, -1, 0, {}, str(e).encode()[:200]))
    return res

def main():
    ws = words()
    print(f"[*] target={TARGET} paths={len(ws)}", file=sys.stderr)
    q = queue.Queue()
    for w in ws:
        q.put(w)
    hits = []
    lock = threading.Lock()

    def worker():
        while True:
            try:
                w = q.get_nowait()
            except queue.Empty:
                return
            for (m, p, st, ln, h, b) in probe(w):
                if st not in (404, -1) or (st == -1 and b'reset' in b):
                    with lock:
                        hits.append({"method": m, "path": "/" + p, "status": st, "len": ln,
                                     "ctype": h.get("Content-Type", ""),
                                     "body": b.decode("utf-8", "replace")[:300]})
            q.task_done()

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(24)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    print(json.dumps(hits, indent=1, ensure_ascii=False))

if __name__ == "__main__":
    main()

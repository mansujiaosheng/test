#!/usr/bin/env python3
"""Concurrent path prober for CTF web reco. Read-only GET/HEAD/OPTIONS only."""
import sys, json, os, time, threading, queue
import urllib3
import requests
from requests.adapters import HTTPAdapter

urllib3.disable_warnings()

TIMEOUT = 6
WORKERS = int(os.environ.get("WEB_WORKERS", "20"))

BASE_WORDS = """
api graphql ota campaign campaigns firmware package packages artifact artifacts
diagnostics diag vehicle vehicles vin tbox telemetry admin internal debug metrics
swagger openapi.json openapi.yaml openapi swagger-ui swagger-ui/index.html docs
login auth token register config healthz readyz version status info index root
robots.txt sitemap.xml favicon.ico index.html static assets public files upload
uploads download downloads report reports log logs test tests dev staging prod
private secret secrets key keys cert certs certificate ca ca.crt client.crt
audit backup db database redis mongo sql shell exec run cmd command task tasks
job jobs service services system sys host hosts device devices edge gateway gw
cgw ecu ecus can uds doip traces trace span spans profile profiles
pprof debug/pprof debug/pprof/ debug/vars debug/pprof/heap debug/pprof/goroutine
debug/pprof/cmdline debug/pprof/profile debug/pprof/symbol debug/pprof/trace
debug/pprof/threadcreate debug/pprof/allocs debug/pprof/block debug/pprof/mutex
.git/HEAD .git/config .git/index .git/logs/HEAD .git/refs/heads/main .svn
.env config.json config.yaml config.yml package.json go.mod main.go Dockerfile
docker-compose.yml nginx.conf .htaccess server-status actuator actuator/health
actuator/env actuator/mappings actuator/beans actuator/info actuator/loggers
v1 v2 v3 api/v1 api/v2 api/v3 api/v1/health api/v1/status api/v1/version
api/health api/status api/version api/vehicles api/vehicle api/ota api/ota/jobs
api/ota/campaigns api/firmware api/packages api/artifacts api/diagnostics
api/graphql api/auth api/login api/token api/admin api/config api/v1/vehicles
api/v1/ota api/v1/firmware api/v1/diagnostics api/v1/vehicles/CV6FF52FEE9EDDD86
graphiql playground query mutate subscription ws websocket socket mqtt sse
events stream hooks webhook webhooks callback callbacks notify notification
notifications push sync update updates upgrade upgrades flash flashjob
ota/jobs ota/campaigns ota/firmware firmware/list firmware/upload firmware/download
package/list packages/list artifact/list artifacts/list artifact/download
diagnostics/run diagnostics/start diagnostics/report diag/run diag/start
vehicles/vin vin/CV6FF52FEE9EDDD86 vehicles/CV6FF52FEE9EDDD86
tbox/health tbox/status tbox/api tbox/diag tbox/ota tbox/auth tbox/login
tbox/register tbox/cert tbox/certs tbox/provision tbox/provisioning
internal/health internal/metrics internal/debug internal/admin
metrics/prometheus prometheus metrics.json stats stat
dash dashboard ui web console panel
csv export import
fleet fleets fleet/vehicles fleet/ota
verify validate check
sudo su root/ shell/
package-lock.json yarn.lock Makefile README.md README changelog LICENSE
""".split()

EXTRA = [
    "api/v1/vehicles/CV6FF52FEE9EDDD86/ota",
    "api/v1/vehicles/CV6FF52FEE9EDDD86/diagnostics",
    "api/v1/vehicles/CV6FF52FEE9EDDD86/telemetry",
    "vehicles/CV6FF52FEE9EDDD86/ota",
    "vehicles/CV6FF52FEE9EDDD86/diagnostics",
    "vehicles/CV6FF52FEE9EDDD86/status",
    "api/v1/vehicles/CV6FF52FEE9EDDD86/firmware",
    "firmware/CV6FF52FEE9EDDD86",
    "ota/CV6FF52FEE9EDDD86",
    "download/CV6FF52FEE9EDDD86",
    "api/v1/vehicles/CV6FF52FEE9EDDD86/campaigns",
    "campaigns/CV6FF52FEE9EDDD86",
    "api/vehicles/CV6FF52FEE9EDDD86",
    "v1/vehicles", "v1/ota", "v1/diagnostics",
    "api/v1/graphql", "api/graphql",
    "graphql/v1", "graphql/schema", "schema.graphql", "schema.json",
    "debug/pprof/profile?seconds=1",
    "metrics/health", "health", "health/ready", "health/live", "alive", "live",
    "ping", "pong", "echo", "time", "date", "whoami", "env", "environ",
    "proc/self/environ", "server", "servers", "cluster", "node", "nodes",
    "master", "worker", "workers", "broker", "queue", "topic", "topics",
    "msg", "message", "messages", "alarm", "alarms", "alert", "alerts",
    "event", "incident", "incidents", "ticket", "tickets", "case", "cases",
    "user", "users", "account", "accounts", "session", "sessions", "role",
    "roles", "permission", "permissions", "acl", "policy", "policies",
    "oauth", "oauth2", "oidc", "jwks.json", "well-known", ".well-known",
    ".well-known/openid-configuration", "jwks", "keys.json", "cert.pem",
    "chain.pem", "root.crt", "Root", "CA", "certs/root.crt",
    "api/v1/auth/login", "api/v1/auth/token", "api/v1/auth/register",
    "auth/login", "auth/token", "auth/register", "auth/refresh",
    "oauth/token", "oauth2/token", "token/verify", "verify/token",
    "api/v1/ota/jobs", "api/v1/ota/campaigns", "api/v1/firmware/list",
    "api/v1/packages", "api/v1/artifacts", "api/v1/telemetry",
    "api/v1/tbox", "api/tbox", "v1/tbox",
    "tbox/diagnostics", "tbox/telemetry", "tbox/vehicle", "tbox/vin",
    "diagnostics/sessions", "diagnostics/upload", "diagnostics/logs",
    "diagnostics/export", "diagnostics/vin", "diagnostics/CV6FF52FEE9EDDD86",
    "cgi-bin/", "cgi-bin/status", "cgi-bin/diag", "cgi-bin/config",
    "index.htm", "default.html", "404.html", "error", "errors",
]

PATHS = []
seen = set()
for p in BASE_WORDS + EXTRA:
    p = p.strip().lstrip("/")
    if p and p not in seen:
        seen.add(p); PATHS.append(p)

_wl = os.environ.get("WEB_WORDLIST")
if _wl:
    PATHS = []
    seen = set()
    with open(_wl, encoding="utf-8") as f:
        for line in f:
            p = line.strip().lstrip("/")
            if p and not p.startswith("#") and p not in seen:
                seen.add(p); PATHS.append(p)


def probe(sess, base, path, results, lock):
    url = base + "/" + path
    method = os.environ.get("WEB_METHOD", "GET").upper()
    try:
        kw = dict(timeout=TIMEOUT, allow_redirects=False, verify=False,
                  headers={"User-Agent": "recon/1.0", "Accept": "*/*"})
        if method == "POST":
            kw["data"] = "{}"
            kw["headers"]["Content-Type"] = "application/json"
            r = sess.post(url, **kw)
        elif method == "HEAD":
            r = sess.head(url, **kw)
        else:
            r = sess.get(url, **kw)
        body = r.content[:400]
        rec = {"path": path, "status": r.status_code, "len": len(r.content),
               "headers": dict(r.headers), "body": body.decode("utf-8", "replace")[:200]}
    except Exception as e:
        rec = {"path": path, "error": f"{type(e).__name__}: {e}"[:200]}
    with lock:
        results.append(rec)


def run(host, port, scheme="http", outfile=None, workers=WORKERS):
    base = f"{scheme}://{host}:{port}"
    sess = requests.Session()
    ad = HTTPAdapter(pool_connections=workers, pool_maxsize=workers, max_retries=0)
    sess.mount("http://", ad); sess.mount("https://", ad)
    results, lock = [], threading.Lock()
    q = queue.Queue()
    for p in PATHS:
        q.put(p)

    def worker():
        while True:
            try:
                p = q.get_nowait()
            except queue.Empty:
                return
            probe(sess, base, p, results, lock)
            q.task_done()

    t0 = time.time()
    ths = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in ths: t.start()
    for t in ths: t.join()
    dt = time.time() - t0

    # baseline: random path
    import random, string
    rand = "".join(random.choice(string.ascii_lowercase) for _ in range(14))
    try:
        rb = sess.get(f"{base}/{rand}", timeout=TIMEOUT, verify=False)
        baseline = {"status": rb.status_code, "len": len(rb.content),
                    "body": rb.content[:120].decode("utf-8", "replace")}
    except Exception as e:
        baseline = {"error": str(e)}

    ok = [r for r in results if "error" not in r]
    errs = [r for r in results if "error" in r]
    interesting = []
    for r in ok:
        st = r["status"]
        if st == 404 and baseline.get("status") == 404:
            continue
        interesting.append(r)
    interesting.sort(key=lambda x: (x["status"], x["path"]))

    out = {
        "target": base, "elapsed_s": round(dt, 1), "probed": len(results),
        "errors": len(errs), "baseline_404": baseline,
        "status_histogram": {},
        "interesting": interesting,
        "server_headers_sample": ok[0]["headers"] if ok else {},
    }
    for r in ok:
        out["status_histogram"][r["status"]] = out["status_histogram"].get(r["status"], 0) + 1
    if outfile:
        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=1, ensure_ascii=False)
    return out


if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    scheme = sys.argv[3] if len(sys.argv) > 3 else "http"
    outfile = sys.argv[4] if len(sys.argv) > 4 else None
    res = run(host, port, scheme, outfile)
    print(json.dumps({k: v for k, v in res.items() if k != "interesting"}, indent=1, ensure_ascii=False))
    print(f"--- {len(res['interesting'])} interesting (non-404 or 404-drift) ---")
    for r in res["interesting"]:
        print(f"{r['status']:>3} {r['len']:>7} {r['path']:<50} {r['body'][:110]!r}")
    print(f"--- errors: {res['errors']} ---")

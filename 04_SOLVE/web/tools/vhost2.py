#!/usr/bin/env python3
"""Host-header vhost brute for .2:8080 and .3:8080.

Why it can work: Go 1.22+ http.ServeMux accepts "host/path" patterns, so a
service can register routes that only answer for a specific Host.  The default
vhost answers /healthz with 200; therefore any Host whose /healthz no longer
returns 200 has a *different* mux -> new surface worth chasing.

Probes per Host: GET /healthz, GET /, POST /graphql
Pass 2 (only for Hosts that deviate) adds OTA-ish paths.
Rate limited to <= 20 req/s as required for the web surface.
"""
import hashlib, json, os, socket, sys, time

EVID = os.path.join(os.path.dirname(__file__), "..", "..", "..", "03_EVIDENCE", "web")
TARGETS = [("10.230.164.2", 8080), ("10.230.164.3", 8080)]

HOSTS = [
    # plain service names
    "tbox", "tsp", "ota", "fleet", "update", "updater", "api", "vehicle", "cv6",
    "admin", "internal", "gateway", "cgw", "bms", "vcu", "diagnostics", "diag",
    "auth", "ca", "pki", "sign", "signer", "release", "releases", "download",
    "downloads", "files", "static", "assets", "storage", "s3", "blob", "artifact",
    "registry", "repo", "git", "npm", "nexus", "minio", "vault", "secrets",
    "local", "localhost", "ip6-localhost", "backend", "service", "svc",
    # FQDN forms
    "tbox.cv6", "tsp.cv6", "ota.cv6", "fleet.cv6", "update.cv6", "api.cv6",
    "tbox.local", "tsp.local", "ota.local", "fleet.local", "update.local",
    "tbox.cv6.local", "tsp.cv6.local", "ota.cv6.local", "fleet.cv6.local",
    "update.cv6.local", "diagnostics.cv6.local", "admin.cv6.local",
    "ota.example.com", "tsp.example.com", "tbox.example.com",
    "cv6", "cv6.local", "cv6-fleet", "cv6fleet", "cv6-ota", "cv6.internal",
    "tbox.internal", "ota.internal", "tsp.internal",
    # wildcard / catch-all tricks
    "*", "cv6-ota." + "a" * 40, "any.example.com",
    # reverse-proxy / infra
    "traefik", "nginx", "envoy", "haproxy", "ingress", "kubernetes",
    "docker", "rancher", "grafana", "prometheus", "kibana", "minio.local",
]

def raw_req(host_ip, port, host_header, method, path, body=b"", ctype=None,
            timeout=5.0, http10=False):
    ver = "HTTP/1.0" if http10 else "HTTP/1.1"
    req = f"{method} {path} {ver}\r\n".encode()
    if host_header is not None:
        req += f"Host: {host_header}\r\n".encode()
    if ctype:
        req += f"Content-Type: {ctype}\r\n".encode()
    if method == "POST":
        req += f"Content-Length: {len(body)}\r\n".encode()
    req += b"Connection: close\r\n\r\n" + body
    s = socket.socket()
    s.settimeout(timeout)
    buf = b""
    err = None
    try:
        s.connect((host_ip, port))
        s.sendall(req)
        while len(buf) < 262144:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    finally:
        try:
            s.close()
        except Exception:
            pass
    status = b""
    head, body_out = buf, b""
    i = buf.find(b"\r\n\r\n")
    if i >= 0:
        head, body_out = buf[:i], buf[i + 4:]
    if head:
        status = head.split(b"\r\n")[0]
    return {"status": status.decode("latin1"),
            "body_sha16": hashlib.sha256(body_out.rstrip(b"\r\n")).hexdigest()[:16],
            "body_len": len(body_out),
            "preview": body_out.rstrip(b"\r\n")[:160].decode("latin1", "replace"),
            "err": err,
            "headers": head.decode("latin1", "replace")}

OTA_PATHS = ["/firmware", "/firmware/", "/firmware/latest.json", "/ota", "/ota/",
             "/ota/manifest", "/download", "/downloads/", "/packages/",
             "/releases/", "/api/ota/manifest", "/v1/ota/manifest",
             "/.well-known/", "/.well-known/cv6", "/ca.pem", "/client.pem",
             "/pki/", "/certs/", "/keys/"]

def main():
    os.makedirs(EVID, exist_ok=True)
    out = {"baseline": {}, "rows": [], "deviations": []}

    # baseline: normal Host (IP) behaviour, so we can compare exactly
    for ip, port in TARGETS:
        b = {}
        b["healthz"] = raw_req(ip, port, f"{ip}:{port}", "GET", "/healthz")
        b["root"] = raw_req(ip, port, f"{ip}:{port}", "GET", "/")
        b["graphql"] = raw_req(ip, port, f"{ip}:{port}", "POST", "/graphql",
                               b'{"query":"{__typename}"}', "application/json")
        out["baseline"][f"{ip}:{port}"] = b
        print(f"baseline {ip}:{port} healthz={b['healthz']['status']} "
              f"root={b['root']['status']} graphql={b['graphql']['status']}", flush=True)

    t0 = time.time()
    n = 0
    for ip, port in TARGETS:
        base = out["baseline"][f"{ip}:{port}"]
        for h in HOSTS:
            for label, method, path, body, ctype in [
                ("healthz", "GET", "/healthz", b"", None),
                ("root", "GET", "/", b"", None),
                ("graphql", "POST", "/graphql", b'{"query":"{__typename}"}', "application/json"),
            ]:
                n += 1
                r = raw_req(ip, port, h, method, path, body, ctype)
                b = base[label]
                dev = (r["status"] != b["status"]) or (r["body_sha16"] != b["body_sha16"])
                row = {"host_port": f"{ip}:{port}", "vhost": h, "probe": label,
                       "status": r["status"], "sha": r["body_sha16"],
                       "len": r["body_len"], "preview": r["preview"],
                       "baseline_status": b["status"], "baseline_sha": b["body_sha16"],
                       "deviates": dev, "err": r["err"]}
                out["rows"].append(row)
                if dev:
                    out["deviations"].append(row)
                    print(f"[DEV] {ip}:{port} Host={h!r:28s} {label:8s} "
                          f"{r['status']} vs {b['status']}  {r['preview'][:80]!r}", flush=True)
                # <=20 req/s
                if n % 20 == 0:
                    dt = time.time() - t0
                    if dt < n / 20.0:
                        time.sleep(n / 20.0 - dt)

    # pass 2: for deviating vhosts, probe OTA paths
    dev_hosts = sorted({(d["host_port"], d["vhost"]) for d in out["deviations"]})
    print(f"\npass2 over {len(dev_hosts)} deviating (host, vhost) pairs", flush=True)
    for hp, vh in dev_hosts:
        ip, port = hp.split(":")
        for p in OTA_PATHS:
            n += 1
            r = raw_req(ip, int(port), vh, "GET", p)
            row = {"host_port": hp, "vhost": vh, "probe": "ota:" + p,
                   "status": r["status"], "sha": r["body_sha16"],
                   "len": r["body_len"], "preview": r["preview"],
                   "deviates": r["status"] not in ("HTTP/1.1 404 Not Found",),
                   "err": r["err"]}
            out["rows"].append(row)
            if row["deviates"]:
                out["deviations"].append(row)
                print(f"[OTA] {hp} Host={vh!r} {p} {r['status']} {r['preview'][:100]!r}", flush=True)
            if n % 20 == 0:
                dt = time.time() - t0
                if dt < n / 20.0:
                    time.sleep(n / 20.0 - dt)

    # no-Host control (HTTP/1.0 without Host header)
    for ip, port in TARGETS:
        r = raw_req(ip, port, None, "GET", "/", http10=True)
        out["rows"].append({"host_port": f"{ip}:{port}", "vhost": "<NO-HOST>",
                            "probe": "http10_root", "status": r["status"],
                            "sha": r["body_sha16"], "len": r["body_len"],
                            "preview": r["preview"], "deviates": True, "err": r["err"]})
        print(f"[NOHOST] {ip}:{port} {r['status']} {r['preview'][:80]!r}", flush=True)

    p = os.path.join(EVID, "vhost_brute_w2.json")
    open(p, "w", encoding="utf-8").write(json.dumps(out, indent=1))
    print(f"\ntotal probes={n} deviations={len(out['deviations'])} -> {p}")

if __name__ == "__main__":
    main()

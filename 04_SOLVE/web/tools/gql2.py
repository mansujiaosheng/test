#!/usr/bin/env python3
"""Wave-2 GraphQL / HTTP-shape probing against 10.230.164.2:8080.

Everything is raw-socket so we control exact bytes (HTTP/1.0, chunked,
oversized body, multipart, WebSocket upgrade). Read-only.

Judgement rule (from task): if the response is byte-identical to the
baseline stub response, the endpoint ignores our input -> stub.
Any difference -> real engine / new surface.
"""
import hashlib, json, os, socket, ssl, sys, time

HOST = "10.230.164.2"
PORT = 8080
EVID = os.path.join(os.path.dirname(__file__), "..", "..", "..", "03_EVIDENCE", "web")
BASE_STUB = b'{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'

RESULTS = []

def raw(req_bytes, host=HOST, port=PORT, timeout=6.0, read_all=True, tls=False):
    s = socket.socket()
    s.settimeout(timeout)
    buf = b""
    err = None
    try:
        s.connect((host, port))
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s)
        s.sendall(req_bytes)
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
            if not read_all and len(buf) > 0:
                break
            if len(buf) > 4 * 1024 * 1024:
                break
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    finally:
        try:
            s.close()
        except Exception:
            pass
    return buf, err

def split_http(resp):
    if not resp:
        return None, b"", b""
    i = resp.find(b"\r\n\r\n")
    if i < 0:
        i = resp.find(b"\n\n")
        if i < 0:
            return None, resp, b""
    head = resp[:i]
    body = resp[i + 4:]
    return head, body, resp

def norm_body(body):
    """strip trailing newline for comparison"""
    return body.rstrip(b"\r\n")

def record(tag, req_desc, resp, err, extra=None):
    head, body, _ = split_http(resp)
    status = b""
    if head:
        status = head.split(b"\r\n")[0]
    nb = norm_body(body)
    same = (nb == BASE_STUB)
    h = hashlib.sha256(nb).hexdigest()[:16]
    row = {
        "tag": tag,
        "req": req_desc,
        "status": status.decode("latin1"),
        "body_len": len(body),
        "body_sha16": h,
        "same_as_stub": same,
        "err": err,
        "head": (head or b"").decode("latin1"),
        "body_preview": nb[:400].decode("latin1", "replace"),
    }
    if extra:
        row.update(extra)
    RESULTS.append(row)
    flag = "SAME" if same else "DIFF"
    print(f"[{flag}] {tag:38s} {row['status']:24s} len={len(body):<7d} sha={h} err={err}", flush=True)
    if not same and body:
        print(f"          body> {row['body_preview'][:200]!r}", flush=True)
    return row

def cl(n):
    return f"Content-Length: {n}\r\n".encode()

# ---------------------------------------------------------------- case set
HOSTH = f"Host: {HOST}:{PORT}\r\n".encode()

def post_json(path, obj, extra_hdr=b"", version=b"HTTP/1.1", ctype=b"application/json"):
    body = json.dumps(obj).encode() if not isinstance(obj, bytes) else obj
    req = (b"POST " + path + b" " + version + b"\r\n" + HOSTH
           + b"Content-Type: " + ctype + b"\r\n"
           + cl(len(body)) + extra_hdr + b"Connection: close\r\n\r\n" + body)
    return req

def main():
    os.makedirs(EVID, exist_ok=True)
    parts = []

    # ---- 0. baseline
    r = post_json(b"/graphql", {"query": "{ __typename }"})
    resp, err = raw(r)
    record("baseline_typename", "POST /graphql json {query:{__typename}}", resp, err)

    # ---- A. classic introspection with explicit CT
    body = b'{"query":"query{__schema{types{name}}}"}'
    req = (b"POST /graphql HTTP/1.1\r\n" + HOSTH +
           b"Content-Type: application/json\r\n" + cl(len(body)) +
           b"Accept: application/json\r\nConnection: close\r\n\r\n" + body)
    record("A_introspection_json", "POST json introspection __schema.types.name", *raw(req))

    # ---- B. GET with ?query=
    for q in [b"/graphql?query=%7B__typename%7D",
              b"/graphql?query={__typename}",
              b"/graphql?query=query%7B__schema%7Btypes%7Bname%7D%7D%7D"]:
        req = b"GET " + q + b" HTTP/1.1\r\n" + HOSTH + b"Accept: text/html\r\nConnection: close\r\n\r\n"
        record("B_get_query_" + hashlib.md5(q).hexdigest()[:6], "GET " + q.decode(), *raw(req))

    # ---- C. application/graphql body
    body = b"{__typename}"
    req = (b"POST /graphql HTTP/1.1\r\n" + HOSTH +
           b"Content-Type: application/graphql\r\n" + cl(len(body)) +
           b"Connection: close\r\n\r\n" + body)
    record("C_appgraphql_typename", "POST CT:application/graphql body {__typename}", *raw(req))

    body = b"query{__schema{types{name}}}"
    req = (b"POST /graphql HTTP/1.1\r\n" + HOSTH +
           b"Content-Type: application/graphql\r\n" + cl(len(body)) +
           b"Connection: close\r\n\r\n" + body)
    record("C_appgraphql_introspection", "POST CT:application/graphql introspection (no braces wrap)", *raw(req))

    # ---- D. chunked transfer-encoding
    body = b'{"query":"{__typename}"}'
    chunk = b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"
    req = (b"POST /graphql HTTP/1.1\r\n" + HOSTH +
           b"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
           b"Connection: close\r\n\r\n" + chunk)
    record("D_chunked", "POST chunked TE", *raw(req))

    # ---- E. HTTP/1.0
    body = b'{"query":"{__typename}"}'
    req = (b"POST /graphql HTTP/1.0\r\n" + HOSTH +
           b"Content-Type: application/json\r\n" + cl(len(body)) + b"\r\n" + body)
    record("E_http10", "POST HTTP/1.0", *raw(req))

    # ---- F. oversized body (1 MB) - still far below DoS territory
    big = b'{"query":"{__typename}","pad":"' + b"A" * (1024 * 1024) + b'"}'
    req = (b"POST /graphql HTTP/1.1\r\n" + HOSTH +
           b"Content-Type: application/json\r\n" + cl(len(big)) +
           b"Connection: close\r\n\r\n" + big)
    record("F_body_1MB", "POST 1MB json body", *raw(req, timeout=15.0))

    # ---- G. multipart/form-data
    bnd = b"----cv6probe"
    mp = (b"--" + bnd + b"\r\nContent-Disposition: form-data; name=\"query\"\r\n\r\n"
          b"{__typename}\r\n--" + bnd + b"--\r\n")
    req = (b"POST /graphql HTTP/1.1\r\n" + HOSTH +
           b"Content-Type: multipart/form-data; boundary=" + bnd + b"\r\n" +
           cl(len(mp)) + b"Connection: close\r\n\r\n" + mp)
    record("G_multipart", "POST multipart query field", *raw(req))

    # ---- G2. urlencoded
    body = b"query=%7B__typename%7D"
    req = (b"POST /graphql HTTP/1.1\r\n" + HOSTH +
           b"Content-Type: application/x-www-form-urlencoded\r\n" + cl(len(body)) +
           b"Connection: close\r\n\r\n" + body)
    record("G2_urlencoded", "POST urlencoded query", *raw(req))

    # ---- H. variant paths
    for p in [b"/graphql/", b"/graphql/v1", b"/v1/graphql", b"/api/graphql",
              b"/gql", b"/query", b"/graphiql", b"/api/v1/graphql",
              b"/graphql/query", b"/v2/graphql", b"/gql/v1", b"/graphql/api",
              b"/graphql?foo=1", b"//graphql", b"/graphql%2F", b"/GRAPHQL"]:
        resp, err = raw(post_json(p, {"query": "{__typename}"}))
        record("H_path_" + p.decode("latin1"), "POST " + p.decode("latin1", "replace"), resp, err)

    # ---- I. WebSocket upgrade on several paths
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    for p in [b"/graphql", b"/", b"/ws", b"/subscriptions", b"/healthz"]:
        req = (b"GET " + p + b" HTTP/1.1\r\n" + HOSTH +
               b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
               b"Sec-WebSocket-Key: " + key.encode() + b"\r\n"
               b"Sec-WebSocket-Version: 13\r\n\r\n")
        record("I_ws_" + p.decode("latin1").replace("/", "_"), "WS upgrade " + p.decode(), *raw(req))

    # ---- J. SSE / streaming accept
    body = b'{"query":"subscription{onOtaUpdate{id}}"}'
    req = (b"POST /graphql HTTP/1.1\r\n" + HOSTH +
           b"Content-Type: application/json\r\nAccept: text/event-stream\r\n" +
           cl(len(body)) + b"Connection: close\r\n\r\n" + body)
    record("J_sse_subscription", "POST Accept: text/event-stream subscription", *raw(req))

    # ---- K. ping / persisted query / apollo style
    for tag, obj in [("K_persisted", {"extensions": {"persistedQuery": {"version": 1, "sha256Hash": "0" * 64}}}),
                     ("K_batch", [{"query": "{__typename}"}, {"query": "{vehicles{vin}}"}]),
                     ("K_batch_2", {"query": "{__typename}", "operationName": None, "variables": {}}),
                     ("K_empty_obj", {}),
                     ("K_query_null", {"query": None}),
                     ("K_vehicles_only", {"query": "{ vehicles { vin label firmware } }"})]:
        resp, err = raw(post_json(b"/graphql", obj))
        record(tag, "POST " + json.dumps(obj)[:70], resp, err)

    # ---- L. header-based hints: X-Forwarded-*, X-HTTP-Method-Override
    resp, err = raw(post_json(b"/graphql", {"query": "{__typename}"},
                              extra_hdr=b"X-HTTP-Method-Override: GET\r\n"
                                        b"X-Forwarded-For: 127.0.0.1\r\n"
                                        b"X-Real-IP: 127.0.0.1\r\n"
                                        b"X-Forwarded-Host: localhost\r\n"))
    record("L_proxy_headers", "POST with XFF/XFHost/method-override", resp, err)

    # ---- M. request smuggling shape: CL + TE
    body = b'{"query":"{__typename}"}'
    req = (b"POST /graphql HTTP/1.1\r\n" + HOSTH +
           b"Content-Type: application/json\r\n" + cl(len(body)) +
           b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + body)
    record("M_cl_te_smuggle", "POST both CL and TE", *raw(req))

    # ---- N. Does /healthz reflect anything? (control: confirm our socket harness works)
    req = b"GET /healthz HTTP/1.1\r\n" + HOSTH + b"Connection: close\r\n\r\n"
    record("N_healthz_control", "GET /healthz (harness control)", *raw(req))

    # ---- write evidence
    p = os.path.join(EVID, "gql2_probe_matrix.json")
    open(p, "w", encoding="utf-8").write(json.dumps(RESULTS, indent=1))
    print("\nwrote", p)

    # human summary
    diff = [r for r in RESULTS if not r["same_as_stub"]]
    print(f"\n=== total={len(RESULTS)} same_as_stub={len(RESULTS)-len(diff)} differing={len(diff)} ===")
    for r in diff:
        print(f"  DIFF {r['tag']:34s} {r['status']:26s} len={r['body_len']} {r['body_preview'][:120]!r}")

if __name__ == "__main__":
    main()

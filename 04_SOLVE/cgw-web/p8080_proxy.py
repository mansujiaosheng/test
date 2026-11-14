#!/usr/bin/env python3
"""Does the CGW's :8080 (or :8080 on the sibling IP) forward anywhere?

Four things are tested, each independently:
  A. absolute-URI request line  -> "GET http://10.224.139.5:8080/ HTTP/1.1" (forward-proxy behaviour)
  B. CONNECT tunnelling         -> "CONNECT 10.224.139.5:8080 HTTP/1.1" then a payload
  C. Host-header virtual host   -> "Host: 10.224.139.5" against ordinary paths
  D. Upgrade / websocket        -> "Upgrade: websocket" + Connection: Upgrade

A response that differs from the known baseline (`404 page not found` / `/healthz`
`{"status":"ok"}`) is the signal we are hunting. Everything is written to
03_EVIDENCE/cgw-web/0603_8080_proxy_semantics.txt.
"""
import socket, ssl, time, json, os, sys

HOSTS = ["10.229.221.2", "10.230.164.4"]
PORT = 8080
OUT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "..", "..", "03_EVIDENCE", "cgw-web",
                                   "0603_8080_proxy_semantics.txt"))

INTERNAL = "10.224.139.5"


def raw(host, request: bytes, *, read_secs=4.0, port=PORT):
    """Send a raw request, return everything until close/timeout."""
    rec = {"host": host, "port": port, "req": request.decode("latin-1")}
    s = socket.socket()
    s.settimeout(6.0)
    t0 = time.perf_counter()
    try:
        s.connect((host, port))
    except Exception as e:
        rec["connect_error"] = repr(e)
        return rec
    rec["connect_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    try:
        s.sendall(request)
    except OSError as e:
        rec["send_error"] = repr(e)
    s.settimeout(read_secs)
    rx = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                rec["closed"] = True
                break
            rx += b
            if len(rx) > 200000:
                break
    except socket.timeout:
        rec["timed_out"] = True
    except OSError as e:
        rec["read_error"] = repr(e)
    rec["rx_len"] = len(rx)
    rec["rx_head"] = rx[:800].decode("latin-1", "replace")
    rec["total_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    try:
        s.close()
    except Exception:
        pass
    return rec


def req(method, target, host_hdr, extra=""):
    return (f"{method} {target} HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            f"User-Agent: curl/8.0\r\n"
            f"Accept: */*\r\n"
            f"{extra}"
            f"Connection: close\r\n\r\n").encode()


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    cases = []

    for h in HOSTS:
        # baseline, to have the control on the same run
        cases.append((h, "baseline_healthz", req("GET", "/healthz", h)))
        cases.append((h, "baseline_404", req("GET", "/nope", h)))
        # A. absolute-URI (forward proxy)
        cases.append((h, "A_abs_uri_internal",
                      req("GET", f"http://{INTERNAL}:8080/", h)))
        cases.append((h, "A_abs_uri_internal_healthz",
                      req("GET", f"http://{INTERNAL}:8080/healthz", h)))
        cases.append((h, "A_abs_uri_cgw_healthz",
                      req("GET", f"http://{h}:8080/healthz", h)))
        # B. CONNECT
        cases.append((h, "B_connect_internal",
                      (f"CONNECT {INTERNAL}:8080 HTTP/1.1\r\n"
                       f"Host: {INTERNAL}:8080\r\n\r\n").encode()))
        cases.append((h, "B_connect_cgw13400",
                      (f"CONNECT {h}:13400 HTTP/1.1\r\n"
                       f"Host: {h}:13400\r\n\r\n").encode()))
        # C. Host-header vhost
        cases.append((h, "C_host_internal_root", req("GET", "/", INTERNAL)))
        cases.append((h, "C_host_internal_healthz", req("GET", "/healthz", INTERNAL)))
        cases.append((h, "C_host_internal_api", req("GET", "/api/status", INTERNAL)))
        # D. Upgrade
        cases.append((h, "D_upgrade_root",
                      req("GET", "/", h,
                          "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                          "Sec-WebSocket-Version: 13\r\n")))

    lines = []
    for host, label, request in cases:
        r = raw(host, request)
        head = r.get("rx_head", "").replace("\r\n", " | ")[:300]
        line = ("%-14s %-30s rx=%-5d %s" % (host, label, r.get("rx_len", -1), head))
        print(line, flush=True)
        lines.append(json.dumps({**r, "label": label}, ensure_ascii=False))

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("# 8080 proxy/forwarding semantics\n")
        f.write("# time: %s\n\n" % time.strftime("%Y-%m-%d %H:%M:%S%z"))
        for l in lines:
            f.write(l + "\n")
    print("\nevidence:", OUT)


if __name__ == "__main__":
    main()

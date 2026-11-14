# -*- coding: utf-8 -*-
"""Robust raw-HTTP helper. Fixes: Windows 10048 socket reuse, keep-alive drain,
Content-Length framed reads, chunked reads."""
import socket, ssl, time, json as _json

class Resp:
    def __init__(self, status, headers, body, elapsed, raw):
        self.status = status; self.headers = headers; self.body = body
        self.elapsed = elapsed; self.raw = raw
    @property
    def first_line(self):
        return self.raw.split(b"\r\n", 1)[0].decode("latin1") if self.raw else ""
    def h(self, name):
        for k, v in self.headers:
            if k.lower() == name.lower(): return v
        return None
    def __repr__(self):
        return f"<{self.first_line} LOC={self.h('location')} len={len(self.body)} body={self.body[:100]!r}>"

def _connect(host, port, timeout, tls=False, sni=None, retries=6):
    last = None
    for i in range(retries):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            if tls:
                ctx = ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=sni or host)
            return s
        except OSError as e:
            last = e; s.close()
            if getattr(e, "winerror", None) in (10048, 10061, 10055):
                time.sleep(0.08 * (i + 1)); continue
            raise
    raise last

def _read_response(sock, timeout):
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = sock.recv(65536)
        if not d: return buf, b""
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1]) if len(lines[0].split(b" ")) > 1 else 0
    headers = []
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers.append((k.decode("latin1").strip(), v.decode("latin1").strip()))
    body = rest
    te = next((v for k, v in headers if k.lower() == "transfer-encoding"), "")
    cl = next((v for k, v in headers if k.lower() == "content-length"), None)
    if "chunked" in te.lower():
        # read until 0-chunk
        while b"\r\n0\r\n\r\n" not in body and b"0\r\n\r\n" not in body:
            try: d = sock.recv(65536)
            except socket.timeout: break
            if not d: break
            body += d
        raw_body, out, i = body, b"", 0
        while True:
            j = raw_body.find(b"\r\n", i)
            if j < 0: break
            try: n = int(raw_body[i:j].split(b";")[0], 16)
            except Exception: break
            if n == 0: break
            out += raw_body[j+2:j+2+n]; i = j + 2 + n + 2
        return head + b"\r\n\r\n" + body, out
    if cl is not None:
        need = int(cl)
        while len(body) < need:
            try: d = sock.recv(65536)
            except socket.timeout: break
            if not d: break
            body += d
        return head + b"\r\n\r\n" + body, body[:need]
    return head + b"\r\n\r\n" + body, body

def request(host, port, method, path, headers=None, body=b"", version="HTTP/1.1",
            timeout=6.0, tls=False, sni=None, host_header=None, read_body=True):
    hdrs = list(headers or [])
    if host_header is not False:
        hdrs = [("Host", host_header or f"{host}:{port}")] + hdrs
    if body and not any(k.lower() in ("content-length", "transfer-encoding") for k, _ in hdrs):
        hdrs.append(("Content-Length", str(len(body))))
    req = (f"{method} {path} {version}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs) + "\r\n").encode("latin1") + body
    return request_raw(host, port, req, timeout=timeout, tls=tls, sni=sni)

def request_raw(host, port, payload, timeout=6.0, tls=False, sni=None):
    t0 = time.time()
    s = _connect(host, port, timeout, tls=tls, sni=sni)
    try:
        s.sendall(payload)
        raw, body = _read_response(s, timeout)
    finally:
        try: s.close()
        except Exception: pass
    head_only = raw.split(b"\r\n\r\n", 1)[0]
    lines = head_only.split(b"\r\n")
    status = 0
    if lines and len(lines[0].split(b" ")) > 1:
        try: status = int(lines[0].split(b" ")[1])
        except Exception: status = 0
    headers = []
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers.append((k.decode("latin1").strip(), v.decode("latin1").strip()))
    return Resp(status, headers, body, time.time() - t0, raw)

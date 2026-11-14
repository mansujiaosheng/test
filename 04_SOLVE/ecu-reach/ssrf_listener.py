#!/usr/bin/env python3
"""Minimal callback listener: logs every TCP connection + HTTP request line/headers.
Binds local VPN address only. Used to test whether any fleet service will connect back (SSRF).
"""
import http.server, socketserver, sys, datetime

ADDR = ("10.252.3.20", 9999)
LOG = "03_EVIDENCE/ecu-reach/ssrf/callbacks.log"

class H(http.server.BaseHTTPRequestHandler):
    def _log(self, tag):
        ts = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
        line = f"{ts} {tag} peer={self.client_address[0]}:{self.client_address[1]} path={self.path} ua={self.headers.get('User-Agent')} host={self.headers.get('Host')}"
        print(line, flush=True)
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    def do_GET(self):
        self._log("GET"); self.send_response(200); self.send_header("Content-Type","text/plain"); self.end_headers(); self.wfile.write(b"ok\n")
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        self._log(f"POST body={body[:200].hex()}")
        self.send_response(200); self.send_header("Content-Type","text/plain"); self.end_headers(); self.wfile.write(b"ok\n")
    def log_message(self, *a): pass

open(LOG,"a",encoding="utf-8").write(f"# listener start {datetime.datetime.now().astimezone().isoformat(timespec='seconds')}\n")
socketserver.TCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer(ADDR, H) as srv:
    print("listening", ADDR, flush=True); srv.serve_forever()

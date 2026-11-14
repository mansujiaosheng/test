#!/usr/bin/env python3
"""8080 management port: protocol-level oddities (raw sockets, one request per conn)."""
import socket, time, json, binascii, random
HOSTS=["10.229.221.2"]
PORT=8080
def req(tag, raw, host="10.229.221.2", wait=2.0):
    out={"tag":tag,"req":raw[:160].decode("latin1")}
    try:
        s=socket.socket(); s.settimeout(4); s.connect((host,PORT)); s.sendall(raw)
        s.settimeout(wait); buf=b""
        while len(buf)<4096:
            try: c=s.recv(4096)
            except socket.timeout: break
            if not c: break
            buf+=c
        s.close()
        out["resp"]=buf.decode("latin1")[:900]
        out["len"]=len(buf)
    except Exception as e:
        out["err"]=type(e).__name__+":"+str(e)
    print(json.dumps(out),flush=True); time.sleep(0.25)

tests=[
 ("GET_healthz_11", b"GET /healthz HTTP/1.1\r\nHost: cgw\r\nConnection: close\r\n\r\n"),
 ("GET_healthz_10", b"GET /healthz HTTP/1.0\r\n\r\n"),
 ("OPTIONS_star",   b"OPTIONS * HTTP/1.1\r\nHost: cgw\r\n\r\n"),
 ("CONNECT",        b"CONNECT 10.230.164.2:8080 HTTP/1.1\r\nHost: x\r\n\r\n"),
 ("absolute_uri",   b"GET http://10.229.221.2:8080/healthz HTTP/1.1\r\nHost: x\r\n\r\n"),
 ("te_chunked",     b"POST /healthz HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
 ("cl_te_smuggle",  b"POST /healthz HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
 ("dup_host",       b"GET /healthz HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"),
 ("query_debug",    b"GET /healthz?debug=1&internal=1 HTTP/1.1\r\nHost: x\r\n\r\n"),
 ("dotdot",         b"GET /x/../healthz HTTP/1.1\r\nHost: x\r\n\r\n"),
 ("pct00",          b"GET /healthz%00 HTTP/1.1\r\nHost: x\r\n\r\n"),
 ("ws_upgrade",     b"GET /healthz HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"),
 ("longpath",       b"GET /"+b"a"*8000+b" HTTP/1.1\r\nHost: x\r\n\r\n"),
 ("ct_json_post",   b"POST /healthz HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"),
]
for t in tests: req(*t)

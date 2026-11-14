#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Final discriminators for 10.229.221.2:13401.

A) Concurrency: do N simultaneous connections all get accepted-then-closed, or
   does a connection limit change behaviour? (a "1-client-only" tunnel would
   show something different on connection #2)
B) Send-then-close ordering: is the FIN already in flight before our payload
   could be read? We time 'send' vs 'FIN arrival'. If the server had to read our
   bytes to decide, the FIN could not precede our data.
C) Does 13401 ever emit ANY byte under a slow-drip write (keeps the socket fed
   so a read() with a short timeout would see partial data)?
D) Compare with 13400 under identical drip, to show 13400 is a real DoIP
   protocol endpoint (answers vehicle identification) and 13401 is not.
"""
import socket
import threading
import time
import json
import os

HOST = "10.229.221.2"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs")
os.makedirs(OUT, exist_ok=True)
res = {}


def one(port, payload=b"", wait=6.0, drip=False):
    s = socket.socket()
    s.settimeout(wait)
    t0 = time.time()
    try:
        s.connect((HOST, port))
    except Exception as e:
        s.close()
        return {"port": port, "err": repr(e)}
    t_conn = time.time()
    sent = 0
    send_t = None
    try:
        if payload:
            if drip:
                # drip 1 byte every 5ms: a server doing read() would get partial
                for b in payload:
                    s.sendall(bytes([b]))
                    sent += 1
                    time.sleep(0.005)
            else:
                s.sendall(payload)
                sent = len(payload)
        send_t = time.time()
    except Exception as e:
        return {"port": port, "send_err": repr(e), "sent": sent,
                "t_connect_ms": round((t_conn - t0) * 1000, 2)}
    got = b""
    kind = "TIMEOUT"
    t_fin = None
    try:
        while True:
            c = s.recv(4096)
            t_fin = time.time()
            if not c:
                kind = "FIN"
                break
            got += c
    except socket.timeout:
        kind = "TIMEOUT"
    except ConnectionResetError:
        kind = "RST"
        t_fin = time.time()
    except Exception as e:
        kind = "ERR:" + repr(e)
    rec = {
        "port": port, "sent": sent, "recv": len(got), "recv_hex": got[:128].hex(),
        "close": kind,
        "t_connect_ms": round((t_conn - t0) * 1000, 2),
        "t_send_done_ms": round((send_t - t0) * 1000, 2) if send_t else None,
        "t_fin_ms": round((t_fin - t0) * 1000, 2) if t_fin else None,
        "fin_minus_send_ms": (round((t_fin - send_t) * 1000, 2)
                              if (t_fin and send_t) else None),
    }
    s.close()
    return rec


print("### A. concurrency: 6 simultaneous idle connections to 13401")
out = []


def worker(i):
    out.append(one(13401, b"", wait=6.0))


ths = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
t0 = time.time()
[t.start() for t in ths]
[t.join() for t in ths]
res["concurrent_13401"] = out
for r in out:
    print(json.dumps(r))

print("\n### B. 13401: payload sent, measure FIN relative to send completion")
b = []
for i in range(4):
    r = one(13401, b"A" * 16, wait=6.0)
    b.append(r)
    print(json.dumps(r))
res["send_vs_fin_13401"] = b

print("\n### C. 13401: slow drip 32 bytes (1 byte / 5ms)")
c = one(13401, b"B" * 32, wait=6.0, drip=True)
print(json.dumps(c))
res["drip_13401"] = c

print("\n### D. 13400 control: same drip + DoIP ident, expect a real response")
d1 = one(13400, bytes.fromhex("02fd000100000000"), wait=6.0)
print("13400 doip_ident:", json.dumps(d1))
res["doip_ident_13400"] = d1
d2 = one(13400, b"", wait=4.0)
print("13400 idle      :", json.dumps(d2))
res["idle_13400"] = d2

p = os.path.join(OUT, "13401_final_discriminators.json")
with open(p, "w", encoding="utf-8") as f:
    json.dump(res, f, indent=2)
print("\n[written]", p)

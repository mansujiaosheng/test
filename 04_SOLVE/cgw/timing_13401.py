#!/usr/bin/env python3
"""Round-2: measure close latency on 13401 (accept-then-close? or read?)"""
import socket, time, json, binascii, sys

HOST = "10.229.221.2"; PORT = 13401
def run(label, payload, wait=2.0):
    s = socket.socket(); s.settimeout(5)
    t0 = time.time(); s.connect((HOST, PORT)); tc = time.time()
    if payload: s.sendall(payload); ts = time.time()
    else: ts = tc
    s.settimeout(wait)
    try:
        c = s.recv(4096)
        te = time.time()
        r = dict(label=label, send=bool(payload), rx_len=len(c),
                 close_after_connect_ms=round((te-tc)*1000,2), close_after_send_ms=round((te-ts)*1000,2),
                 outcome="FIN" if c == b"" else "DATA:"+binascii.hexlify(c).decode())
    except ConnectionResetError:
        te = time.time()
        r = dict(label=label, send=bool(payload), outcome="RST",
                 close_after_connect_ms=round((te-tc)*1000,2), close_after_send_ms=round((te-ts)*1000,2))
    except socket.timeout:
        te = time.time()
        r = dict(label=label, send=bool(payload), outcome="TIMEOUT_NO_CLOSE", waited_ms=round((te-tc)*1000,1))
    print(json.dumps(r), flush=True)
    s.close(); time.sleep(0.3)

if __name__ == "__main__":
    for i in range(3): run("connect_only_%d" % i, b"")
    for i in range(3): run("send_1B_%d" % i, b"\x41")
    run("send_after_100ms", b"\x41", wait=2.0)   # placeholder; separate below

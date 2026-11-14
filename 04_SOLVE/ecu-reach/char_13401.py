#!/usr/bin/env python3
"""Characterise CGW TCP/13401 precisely.

Hypothesis under test: 13401 is an accept-then-immediate-close listener (source-IP ACL
or placeholder), NOT a protocol parser waiting for a specific handshake.

Signature that separates the two:
  * connect() returns after 1 RTT (~26 ms)
  * server FIN arrives ~1 RTT later (~26 ms) even though the client sent NOTHING
  -> the server closed on accept, it never waited for client input.
A parser-based service would instead keep the socket open until input arrives (or a
long idle timeout), so the "silent" case would time out, not EOF at 26 ms.
"""
from __future__ import annotations

import socket
import statistics
import time
import select
import sys
import json
from datetime import datetime

HOSTS = [("10.226.193.2", 13401), ("10.225.139.4", 13401)]
SENT = b"\x02\xfd\x00\x05\x00\x00\x00\x07\x0e\x00\x00\x00\x00\x00\x00"

CASES = {
    "silent(no bytes)": b"",
    "doip-ra": SENT,
    "http-get": b"GET / HTTP/1.1\r\nHost: cgw\r\nConnection: close\r\n\r\n",
    "http-connect": b"CONNECT 10.226.197.5:8080 HTTP/1.1\r\nHost: 10.226.197.5\r\n\r\n",
    "ws-upgrade": b"GET /canfd HTTP/1.1\r\nHost: cgw\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    "h2-preface": b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    "socks5": b"\x05\x01\x00",
    "mqtt-connect": b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00",
    "ssh-banner": b"SSH-2.0-probe\r\n",
    "grpc-empty-frame": b"\x00\x00\x00\x00\x00",
    "doip-v1": b"\x01\xfe\x00\x01\x00\x00\x00\x00",
    "doip-v3": b"\x03\xfc\x00\x01\x00\x00\x00\x00",
    "can-7e0": b"\x07\xe0\x08\x02\x22\xf1\x90\x00\x00\x00\x00\x00",
    "zeroes16": b"\x00" * 16,
}


def one(host, port, payload, wait=0.8):
    ev = {"connect_ms": None, "eof_after_connect_ms": None, "rx_len": 0,
          "rx_hex": "", "error": None, "eof": False}
    s = socket.socket(); s.settimeout(3.0)
    t0 = time.time()
    try:
        s.connect((host, port))
    except OSError as e:
        ev["error"] = f"connect:{type(e).__name__}"; s.close(); return ev
    tc = time.time()
    ev["connect_ms"] = round((tc - t0) * 1000, 1)
    try:
        if payload:
            s.sendall(payload)
        buf = b""
        deadline = time.time() + wait
        while time.time() < deadline:
            r, _, _ = select.select([s], [], [], 0.05)
            if not r:
                continue
            d = s.recv(4096)
            if not d:
                ev["eof"] = True
                ev["eof_after_connect_ms"] = round((time.time() - tc) * 1000, 1)
                break
            buf += d
        ev["rx_len"] = len(buf); ev["rx_hex"] = buf.hex()
    except OSError as e:
        ev["error"] = type(e).__name__
    finally:
        try: s.close()
        except Exception: pass
    return ev


def main():
    out = {"started": datetime.now().astimezone().isoformat(timespec="seconds"),
           "note": "13401 accept-then-close characterisation; client sends nothing in 'silent' case",
           "results": []}
    for host, port in HOSTS:
        # timing distribution, silent
        cms, ems = [], []
        for _ in range(10):
            e = one(host, port, b"", wait=1.0)
            if e["connect_ms"] is not None:
                cms.append(e["connect_ms"])
            if e["eof_after_connect_ms"] is not None:
                ems.append(e["eof_after_connect_ms"])
            time.sleep(0.1)
        rec = {"host": host, "port": port, "silent_timing":
               {"connect_ms_median": round(statistics.median(cms), 1) if cms else None,
                "eof_after_connect_ms_median": round(statistics.median(ems), 1) if ems else None,
                "eof_samples": len(ems), "n": 10}}
        print(f"== {host}:{port} silent: connect med={rec['silent_timing']['connect_ms_median']}ms "
              f"EOF-after-connect med={rec['silent_timing']['eof_after_connect_ms_median']}ms "
              f"({len(ems)}/10)", flush=True)
        out["results"].append(rec)

        # full payload battery
        for name, payload in CASES.items():
            e = one(host, port, payload)
            e["case"] = name
            out["results"].append(dict(e, host=host, port=port))
            print(f"   {name:<20} rx={e['rx_len']:>3}B eof={e['eof']} "
                  f"eof_after={e['eof_after_connect_ms']} err={e['error']}", flush=True)
    text = json.dumps(out, ensure_ascii=False, indent=2)
    with open(sys.argv[1] if len(sys.argv) > 1 else "13401_char.json", "w", encoding="utf-8") as f:
        f.write(text + "\n")
    print("wrote", sys.argv[1] if len(sys.argv) > 1 else "13401_char.json")


if __name__ == "__main__":
    main()

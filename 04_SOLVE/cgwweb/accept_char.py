#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Precisely characterise what :13401 does right after accept().

Measures, per trial: time to FIN/RST, bytes received, and whether the peer
sent FIN (recv -> b"") or RST (ConnectionResetError).  Compares hosts.
"""
from __future__ import annotations

import json
import socket
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVID = ROOT / "03_EVIDENCE" / "cgwweb"


def one(host, port, wait=2.0, send=None):
    t0 = time.time()
    s = socket.create_connection((host, port), timeout=4)
    t_conn = (time.time() - t0) * 1000
    s.settimeout(wait)
    if send:
        s.sendall(send)
    ev = "timeout(no event)"
    data = b""
    try:
        while True:
            c = s.recv(4096)
            if not c:
                ev = "FIN"
                break
            data += c
    except socket.timeout:
        ev = "timeout(still open)"
    except ConnectionResetError:
        ev = "RST"
    except Exception as e:
        ev = f"{type(e).__name__}"
    t_ev = (time.time() - t0) * 1000
    try:
        s.close()
    except OSError:
        pass
    return {"host": host, "port": port, "connect_ms": round(t_conn, 1),
            "event": ev, "at_ms": round(t_ev, 1), "recv_bytes": len(data),
            "recv_hex": data.hex().upper()}


def main():
    jobs = [("10.229.221.2", 13401), ("10.230.164.4", 13401),
            ("10.229.221.2", 13400), ("10.230.164.4", 13400)]
    out = []
    for host, port in jobs:
        for trial in range(3):
            try:
                r = one(host, port)
            except Exception as e:
                r = {"host": host, "port": port, "error": f"{type(e).__name__}: {e}"}
            r["trial"] = trial
            out.append(r)
            print(json.dumps(r, ensure_ascii=False))
    rec = {"label": "port13401_accept_behaviour", "ts": datetime.now().astimezone().isoformat(),
           "rows": out}
    (EVID / "4012_port13401_accept_behaviour.json").write_text(
        json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()

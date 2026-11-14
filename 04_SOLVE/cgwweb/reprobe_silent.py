#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-probe LAs that returned *no* response in the 0x0000-0x00FF scan.

Purpose: distinguish
  (a) genuine "gateway forwarded it and nobody answered"  -> stays silent even
      with a 2 s wait, repeatedly, on a fresh socket
  (b) measurement noise (short quiet window, server hiccup) -> becomes 7F3E31

Evidence -> 03_EVIDENCE/cgwweb/
"""
from __future__ import annotations

import json
import socket
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVID = ROOT / "03_EVIDENCE" / "cgwweb"

HOST = "10.229.221.2"
PORT = 13400
SA = 0x0E00


def hx(b):
    return b.hex().upper()


class Conn:
    def __init__(self, host, port, timeout=4.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b""

    def send(self, ptype, payload=b"", ver=2):
        self.s.sendall(bytes([ver, 0xFF - ver]) + struct.pack(">H", ptype)
                       + struct.pack(">I", len(payload)) + payload)

    def recv(self, timeout):
        end = time.time() + timeout
        while True:
            if len(self.buf) >= 8:
                ver, inv, ptype, plen = struct.unpack(">BBHI", self.buf[:8])
                if len(self.buf) >= 8 + plen:
                    p = self.buf[8:8 + plen]
                    self.buf = self.buf[8 + plen:]
                    return ptype, p
            rem = end - time.time()
            if rem <= 0:
                return None
            self.s.settimeout(rem)
            try:
                c = self.s.recv(65536)
            except socket.timeout:
                return None
            if not c:
                return None
            self.buf += c

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def main():
    targets = [int(x, 16) for x in (
        "0038 0039 00B6 00BB 00BC 00C0 00C8 00D0 00D8 00DC 00E0 00E3 00EF "
        "07E0 07E1 07E2 07E8 07E9 07EA 07EB 1000 0002"
    ).split()]
    wait = float(sys.argv[1]) if len(sys.argv) > 1 else 2.0
    rows = []
    for trial in range(2):
        c = Conn(HOST, PORT)
        # routing activation
        c.send(0x0005, struct.pack(">H", SA) + bytes([0]) + b"\x00\x00\x00\x00")
        ra = c.recv(3.0)
        for ta in targets:
            payload = struct.pack(">HH", SA, ta) + b"\x3e\x00"
            t0 = time.time()
            c.send(0x8001, payload)
            got = []
            while True:
                fr = c.recv(wait)
                if fr is None:
                    break
                got.append(fr)
                if len(got) >= 4:
                    break
            el = round((time.time() - t0) * 1000, 1)
            rows.append({"trial": trial, "ta": f"0x{ta:04X}", "ms": el,
                         "frames": [{"ptype": f"0x{p:04X}", "hex": hx(d)} for p, d in got],
                         "silent": len(got) == 0})
            tag = "SILENT" if not got else " ".join(hx(d) for _, d in got)
            print(f"  trial{trial} 0x{ta:04X} {el:>7.1f}ms {tag}")
        c.close()
    rec = {"label": "reprobe_silent_las", "ts": datetime.now().astimezone().isoformat(),
           "wait_s": wait, "rows": rows,
           "note": "re-verify LAs that produced no frame in la_scan_0000_00FF"}
    (EVID / "4120_reprobe_silent_las.json").write_text(
        json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DoIP <-> CAN FD bridge client for the CyberCar CGW.

Purpose: drive UDS requests through the central gateway (DoIP, ISO 13400-2)
down to the CAN FD powertrain nodes, and keep an exact record of which logical
address answered.

The gateway behaves like a DoIP "edge node": a diagnostic message addressed to
a functional CAN identifier (0x0700 seen) is fanned out to several ECUs and each
answer comes back as its own 0x8001 message, so the *source* address in the
response is the only way to tell ECUs apart.

Read-only policy: this module refuses state-changing UDS services unless the
caller explicitly passes allow_write=True (used only where the challenge task
requires it, e.g. 0x10 session control for reading memory).
"""
from __future__ import annotations

import socket
import struct
import time

PT_DIAG_MSG = 0x8001
PT_DIAG_ACK = 0x8002
PT_DIAG_NACK = 0x8003


def doip_pkt(ptype: int, payload: bytes = b"", ver: int = 0x02) -> bytes:
    return bytes([ver, 0xFF - ver]) + struct.pack(">HI", ptype, len(payload)) + payload


class DoIP:
    def __init__(self, host: str = "10.229.221.2", port: int = 13400,
                 sa: int = 0x0E00, timeout: float = 3.0):
        self.host, self.port, self.sa = host, port, sa
        self.timeout = timeout
        self.buf = b""
        self.sock = None
        self.log: list[dict] = []

    # ---------------------------------------------------------------- socket
    def connect(self, activate: bool = True, act_type: int = 0x00):
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b""
        if activate:
            self.raw(0x0005, struct.pack(">H", self.sa) + bytes([act_type]) + b"\x00" * 4)
            r = self.recv(self.timeout)
            if r is None:
                raise RuntimeError("no routing activation response")
            v, t, d = r
            if t != 0x0006 or len(d) < 5:
                raise RuntimeError(f"routing activation failed: ptype=0x{t:04X} {d.hex()}")
            tester, entity, code = struct.unpack(">HHB", d[:5])
            self.log.append({"ra": {"tester": tester, "entity": entity, "code": code}})
            if code != 0x10:
                raise RuntimeError(f"routing activation denied code=0x{code:02X}")
            self.sa = tester
        return self

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *a):
        self.close()

    def raw(self, ptype: int, payload: bytes = b""):
        self.sock.sendall(doip_pkt(ptype, payload))

    def recv(self, timeout: float | None = None):
        timeout = self.timeout if timeout is None else timeout
        end = time.time() + max(timeout, 0.0)
        while True:
            if len(self.buf) >= 8:
                ver, inv, ptype, plen = struct.unpack(">BBHI", self.buf[:8])
                if len(self.buf) >= 8 + plen:
                    payload = self.buf[8:8 + plen]
                    self.buf = self.buf[8 + plen:]
                    return ver, ptype, payload
            rem = end - time.time()
            if rem <= 0:
                return None
            self.sock.settimeout(rem)
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                return None
            if not chunk:
                raise ConnectionError("peer closed")
            self.buf += chunk

    # ------------------------------------------------------------------ UDS
    def uds(self, ta: int, body: bytes, quiet: float = 0.25, total: float | None = None):
        """Send one UDS request, collect every diagnostic answer until quiet.

        Returns list of dicts {src, dst, body(hex), raw}.
        """
        total = self.timeout if total is None else total
        self.raw(PT_DIAG_MSG, struct.pack(">HH", self.sa, ta) + body)
        out = []
        end = time.time() + total
        nacks = []
        while time.time() < end:
            r = self.recv(min(quiet, max(0.0, end - time.time())))
            if r is None:
                break
            v, ptype, d = r
            if ptype == PT_DIAG_MSG and len(d) >= 4:
                src, dst = struct.unpack(">HH", d[:4])
                out.append({"src": src, "dst": dst, "body": d[4:], "hex": d[4:].hex().upper()})
            elif ptype == PT_DIAG_NACK and len(d) >= 5:
                nacks.append({"raw": d.hex(), "code": d[4]})
            elif ptype == PT_DIAG_ACK:
                pass
        if nacks and not out:
            for n in nacks:
                out.append({"src": None, "dst": None, "body": b"", "hex": "",
                            "nack": n["code"]})
        self.log.append({"ta": ta, "req": body.hex().upper(), "answers": [
            {"src": (f"0x{a['src']:04X}" if a.get("src") is not None else None),
             "hex": a["hex"], "nack": a.get("nack")} for a in out]})
        return out

    def uds_one(self, ta: int, body: bytes, **kw):
        answers = self.uds(ta, body, **kw)
        return answers[0] if answers else None


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.229.221.2")
    ap.add_argument("--port", type=int, default=13400)
    ap.add_argument("--ta", default="0700")
    ap.add_argument("--req", default="3E00")
    ap.add_argument("--quiet", type=float, default=0.3)
    ap.add_argument("--total", type=float, default=3.0)
    a = ap.parse_args()
    with DoIP(a.host, a.port) as c:
        print(f"activated tester=0x{c.sa:04X}")
        ans = c.uds(int(a.ta, 16), bytes.fromhex(a.req), quiet=a.quiet, total=a.total)
        for x in ans:
            src = f"0x{x['src']:04X}" if x.get("src") is not None else "nack"
            print(f"  {src} {x['hex']}")


if __name__ == "__main__":
    main()

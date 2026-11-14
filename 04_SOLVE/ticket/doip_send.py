#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal DoIP + UDS raw sender (full control, no read-only guard).

Purpose: work out *how* the 8443 diagnosticTicket is presented to the CGW.
Every request/response is dumped verbatim to 03_EVIDENCE/ticket/.

DoIP (ISO 13400-2) over TCP 13400:
  generic header: 02 FD | ptype(2) | plen(4 BE)
  routing activation req (0x0005): SA(2) acttype(1) reserved(4) [OEM(4)]
  diag message (0x8001): SA(2) TA(2) data[..]
  diag ack  (0x8002): SA(2) TA(2) ackcode(1) prev(4)
"""
import binascii
import json
import os
import socket
import struct
import sys
import time

DEFAULT_HOST = "10.226.193.2"
DEFAULT_PORT = 13400
DEFAULT_SA = 0x0E00

EVID = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "03_EVIDENCE", "ticket")


class DoIP:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, sa=DEFAULT_SA, timeout=3.0):
        self.host, self.port, self.sa, self.timeout = host, port, sa, timeout
        self.sock = None
        self.log = []

    def open(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        return self

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None

    def _send(self, ptype, payload, note=""):
        frame = struct.pack(">BBHI", 0x02, 0xFD, ptype, len(payload)) + payload
        self.log.append({"dir": "tx", "note": note, "ptype": ptype,
                         "hex": frame.hex(), "t": time.time()})
        self.sock.sendall(frame)
        return frame

    def _recv_one(self, wait=None):
        self.sock.settimeout(wait or self.timeout)
        hdr = b""
        while len(hdr) < 8:
            d = self.sock.recv(8 - len(hdr))
            if not d:
                return None, None
            hdr += d
        if hdr[0:2] != b"\x02\xfd":
            return None, hdr
        ptype, plen = struct.unpack(">HI", hdr[2:8])
        body = b""
        while len(body) < plen:
            d = self.sock.recv(plen - len(body))
            if not d:
                break
            body += d
        self.log.append({"dir": "rx", "ptype": ptype, "plen": plen, "hex": (hdr + body).hex(),
                         "t": time.time()})
        return ptype, body

    def drain(self, wait=0.6):
        out = []
        while True:
            try:
                pt, body = self._recv_one(wait)
            except socket.timeout:
                break
            if pt is None:
                break
            out.append((pt, body))
        return out

    def routing_activation(self, act=0x00, oem=None, note="RA"):
        pay = struct.pack(">HB", self.sa, act) + b"\x00\x00\x00\x00"
        if oem is not None:
            pay += oem
        self._send(0x0005, pay, note)
        pt, body = self._recv_one()
        if pt == 0x0006 and body and len(body) >= 5:
            code = body[4]
            return {"code": code, "hex": body.hex(),
                    "extra": body[5:].hex() if len(body) > 5 else None}
        return {"code": None, "ptype": pt, "hex": body.hex() if body else None}

    def uds(self, ta, data, wait=None, note=""):
        """>0x8001 diagnostic message; returns (uds_bytes, ackcode, raw)"""
        pay = struct.pack(">HH", self.sa, ta) + bytes(data)
        self._send(0x8001, pay, note)
        uds, ack = None, None
        deadline = time.time() + (wait or self.timeout)
        while time.time() < deadline:
            try:
                pt, body = self._recv_one(max(0.05, deadline - time.time()))
            except socket.timeout:
                break
            if pt is None:
                break
            if pt == 0x8002 and len(body) >= 5:
                ack = body[4]
            elif pt == 0x8003 and len(body) >= 5:
                ack = -body[4] if body[4] else -1
            elif pt == 0x8001 and len(body) >= 4:
                uds = body[4:]
                break
        return uds, ack


def hexs(b):
    return binascii.hexlify(b).decode().upper() if b else None


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["ra", "uds", "seq"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--sa", default="0E00")
    a = ap.parse_args()
    sa = int(a.sa, 16)
    c = DoIP(a.host, a.port, sa).open()
    try:
        print("RA:", c.routing_activation())
        if a.cmd == "uds":
            ta, req = int(a.args[0], 16), bytes.fromhex(a.args[1])
            uds, ack = c.uds(ta, req)
            print("TA=0x%04X req=%s -> uds=%s ack=%s" % (ta, hexs(req), hexs(uds), ack))
        elif a.cmd == "seq":
            for spec in a.args:
                ta, req = spec.split(":")
                ta = int(ta, 16)
                req = bytes.fromhex(req)
                uds, ack = c.uds(ta, req)
                print("0x%04X %-24s -> %s (ack=%s)" % (ta, hexs(req), hexs(uds), ack))
                time.sleep(0.15)
    finally:
        out = os.path.join(EVID, "0210_doip_%s.json" % time.strftime("%H%M%S"))
        json.dump(c.log, open(out, "w"), indent=1)
        c.close()
        print("logged:", out)


if __name__ == "__main__":
    main()

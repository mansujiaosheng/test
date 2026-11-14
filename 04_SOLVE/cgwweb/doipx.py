#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ecu-bridge DoIP/UDS probe client (ISO 13400-2 + ISO 14229-1).

Evidence output goes to 03_EVIDENCE/cgwweb/ ONLY (this worker's directory).
Never writes 03_EVIDENCE/cgw/ (lead's DoIP master dir).

Read-only guard: only 0x22, 0x19, 0x3E, 0x27-odd(requestSeed), 0x31-03
(requestRoutineResults) may leave the socket.

Usage:
  python doipx.py ident   [--host H --port P]
  python doipx.py la <lo> <hi> [step]      # logical-address existence scan
  python doipx.py uds <TA> <hexbytes>      # one read-only UDS request
  python doipx.py dids <TA> <did1,did2..>  # read a list of DIDs from TA
"""
from __future__ import annotations

import argparse
import json
import select
import socket
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVID = ROOT / "03_EVIDENCE" / "cgwweb"
EVID.mkdir(parents=True, exist_ok=True)

PT_IDENT_REQ = 0x0001
PT_IDENT_RSP = 0x0004
PT_RA_REQ = 0x0005
PT_RA_RSP = 0x0006
PT_DIAG = 0x8001
PT_ACK = 0x8002
PT_NACK = 0x8003
PT_ENTITY_REQ = 0x4001
PT_ENTITY_RSP = 0x4002

UDS_NAMES = {0x10: "SessionControl", 0x11: "ECUReset", 0x14: "ClearDTC",
             0x19: "ReadDTC", 0x22: "ReadDataByIdentifier", 0x27: "SecurityAccess",
             0x28: "CommControl", 0x2E: "WriteDID", 0x2F: "IOControl",
             0x31: "RoutineControl", 0x34: "RequestDownload", 0x36: "TransferData",
             0x3E: "TesterPresent", 0x85: "ControlDTCSetting"}
NRC_NAMES = {0x10: "generalReject", 0x11: "serviceNotSupported",
             0x12: "subFunctionNotSupported", 0x13: "incorrectLength",
             0x21: "busyRepeatRequest", 0x22: "conditionsNotCorrect",
             0x24: "requestSequenceError", 0x25: "noResponseFromSubnetComponent",
             0x26: "failurePreventsExecution", 0x31: "requestOutOfRange",
             0x33: "securityAccessDenied", 0x35: "invalidKey",
             0x36: "exceedNumberOfAttempts", 0x37: "requiredTimeDelayNotExpired",
             0x72: "generalProgrammingFailure", 0x78: "responsePending",
             0x7E: "subFuncNotSupportedInActiveSession",
             0x7F: "serviceNotSupportedInActiveSession"}

_seq = [0]
_wire = None


def hx(b: bytes) -> str:
    return b.hex().upper()


def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _wire_open():
    global _wire
    if _wire is None:
        _wire = open(EVID / "wire.log", "a", encoding="utf-8")
    return _wire


def wire(direction: str, ptype: int, data: bytes):
    f = _wire_open()
    f.write(f"{now()} {direction} pt=0x{ptype:04X} len={len(data)} {hx(data)}\n")
    f.flush()


def record(rec: dict) -> dict:
    _seq[0] += 1
    rec["seq"] = _seq[0]
    rec["ts"] = now()
    p = EVID / f"{_seq[0]:04d}_{rec.get('label', 'rec')}.json"
    p.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
    return rec


def assert_read_only(uds: bytes):
    if not uds:
        raise ValueError("empty UDS")
    sid = uds[0]
    if sid in (0x2E, 0x2F, 0x11, 0x14, 0x28, 0x85, 0x34, 0x35, 0x36, 0x37, 0x38):
        raise ValueError(f"refused: SID 0x{sid:02X} mutates state")
    if sid == 0x31 and (len(uds) < 2 or uds[1] != 0x03):
        raise ValueError("refused: 0x31 only sub 0x03 (requestRoutineResults)")
    if sid == 0x27 and (len(uds) < 2 or uds[1] % 2 == 0):
        raise ValueError("refused: 0x27 even sub-function = sendKey")
    if sid not in (0x10, 0x19, 0x22, 0x27, 0x31, 0x3E):
        raise ValueError(f"refused: SID 0x{sid:02X} not on read-only allowlist")


def parse_uds(data: bytes) -> str:
    if len(data) < 5:
        return "short"
    src, dst = struct.unpack(">HH", data[:4])
    body = data[4:]
    if not body:
        return f"from 0x{src:04X} empty"
    if body[0] == 0x7F and len(body) >= 3:
        return (f"0x{src:04X} NEG {UDS_NAMES.get(body[1], hex(body[1]))} "
                f"NRC=0x{body[2]:02X}({NRC_NAMES.get(body[2], '?')})")
    return f"0x{src:04X} POS {UDS_NAMES.get(body[0], hex(body[0]))} data={hx(body)}"


class Conn:
    def __init__(self, host: str, port: int, timeout: float = 3.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b""
        self.host, self.port = host, port

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, ptype: int, payload: bytes = b"", ver: int = 0x02):
        frame = bytes([ver, 0xFF - ver]) + struct.pack(">H", ptype) + struct.pack(">I", len(payload)) + payload
        self.sock.sendall(frame)
        wire("TX", ptype, payload)

    def _pop(self):
        if len(self.buf) < 8:
            return None
        ver, inv, ptype, plen = struct.unpack(">BBHI", self.buf[:8])
        if len(self.buf) < 8 + plen:
            return None
        payload = self.buf[8:8 + plen]
        self.buf = self.buf[8 + plen:]
        return ptype, payload

    def recv(self, timeout: float):
        end = time.time() + max(timeout, 0.0)
        while True:
            fr = self._pop()
            if fr:
                wire("RX", fr[0], fr[1])
                return fr
            rem = end - time.time()
            if rem <= 0:
                return None
            r, _, _ = select.select([self.sock], [], [], rem)
            if not r:
                return None
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("peer closed")
            self.buf += chunk

    def drain(self, quiet: float = 0.15, total: float = 4.0):
        frames = []
        end = time.time() + total
        while time.time() < end:
            fr = self.recv(min(quiet, max(0.0, end - time.time())))
            if fr is None:
                break
            frames.append(fr)
        return frames


class Link:
    def __init__(self, conn: Conn, sa: int, timeout: float):
        self.conn, self.sa, self.timeout = conn, sa, timeout

    def activate(self, sa=None, act=0x00, label="ra") -> dict:
        sa = sa if sa is not None else self.sa
        payload = struct.pack(">H", sa) + bytes([act]) + b"\x00\x00\x00\x00"
        t0 = time.time()
        self.conn.send(PT_RA_REQ, payload)
        fr = self.conn.recv(self.timeout)
        el = round((time.time() - t0) * 1000, 2)
        rec = {"label": label, "request_hex": hx(payload), "elapsed_ms": el}
        if fr is None:
            rec["parsed"] = "NO RESPONSE"
        elif fr[0] == PT_RA_RSP and len(fr[1]) >= 5:
            tester, entity, code = struct.unpack(">HHB", fr[1][:5])
            rec.update({"tester_sa": f"0x{tester:04X}", "entity_la": f"0x{entity:04X}",
                        "code": f"0x{code:02X}", "response_hex": hx(fr[1])})
            self.sa = tester
        else:
            rec.update({"ptype": f"0x{fr[0]:04X}", "response_hex": hx(fr[1])})
        return record(rec)

    def uds_raw(self, ta: int, uds: bytes, quiet=0.15, total=4.0):
        assert_read_only(uds)
        payload = struct.pack(">HH", self.sa, ta) + uds
        t0 = time.time()
        self.conn.send(PT_DIAG, payload)
        frames = self.conn.drain(quiet=quiet, total=total)
        # ISO 14229 P2*: keep reading while 0x7F xx 78 pending
        for _ in range(4):
            if not any(p == PT_DIAG and len(d) >= 7 and d[4:7] == bytes([0x7F, uds[0], 0x78])
                       for p, d in frames):
                break
            frames += self.conn.drain(quiet=max(quiet, 0.9), total=10.0)
        return frames, round((time.time() - t0) * 1000, 2)


def probe_la(link: Link, ta: int, label: str, purpose: str, write: bool = True) -> dict:
    frames, el = link.uds_raw(ta, b"\x3e\x00")
    diag = [d for p, d in frames if p == PT_DIAG]
    nack = [d for p, d in frames if p == PT_NACK]
    ack = [d for p, d in frames if p == PT_ACK]
    rec = {"label": label, "purpose": purpose, "tester_sa": f"0x{link.sa:04X}",
           "target_la": f"0x{ta:04X}", "elapsed_ms": el,
           "responses": [hx(d) for d in diag], "acks": [hx(d) for d in ack],
           "nacks": [hx(d) for d in nack],
           "parsed": [parse_uds(d) for d in diag]}
    # classify from RAW frames, not from hex strings
    nrc = None
    for d in diag:
        if len(d) >= 7 and d[4] == 0x7F:
            nrc = d[6]
            break
    if not diag:
        rec["cls"] = "silent"
    elif nrc == 0x31:
        rec["cls"] = "absent"
    elif nrc == 0x11:
        rec["cls"] = "present_nosvc"
    else:
        rec["cls"] = "present"
    if write:
        record(rec)
    return rec


def nrc_of(diag_frames):
    for d in diag_frames:
        if len(d) >= 7 and d[4] == 0x7F:
            return d[6]
    return None


def cmd_ident(args):
    conn = Conn(args.host, args.port, args.timeout)
    try:
        conn.send(PT_IDENT_REQ, b"")
        frames = conn.drain(quiet=1.2, total=6.0)
        rec = {"label": f"ident_{args.port}", "host": args.host, "port": args.port,
               "responses": [{"ptype": f"0x{p:04X}", "hex": hx(d)} for p, d in frames]}
        rec = record(rec)
        print(json.dumps(rec, indent=2, ensure_ascii=False))
    finally:
        conn.close()


def cmd_la(args):
    lo, hi, step = args.lo, args.hi, args.step
    conn = Conn(args.host, args.port, args.timeout)
    try:
        link = Link(conn, args.sa, args.timeout)
        ra = link.activate(label="ra_for_la_scan")
        print("RA:", json.dumps(ra, ensure_ascii=False))
        rows = []
        t0 = time.time()
        ta = lo
        while ta <= hi:
            rec = probe_la(link, ta, f"la_{ta:04X}", f"LA existence probe 0x{ta:04X}")
            cls = rec["cls"]
            if cls != "absent":
                record(rec)
            rows.append({"ta": f"0x{ta:04X}", "cls": cls, "resp": rec["parsed"],
                         "nack": rec["nacks"]})
            if cls not in ("absent",):
                print(f"  [{cls}] 0x{ta:04X} {rec['parsed']} {rec['nacks']}")
            ta += step
            time.sleep(0.05)
        summ = record({"label": f"la_scan_{lo:04X}_{hi:04X}",
                       "purpose": "DoIP logical-address existence scan (3E00 oracle)",
                       "range": [f"0x{lo:04X}", f"0x{hi:04X}"], "step": step,
                       "elapsed_s": round(time.time() - t0, 1),
                       "hits": [r for r in rows if r["cls"] != "absent"],
                       "total": len(rows)})
        print(f"\n{len(rows)} probed, {len(summ['hits'])} non-absent, "
              f"{summ['elapsed_s']}s -> 03_EVIDENCE/cgwweb/{summ['seq']:04d}_*.json")
    finally:
        conn.close()


def cmd_uds(args):
    conn = Conn(args.host, args.port, args.timeout)
    try:
        link = Link(conn, args.sa, args.timeout)
        link.activate(label="ra_for_uds")
        uds = bytes.fromhex(args.hexbytes)
        frames, el = link.uds_raw(args.ta, uds, quiet=args.quiet, total=args.total)
        diag = [d for p, d in frames if p == PT_DIAG]
        rec = record({"label": f"uds_{args.ta:04X}_{uds.hex().upper()}",
                      "tester_sa": f"0x{link.sa:04X}", "target_la": f"0x{args.ta:04X}",
                      "request_uds": hx(uds), "elapsed_ms": el,
                      "responses": [hx(d) for d in diag],
                      "acks": [hx(d) for p, d in frames if p == PT_ACK],
                      "nacks": [hx(d) for p, d in frames if p == PT_NACK],
                      "parsed": [parse_uds(d) for d in diag]})
        print(json.dumps(rec, indent=2, ensure_ascii=False))
    finally:
        conn.close()


def cmd_dids(args):
    dids = [int(x, 16) for x in args.dids.replace(" ", "").split(",") if x]
    conn = Conn(args.host, args.port, args.timeout)
    try:
        link = Link(conn, args.sa, args.timeout)
        link.activate(label="ra_for_dids")
        for did in dids:
            uds = struct.pack(">BH", 0x22, did)
            frames, el = link.uds_raw(args.ta, uds, quiet=args.quiet, total=args.total)
            diag = [d for p, d in frames if p == PT_DIAG]
            parsed = [parse_uds(d) for d in diag]
            rec = record({"label": f"did_{args.ta:04X}_{did:04X}",
                          "target_la": f"0x{args.ta:04X}", "did": f"0x{did:04X}",
                          "request_uds": hx(uds), "elapsed_ms": el,
                          "responses": [hx(d) for d in diag],
                          "parsed": parsed})
            print(f"0x{did:04X}: {parsed}")
            time.sleep(0.05)
    finally:
        conn.close()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.229.221.2")
    ap.add_argument("--port", type=int, default=13400)
    ap.add_argument("--sa", type=lambda s: int(s, 16), default=0x0E00)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--quiet", type=float, default=0.15)
    ap.add_argument("--total", type=float, default=4.0)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("ident")

    p = sub.add_parser("la")
    p.add_argument("lo", type=lambda s: int(s, 16))
    p.add_argument("hi", type=lambda s: int(s, 16))
    p.add_argument("step", type=lambda s: int(s, 0), nargs="?", default=1)

    p = sub.add_parser("uds")
    p.add_argument("ta", type=lambda s: int(s, 16))
    p.add_argument("hexbytes")

    p = sub.add_parser("dids")
    p.add_argument("ta", type=lambda s: int(s, 16))
    p.add_argument("dids")

    args = ap.parse_args(argv)
    {"ident": cmd_ident, "la": cmd_la, "uds": cmd_uds, "dids": cmd_dids}[args.cmd](args)


if __name__ == "__main__":
    main()

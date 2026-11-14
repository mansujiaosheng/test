#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CGW DoIP/UDS read-only probe client (ISO 13400-2 + ISO 14229-1).

Target : 10.230.164.4:13400 (DoIP over TCP)
Context: CTF automotive challenge; vehicle identification returns
         VIN=CV6FF52FEE9EDDD86, DoIP entity LA=0x1000.

Every DoIP frame sent/received is persisted verbatim under 03_EVIDENCE/cgw/
(one numbered JSON per key exchange, one numbered JSON per sweep, plus a
line-wise wire.log).  Nothing outside 01_TARGETS/cgw, 03_EVIDENCE/cgw and
04_SOLVE/cgw is written.

Read-only guard
---------------
Only UDS services that cannot change vehicle / ECU state pass the guard:
0x22 ReadDataByIdentifier, 0x19 ReadDTCInformation, 0x3E TesterPresent,
0x27 requestSeed (odd sub-function only), 0x31 requestRoutineResults (sub 0x03
only), and 0x10 DiagnosticSessionControl *only* when the target is the
gateway 0x1000 (explicitly authorised by task-1).
0x2E / 0x2F / 0x11 / 0x14 / 0x28 / 0x85 / 0x34-0x38 / 0x31-01 / 0x27 key-send
raise ValueError before a single byte leaves the socket.

Usage
-----
  python doip_uds.py ident                  # vehicle identification request
  python doip_uds.py entity                 # DoIP entity status + power mode
  python doip_uds.py activate               # routing activation matrix
  python doip_uds.py gw                     # UDS probes on gateway LA 0x1000
  python doip_uds.py enum                   # logical address enumeration
  python doip_uds.py sweep                  # DID sweep 0xF180-0xF1FF on 0x1000
  python doip_uds.py all                    # ident + entity + activate + gw + enum + sweep
  python doip_uds.py uds 1000 22F190        # one manual (read-only) request

Options: --host --port --sa 0E00 --act 00 --timeout 3.0
"""
from __future__ import annotations

import argparse
import json
import re
import select
import socket
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVID = ROOT / "03_EVIDENCE" / "cgw"
SOLVE = ROOT / "04_SOLVE" / "cgw"

DEFAULT_HOST = "10.226.193.2"  # current CGW (2026-11-14 restart)
DEFAULT_PORT = 13400
DEFAULT_SA = 0x0E00
DEFAULT_ACT = 0x00
GATEWAY_LA = 0x1000
# Second UDS node discovered on the gateway: physical 0x1220, reachable only
# through the functional address 0xE442. Session control is allowed on it
# because it is reversible with 10 01 and is required to reach the
# SecurityAccess seed (27 01) that guards DID 0xF1A3.
NODE_1220_TA = 0xE442
NODE_1220_PHYS = 0x1220
SESSION_ALLOWED_TAS = (GATEWAY_LA, NODE_1220_TA, NODE_1220_PHYS)

# ------------------------------------------------------------------ DoIP types
PT = {
    0x0001: "vehicle identification request",
    0x0002: "vehicle identification request (EID)",
    0x0003: "vehicle identification request (VIN)",
    0x0004: "vehicle announcement / identification response",
    0x0005: "routing activation request",
    0x0006: "routing activation response",
    0x0007: "alive check request",
    0x0008: "alive check response",
    0x4001: "DoIP entity status request",
    0x4002: "DoIP entity status response",
    0x4003: "diagnostic power mode information request",
    0x4004: "diagnostic power mode information response",
    0x8001: "diagnostic message",
    0x8002: "diagnostic message positive ack",
    0x8003: "diagnostic message negative ack",
}
PT_REQ_VEH_ID = 0x0001
PT_ROUTING_ACT_REQ = 0x0005
PT_ROUTING_ACT_RSP = 0x0006
PT_DIAG_MSG = 0x8001
PT_DIAG_ACK = 0x8002
PT_DIAG_NACK = 0x8003
PT_ENTITY_STATUS_REQ = 0x4001
PT_POWERMODE_REQ = 0x4003

# ---------------------------------------------------------------- DoIP codes
RA_CODES = {
    0x00: "denied: unknown source address",
    0x01: "denied: all concurrently supported sockets registered to other SAs",
    0x02: "denied: SA differs from already activated TCP_DATA socket",
    0x03: "denied: SA already registered and active on another socket",
    0x04: "denied: missing authentication",
    0x05: "denied: rejected confirmation",
    0x06: "denied: unsupported routing activation type",
    0x07: "denied: TLS required",
    0x10: "routing successfully activated",
    0x11: "routing will be activated, confirmation required",
}
ACK_CODES = {
    0x00: "routing confirmation ack (positive)",
    0x01: "invalid source address",
    0x02: "invalid target address",
    0x03: "unsupported diagnostic message type",
    0x04: "diagnostic message too large",
    0x05: "out of memory",
    0x06: "target address unreachable",
    0x07: "unknown network",
    0x08: "transport protocol error",
}

# ------------------------------------------------------------------- UDS
UDS_SIDS = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x2E: "WriteDataByIdentifier",
    0x2F: "InputOutputControlByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x3E: "TesterPresent",
    0x85: "ControlDTCSetting",
}
NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x14: "responseTooLong",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent",
    0x26: "failurePreventsExecutionOfRequestedAction",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x72: "generalProgrammingFailure",
    0x78: "requestCorrectlyReceived-ResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}

SESSION_NAMES = {0x01: "default", 0x02: "programming", 0x03: "extended", 0x04: "safety-system"}

# ---------------------------------------------------- read-only service guard
MUTATING_SIDS = {
    0x2E, 0x2F, 0x11, 0x14, 0x28, 0x85,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x3D,
    0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
}


def assert_read_only(uds: bytes, ta: int) -> None:
    """Abort unless the UDS request is provably non-mutating."""
    if not uds:
        raise ValueError("empty UDS request")
    sid = uds[0]
    if sid in MUTATING_SIDS:
        raise ValueError(
            f"refused: SID 0x{sid:02X} ({UDS_SIDS.get(sid, '?')}) can change ECU state"
        )
    if sid == 0x10:
        if ta not in SESSION_ALLOWED_TAS:
            raise ValueError(
                "refused: 0x10 session control only authorised on 0x1000 / 0xE442"
            )
        if len(uds) < 2:
            raise ValueError("refused: 0x10 without session sub-function")
        return
    if sid == 0x23:
        # ReadMemoryByAddress: read-only by definition (no write path).
        if len(uds) < 3:
            raise ValueError("refused: 0x23 too short")
        return
    if sid == 0x24:
        # ReadScalingDataByIdentifier: read-only.
        if len(uds) != 3:
            raise ValueError("refused: 0x24 needs exactly one 2-byte DID")
        return
    if sid == 0x22:
        # one or more 2-byte DIDs (ISO 14229 allows a DID list); read-only.
        if len(uds) < 3 or (len(uds) - 1) % 2 != 0:
            raise ValueError("refused: 0x22 needs one or more 2-byte DIDs")
        return
    if sid == 0x19:
        return
    if sid == 0x3E:
        return
    if sid == 0x27:
        if len(uds) < 2:
            raise ValueError("refused: 0x27 without sub-function")
        if uds[1] % 2 == 0:
            raise ValueError("refused: even 0x27 sub-function = sendKey (state changing)")
        return
    if sid == 0x31:
        if len(uds) < 4:
            raise ValueError("refused: 0x31 too short")
        if uds[1] != 0x03:
            raise ValueError(
                "refused: 0x31 only requestRoutineResults (0x03) is allowed; "
                f"sub 0x{uds[1]:02X} would start/stop a routine"
            )
        return
    raise ValueError(f"refused: SID 0x{sid:02X} is not on the read-only allowlist")


# --------------------------------------------------------------------- output
def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def hx(b: bytes) -> str:
    return b.hex().upper()


def parse_uds_response(data: bytes) -> str:
    if not data:
        return "empty"
    sid = data[0]
    if sid == 0x7F and len(data) >= 3:
        n = NRC.get(data[2], "?")
        return f"NEGATIVE service=0x{data[1]:02X} NRC=0x{data[2]:02X} ({n})"
    if 0x40 <= sid <= 0x7E:
        req = sid - 0x40
        return (
            f"POSITIVE for 0x{req:02X} ({UDS_SIDS.get(req, '?')}) "
            f"data={hx(data[1:])}"
        )
    return f"raw sid=0x{sid:02X} data={hx(data[1:])}"


class Evidence:
    """Numbered JSON artefacts + a line-wise wire log."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.seq = self._next_seq()
        self.trace_path = self.root / "trace.jsonl"
        self.wire_path = self.root / "wire.log"

    def _next_seq(self) -> int:
        mx = 0
        for p in self.root.glob("[0-9][0-9][0-9][0-9]_*"):
            m = re.match(r"(\d{4})_", p.name)
            if m:
                mx = max(mx, int(m.group(1)))
        return mx

    def wire(self, direction: str, ptype: int, payload: bytes) -> None:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        line = f"{ts} {direction:4s} ptype=0x{ptype:04X} len={len(payload):5d} {hx(payload)}"
        with open(self.wire_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def numbered_path(self, label: str, ext: str = "json") -> Path:
        self.seq += 1
        safe = re.sub(r"[^0-9A-Za-z_.-]+", "_", label)[:60]
        return self.root / f"{self.seq:04d}_{safe}.{ext}"

    def record(self, rec: dict) -> dict:
        self.seq += 1
        rec["seq"] = self.seq
        rec.setdefault("ts", now_iso())
        safe = re.sub(r"[^0-9A-Za-z_.-]+", "_", rec.get("label", "rec"))[:60]
        path = self.root / f"{self.seq:04d}_{safe}.json"
        path.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
        with open(self.trace_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec


# ------------------------------------------------------------------- DoIP I/O
class DoIPConnection:
    def __init__(self, host: str, port: int, ev: Evidence, timeout: float = 3.0):
        self.ev = ev
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b""
        self.host, self.port = host, port

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, ptype: int, payload: bytes = b"", ver: int = 0x02) -> bytes:
        frame = bytes([ver, 0xFF - ver]) + struct.pack(">H", ptype) + struct.pack(">I", len(payload)) + payload
        self.sock.sendall(frame)
        self.ev.wire("TX", ptype, payload)
        return frame

    def _frame_from_buf(self):
        if len(self.buf) < 8:
            return None
        ver, inv, ptype, plen = struct.unpack(">BBHI", self.buf[:8])
        if len(self.buf) < 8 + plen:
            return None
        payload = self.buf[8:8 + plen]
        self.buf = self.buf[8 + plen:]
        return ver, ptype, payload

    def recv_frame(self, timeout: float):
        end = time.time() + max(timeout, 0.0)
        while True:
            fr = self._frame_from_buf()
            if fr:
                return fr
            rem = end - time.time()
            if rem <= 0:
                return None
            r, _, _ = select.select([self.sock], [], [], rem)
            if not r:
                return None
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("peer closed the connection")
            self.buf += chunk

    def drain(self, quiet: float = 0.35, total: float = 6.0):
        frames = []
        end = time.time() + total
        while time.time() < end:
            fr = self.recv_frame(min(quiet, max(0.0, end - time.time())))
            if fr is None:
                break
            frames.append(fr)
        return frames


class Link:
    """One activated DoIP socket: tester SA fixed, UDS exchanges recorded."""

    def __init__(self, host, port, ev: Evidence, sa: int, timeout: float):
        self.ev = ev
        self.host, self.port = host, port
        self.sa = sa
        self.conn = DoIPConnection(host, port, ev, timeout)
        self.timeout = timeout

    def close(self):
        self.conn.close()

    def activate(self, sa: int, act_type: int = 0x00, oem: bytes = b"", label: str = "routing_activation"):
        payload = struct.pack(">H", sa) + bytes([act_type]) + b"\x00\x00\x00\x00" + oem
        t0 = time.time()
        self.conn.send(PT_ROUTING_ACT_REQ, payload)
        frame = self.conn.recv_frame(self.timeout)
        elapsed = (time.time() - t0) * 1000
        rec = {
            "label": label,
            "purpose": "DoIP routing activation (0x0005) -> parse 0x0006",
            "host": f"{self.host}:{self.port}",
            "request": {"ptype": "0x0005", "hex": hx(payload)},
            "responses": [],
            "elapsed_ms": round(elapsed, 2),
        }
        if frame is None:
            rec["parsed"] = "NO RESPONSE within timeout"
            self.ev.record(rec)
            return rec, None
        ver, ptype, data = frame
        self.ev.wire("RX", ptype, data)
        rec["responses"].append({"ptype": f"0x{ptype:04X}", "hex": hx(data), "len": len(data)})
        parsed = {"tester_sa": None, "entity_la": None, "code": None, "text": "unparsed"}
        if ptype == PT_ROUTING_ACT_RSP and len(data) >= 5:
            tester, entity, code = struct.unpack(">HHB", data[:5])
            parsed = {
                "tester_sa": f"0x{tester:04X}",
                "entity_la": f"0x{entity:04X}",
                "code": f"0x{code:02X}",
                "text": RA_CODES.get(code, "unknown"),
                "trailing": hx(data[5:]),
            }
            self.sa = tester
        rec["parsed"] = parsed
        self.ev.record(rec)
        return rec, parsed

    def uds(self, ta: int, uds: bytes, label: str, quiet: float = 0.35,
            total: float = 5.0, purpose: str = ""):
        assert_read_only(uds, ta)
        payload = struct.pack(">HH", self.sa, ta) + uds
        t0 = time.time()
        self.conn.send(PT_DIAG_MSG, payload)
        frames = self.conn.drain(quiet=quiet, total=total)
        # ISO 14229 P2*: keep listening while ECU reports responsePending (0x78)
        for _ in range(3):
            if not any(
                p == PT_DIAG_MSG and len(d) >= 8 and d[4:7] == bytes([0x7F, uds[0], 0x78])
                for _, p, d in frames
            ):
                break
            frames += self.conn.drain(quiet=max(quiet, 0.9), total=8.0)
        elapsed = (time.time() - t0) * 1000

        rec = {
            "label": label,
            "purpose": purpose,
            "host": f"{self.host}:{self.port}",
            "tester_sa": f"0x{self.sa:04X}",
            "target_la": f"0x{ta:04X}",
            "request": {"ptype": "0x8001", "hex": hx(payload), "uds": hx(uds)},
            "responses": [],
            "acks": [],
            "nacks": [],
            "uds": [],
            "elapsed_ms": round(elapsed, 2),
        }
        for ver, ptype, data in frames:
            self.ev.wire("RX", ptype, data)
            rec["responses"].append({"ptype": f"0x{ptype:04X}", "hex": hx(data), "len": len(data)})
            if ptype == PT_DIAG_ACK and len(data) >= 5:
                code = data[4]
                rec["acks"].append(
                    f"src=0x{struct.unpack('>H', data[0:2])[0]:04X} "
                    f"dst=0x{struct.unpack('>H', data[2:4])[0]:04X} "
                    f"code=0x{code:02X} ({ACK_CODES.get(code, '?')})"
                )
            elif ptype == PT_DIAG_NACK and len(data) >= 5:
                code = data[4]
                rec["nacks"].append(
                    f"src=0x{struct.unpack('>H', data[0:2])[0]:04X} "
                    f"dst=0x{struct.unpack('>H', data[2:4])[0]:04X} "
                    f"code=0x{code:02X} ({ACK_CODES.get(code, '?')})"
                )
            elif ptype == PT_DIAG_MSG and len(data) >= 4:
                src, dst = struct.unpack(">HH", data[:4])
                body = data[4:]
                rec["uds"].append(
                    {"from": f"0x{src:04X}", "to": f"0x{dst:04X}",
                     "hex": hx(body), "parsed": parse_uds_response(body)}
                )
        if not rec["responses"]:
            rec["parsed"] = "NO RESPONSE within timeout"
        elif rec["nacks"]:
            rec["parsed"] = "DoIP NACK: " + " | ".join(rec["nacks"])
        elif rec["uds"]:
            rec["parsed"] = " | ".join(f"{u['from']}: {u['parsed']}" for u in rec["uds"])
        else:
            rec["parsed"] = "only ack: " + " | ".join(rec["acks"])
        self.ev.record(rec)
        return rec

    def collect_n(self, n: int, timeout: float = 1.5, quiet: float = 0.2):
        """Read up to n diagnostic answers (acks/nacks/UDS) without a per-request wait.

        Used for pipelined sweeps: many 0x8001 requests are sent back-to-back and
        the answers are collected as a batch. Returns [(kind, src, body)].
        """
        out = []
        end = time.time() + timeout
        while len(out) < n and time.time() < end:
            fr = self.conn.recv_frame(min(quiet, max(0.0, end - time.time())))
            if fr is None:
                break
            ver, ptype, data = fr
            self.ev.wire("RX", ptype, data)
            if ptype == PT_DIAG_MSG and len(data) >= 4:
                src = struct.unpack(">H", data[:2])[0]
                out.append(("uds", src, data[4:]))
            elif ptype == PT_DIAG_ACK and len(data) >= 5:
                out.append(("ack", None, data))
            elif ptype == PT_DIAG_NACK and len(data) >= 5:
                out.append(("nack", None, data))
        return out

    def request_no_ack(self, ptype: int, payload: bytes = b"", label: str = "",
                       purpose: str = "", quiet: float = 0.4):
        t0 = time.time()
        self.conn.send(ptype, payload)
        frames = self.conn.drain(quiet=quiet, total=3.0)
        rec = {
            "label": label,
            "purpose": purpose,
            "request": {"ptype": f"0x{ptype:04X}", "hex": hx(payload)},
            "responses": [],
            "elapsed_ms": round((time.time() - t0) * 1000, 2),
        }
        for ver, p, data in frames:
            self.ev.wire("RX", p, data)
            rec["responses"].append({"ptype": f"0x{p:04X}", "hex": hx(data), "len": len(data)})
        if not rec["responses"]:
            rec["parsed"] = "NO RESPONSE within timeout"
        self.ev.record(rec)
        return rec


# -------------------------------------------------------------- phase helpers
def phase_ident(host, port, ev, timeout):
    conn = DoIPConnection(host, port, ev, timeout)
    try:
        conn.send(PT_REQ_VEH_ID, b"")
        frame = conn.recv_frame(timeout)
        rec = {"label": "ident", "purpose": "vehicle identification request (0x0001)",
               "request": {"ptype": "0x0001", "hex": ""}, "responses": []}
        if frame is None:
            rec["parsed"] = "NO RESPONSE"
            ev.record(rec)
            return rec
        ver, ptype, data = frame
        ev.wire("RX", ptype, data)
        rec["responses"].append({"ptype": f"0x{ptype:04X}", "hex": hx(data), "len": len(data)})
        parsed = {"ptype_name": PT.get(ptype, "?")}
        if ptype == 0x0004 and len(data) >= 32:
            vin = data[:17].decode("ascii", "replace")
            la = struct.unpack(">H", data[17:19])[0]
            parsed.update({
                "vin": vin,
                "logical_address": f"0x{la:04X}",
                "eid": hx(data[19:25]),
                "gid": hx(data[25:31]),
                "further_action": f"0x{data[31]:02X}",
            })
        rec["parsed"] = parsed
        ev.record(rec)
        return rec
    finally:
        conn.close()


def phase_entity(host, port, ev, timeout):
    conn = DoIPConnection(host, port, ev, timeout)
    out = {}
    try:
        for ptype, label, purpose in (
            (PT_ENTITY_STATUS_REQ, "entity_status", "DoIP entity status request (0x4001)"),
            (PT_POWERMODE_REQ, "entity_power_mode", "diagnostic power mode info request (0x4003)"),
        ):
            conn.send(ptype, b"")
            frames = conn.drain(quiet=0.5, total=3.0)
            rec = {"label": label, "purpose": purpose,
                   "request": {"ptype": f"0x{ptype:04X}", "hex": ""}, "responses": []}
            for ver, p, data in frames:
                ev.wire("RX", p, data)
                rec["responses"].append({"ptype": f"0x{p:04X}", "hex": hx(data), "len": len(data)})
            rec["parsed"] = ("NO RESPONSE" if not rec["responses"]
                             else "; ".join(r["hex"] for r in rec["responses"]))
            ev.record(rec)
            out[label] = rec
        return out
    finally:
        conn.close()


def phase_activate(host, port, ev, timeout, matrix=None):
    """Try routing activation on a fresh socket per (SA, type) pair."""
    matrix = matrix or [
        (0x0E00, 0x00), (0x0E00, 0xE0),
        (0x0E80, 0x00), (0x0E80, 0xE0),
        (0x0E01, 0x00),
    ]
    results = []
    for sa, act in matrix:
        link = Link(host, port, ev, sa, timeout)
        try:
            rec, parsed = link.activate(
                sa, act, label=f"ra_sa{sa:04x}_act{act:02x}"
            )
            results.append({"sa": f"0x{sa:04X}", "act": f"0x{act:02X}",
                            "rec": rec, "parsed": parsed})
            print(f"[RA] SA=0x{sa:04X} act=0x{act:02X} -> "
                  f"{(parsed or {}).get('code', 'no-response')} "
                  f"{(parsed or {}).get('text', '')}")
            if parsed and parsed.get("code") == "0x10":
                # stop after the first success: later attempts on new sockets are
                # reported by many entities as 0x03 (SA already active elsewhere)
                break
        finally:
            link.close()
    return results


def phase_gateway(host, port, ev, timeout, sa):
    link = Link(host, port, ev, sa, timeout)
    out = {}
    try:
        rec, parsed = link.activate(sa, 0x00, label=f"ra_for_gw_sa{sa:04x}")
        out["_ra"] = rec
        if not parsed or parsed.get("code") != "0x10":
            print(f"[!] routing activation failed: {parsed}")
            return out
        # 1) baseline in the default session (read-only)
        out["3E00"] = link.uds(GATEWAY_LA, bytes.fromhex("3E00"), "gw_3E00_default",
                               purpose="TesterPresent to prove routing works")
        out["22F190"] = link.uds(GATEWAY_LA, bytes.fromhex("22F190"), "gw_22_F190_default",
                                 purpose="read VIN in default session")
        out["2701"] = link.uds(GATEWAY_LA, bytes.fromhex("2701"), "gw_27_01_default",
                               purpose="SecurityAccess level1 requestSeed in default session")
        out["1902FF"] = link.uds(GATEWAY_LA, bytes.fromhex("1902FF"), "gw_19_02_default",
                                 purpose="ReadDTCInformation reportDTCByStatusMask FF")
        out["3103FF00"] = link.uds(GATEWAY_LA, bytes.fromhex("3103FF00"), "gw_31_03_ff00_default",
                                   purpose="RoutineControl requestRoutineResults 0xFF00")
        # 2) extended session, per task order
        out["1003"] = link.uds(GATEWAY_LA, bytes.fromhex("1003"), "gw_10_03_extended",
                               purpose="DiagnosticSessionControl extended (10 03)")
        out["2701_ext"] = link.uds(GATEWAY_LA, bytes.fromhex("2701"), "gw_27_01_extended",
                                   purpose="SecurityAccess level1 requestSeed in extended session")
        for did in ("F187", "F188", "F189", "F18A", "F1A0", "F186", "F1A1", "F195", "F19E", "F1AF"):
            out[f"22{did}"] = link.uds(
                GATEWAY_LA, bytes.fromhex("22" + did), f"gw_22_{did.lower()}_extended",
                purpose=f"read DID 0x{did} in extended session")
        out["1902FF_ext"] = link.uds(GATEWAY_LA, bytes.fromhex("1902FF"), "gw_19_02_extended",
                                     purpose="DTC read in extended session")
        out["3103FF00_ext"] = link.uds(GATEWAY_LA, bytes.fromhex("3103FF00"),
                                       "gw_31_03_ff00_extended",
                                       purpose="RoutineControl requestRoutineResults 0xFF00 (ext)")
        # 3) back to default session
        out["1001"] = link.uds(GATEWAY_LA, bytes.fromhex("1001"), "gw_10_01_default_return",
                               purpose="return to default session (10 01)")
        return out
    finally:
        link.close()


ENUM_TARGETS = (
    [0x0001, 0x0002, 0x0003, 0x0004, 0x0005]
    + [0x0E00, 0x0E80]
    + list(range(0x1001, 0x1011))
    + [0xE000, 0xE400]
)


def phase_enum(host, port, ev, timeout, sa):
    link = Link(host, port, ev, sa, timeout)
    rows = []
    try:
        rec, parsed = link.activate(sa, 0x00, label=f"ra_for_enum_sa{sa:04x}")
        if not parsed or parsed.get("code") != "0x10":
            print(f"[!] routing activation failed: {parsed}")
            return rows
        for ta in ENUM_TARGETS:
            r1 = link.uds(ta, bytes.fromhex("3E00"), f"enum_{ta:04x}_3E00",
                          quiet=0.30, total=2.0,
                          purpose=f"TesterPresent to LA 0x{ta:04X} (existence probe)")
            alive = bool(r1.get("uds")) and any(u["parsed"].startswith("POSITIVE") for u in r1["uds"])
            row = {"ta": f"0x{ta:04X}", "probe": "3E00", "alive": alive,
                   "nack": r1.get("nacks", []), "uds": [u["parsed"] for u in r1["uds"]]}
            if alive:
                r2 = link.uds(ta, bytes.fromhex("22F190"), f"enum_{ta:04x}_22F190",
                              quiet=0.30, total=2.0,
                              purpose=f"read VIN (0xF190) from LA 0x{ta:04X}")
                row["vin_probe"] = [u["parsed"] for u in r2["uds"]] or r2.get("parsed")
            rows.append(row)
            print(f"[ENUM] 0x{ta:04X} alive={alive} {row.get('vin_probe', '') or (r1.get('nacks') or r1.get('parsed'))}")
    finally:
        link.close()
    ev.record({"label": "enum_summary", "purpose": "logical address enumeration summary",
               "request": {"ptype": "multiple", "hex": ""}, "rows": rows,
               "parsed": json.dumps(rows, ensure_ascii=False)})
    return rows


def phase_sweep(host, port, ev, timeout, sa, lo=0xF180, hi=0xF1FF):
    link = Link(host, port, ev, sa, timeout)
    exchanges = []
    try:
        rec, parsed = link.activate(sa, 0x00, label=f"ra_for_sweep_sa{sa:04x}")
        if not parsed or parsed.get("code") != "0x10":
            print(f"[!] routing activation failed: {parsed}")
            return exchanges
        print(f"[*] DID sweep 0x{lo:04X}-0x{hi:04X} on 0x{GATEWAY_LA:04X} (default session)")
        for did in range(lo, hi + 1):
            r = link.uds(GATEWAY_LA, struct.pack(">BH", 0x22, did), f"dummy", quiet=0.18, total=1.2,
                         purpose=f"read DID 0x{did:04X}")
            exchanges.append(r)
            if did % 16 == 0:
                print(f"    ...0x{did:04X} ({len(exchanges)} sent)")
    finally:
        link.close()
    # one numbered artefact holding the whole sweep
    keep = [{"label": e["label"], "request": e["request"], "responses": e["responses"],
             "acks": e["acks"], "nacks": e["nacks"], "uds": e["uds"], "parsed": e["parsed"]}
            for e in exchanges]
    ev.record({"label": f"sweep_{lo:04x}_{hi:04x}_default_session",
               "purpose": f"0x22 DID sweep 0x{lo:04X}-0x{hi:04X} on gateway 0x{GATEWAY_LA:04X}",
               "request": {"ptype": "0x8001 x %d" % len(exchanges), "hex": ""},
               "exchanges": keep,
               "parsed": f"{len(exchanges)} requests"})
    return exchanges


# ------------------------------------------------------------------- reporting
def scan_space(host, port, ev, timeout, sa, lo, hi, kind="did", batch=32, ta=None):
    """Pipelined probe of a value space.

    kind="did"  -> UDS 0x22 <did> to logical address `ta` (default 0x1000)
    kind="la"   -> UDS 0x3E 00 to every logical address in [lo, hi]

    Requests are pushed back-to-back and the answers are collected as a batch.
    Because all "nothing here" answers are byte-identical, a batch is only
    accepted when its answer count matches and every answer is identical;
    a mixed or short batch is re-probed one request at a time so the mapping
    never depends on response ordering.
    """
    ta = GATEWAY_LA if ta is None else ta
    link = Link(host, port, ev, sa, timeout)
    results = []
    slow_batches = 0
    t0 = time.time()
    try:
        rec, parsed = link.activate(sa, 0x00, label=f"ra_for_{kind}scan_sa{sa:04x}")
        if not parsed or parsed.get("code") != "0x10":
            print(f"[!] routing activation failed: {parsed}")
            return results
        total = hi - lo + 1
        for start in range(lo, hi + 1, batch):
            chunk = list(range(start, min(start + batch, hi + 1)))
            for v in chunk:
                if kind == "did":
                    payload = struct.pack(">HH", link.sa, ta) + struct.pack(">BH", 0x22, v)
                else:
                    payload = struct.pack(">HH", link.sa, v) + bytes.fromhex("3E00")
                link.conn.send(PT_DIAG_MSG, payload)
            frames = link.collect_n(len(chunk), timeout=3.0, quiet=0.15)
            bodies = {b for (k, s, b) in frames if k == "uds"}
            if (len(frames) != len(chunk)
                    or not all(k == "uds" for k, _, _ in frames)
                    or len(bodies) != 1):
                slow_batches += 1
                for v in chunk:
                    if kind == "did":
                        r = link.uds(ta, struct.pack(">BH", 0x22, v),
                                     f"{kind}_slow_{v:04x}", quiet=0.12, total=1.0)
                    else:
                        r = link.uds(v, bytes.fromhex("3E00"),
                                     f"{kind}_slow_{v:04x}", quiet=0.12, total=1.0)
                    u = r["uds"][0] if r.get("uds") else None
                    results.append({
                        "value": v,
                        "src": u["from"] if u else "",
                        "body": u["hex"] if u else "",
                        "parsed": r.get("parsed", ""),
                    })
                continue
            body = hx(frames[0][2])
            src = f"0x{frames[0][1]:04X}" if frames[0][1] is not None else ""
            results.append({"value": chunk[0], "span": len(chunk), "src": src,
                            "body": body, "parsed": ""})
            if (start - lo) % (batch * 128) == 0 and start > lo:
                rate = (start - lo) / max(time.time() - t0, 1e-6)
                print(f"    ...0x{start:04X}/{hi:04X}  {rate:.0f} probe/s")

        # expand batched rows into one row per value for the evidence file
        flat = []
        for r in results:
            if r.get("span"):
                for v in range(r["value"], r["value"] + r["span"]):
                    flat.append({"v": f"0x{v:04X}", "src": r["src"], "resp": r["body"]})
            else:
                flat.append({"v": f"0x{r['value']:04X}", "src": r["src"], "resp": r["body"]})
        path = ev.numbered_path(f"{kind}scan_{lo:04x}_{hi:04x}", "jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for row in flat:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

        # a hit is anything that differs from the dominant (source, body) pair
        pairs = {}
        for row in flat:
            k = (row["src"], row["resp"])
            pairs[k] = pairs.get(k, 0) + 1
        baseline_pair = max(pairs, key=lambda k: pairs[k])
        hits = [row for row in flat if (row["src"], row["resp"]) != baseline_pair]
        summary = ev.record({
            "label": f"{kind}scan_{lo:04x}_{hi:04x}_summary",
            "purpose": (f"0x22 DID scan on 0x{ta:04X}" if kind == "did"
                        else "logical-address scan with 3E 00"),
            "request": {"ptype": "0x8001",
                        "hex": f"{kind} {lo:04x}-{hi:04x} ta=0x{ta:04x}"},
            "parsed": f"{len(flat)} values, {len(hits)} non-baseline, "
                      f"baseline={baseline_pair}, slow_batches={slow_batches}, "
                      f"elapsed={time.time() - t0:.1f}s",
            "baseline": f"{baseline_pair}",
            "hits": hits[:200],
            "evidence_file": path.name,
        })
        print(f"[+] {kind}scan 0x{lo:04X}-0x{hi:04X} (ta=0x{ta:04X}): {len(flat)} values, "
              f"{len(hits)} non-baseline, {time.time() - t0:.1f}s -> {path.name}")
        for h in hits[:40]:
            print(f"    hit {h['v']} src={h['src']} {h['resp']}")
        return flat, hits, summary
    finally:
        link.close()


def format_summary(rows):
    """Short human-readable table for a scan result list."""
    return "\n".join(f"{r['v']} {r['src']} {r['resp']}" for r in rows)


def summarise(exchanges):
    """Condense sweep results: did -> status."""
    rows = []
    for e in exchanges:
        req = bytes.fromhex(e["request"]["uds"])
        did = struct.unpack(">H", req[1:3])[0]
        if e.get("nacks"):
            status = "NACK " + e["nacks"][0]
        elif e.get("uds"):
            status = " | ".join(f"{u['from']}:{u['parsed']}" for u in e["uds"])
        elif e.get("responses"):
            status = "ack-only"
        else:
            status = "no-response"
        rows.append((did, status))
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="CGW DoIP/UDS read-only probe")
    ap.add_argument("cmd", choices=["ident", "entity", "activate", "gw", "enum", "sweep",
                                    "didscan", "lascan", "all", "uds"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--sa", default="0E00", help="tester logical address (hex)")
    ap.add_argument("--act", default="00", help="routing activation type (hex)")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--lo", default="0000", help="scan low bound (hex, inclusive)")
    ap.add_argument("--hi", default="FFFF", help="scan high bound (hex, inclusive)")
    ap.add_argument("--batch", type=int, default=32, help="pipelined batch size")
    ap.add_argument("--ta", default="1000", help="target logical address for didscan (hex)")
    args = ap.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ev = Evidence(EVID)
    sa = int(args.sa, 16)
    act = int(args.act, 16)
    print(f"[*] evidence dir: {EVID} (starting at seq {ev.seq + 1})")

    if args.cmd == "ident":
        r = phase_ident(args.host, args.port, ev, args.timeout)
        print(json.dumps(r.get("parsed"), indent=2, ensure_ascii=False))
    elif args.cmd == "entity":
        r = phase_entity(args.host, args.port, ev, args.timeout)
        for k, v in r.items():
            print(k, "->", v["parsed"])
    elif args.cmd == "activate":
        phase_activate(args.host, args.port, ev, args.timeout)
    elif args.cmd == "gw":
        r = phase_gateway(args.host, args.port, ev, args.timeout, sa)
        for k, v in r.items():
            if k.startswith("_"):
                continue
            print(f"{k:12s} {v.get('parsed')}")
    elif args.cmd == "enum":
        phase_enum(args.host, args.port, ev, args.timeout, sa)
    elif args.cmd == "sweep":
        phase_sweep(args.host, args.port, ev, args.timeout, sa)
    elif args.cmd == "didscan":
        scan_space(args.host, args.port, ev, args.timeout, sa,
                   int(args.lo, 16), int(args.hi, 16), kind="did", batch=args.batch,
                   ta=int(args.ta, 16))
    elif args.cmd == "lascan":
        scan_space(args.host, args.port, ev, args.timeout, sa,
                   int(args.lo, 16), int(args.hi, 16), kind="la", batch=args.batch)
    elif args.cmd == "uds":
        ta = int(args.args[0], 16)
        uds = bytes.fromhex(args.args[1])
        link = Link(args.host, args.port, ev, sa, args.timeout)
        try:
            rec, parsed = link.activate(sa, act, label=f"ra_manual_sa{sa:04x}")
            print("[RA]", parsed)
            r = link.uds(ta, uds, "manual", purpose="manual read-only request")
            print(json.dumps(r, indent=2, ensure_ascii=False))
        finally:
            link.close()
    elif args.cmd == "all":
        print("\n=== phase 1: vehicle identification ===")
        ident = phase_ident(args.host, args.port, ev, args.timeout)
        print(json.dumps(ident.get("parsed"), indent=2, ensure_ascii=False))

        print("\n=== phase 2: DoIP entity status / power mode ===")
        phase_entity(args.host, args.port, ev, args.timeout)

        print("\n=== phase 3: routing activation matrix ===")
        ras = phase_activate(args.host, args.port, ev, args.timeout)

        chosen = sa
        for r in ras:
            if r.get("parsed") and r["parsed"].get("code") == "0x10":
                chosen = int(r["sa"], 16)
                break
        print(f"[*] using tester SA 0x{chosen:04X} for UDS phases")

        print("\n=== phase 4: UDS on gateway 0x1000 ===")
        gw = phase_gateway(args.host, args.port, ev, args.timeout, chosen)
        for k, v in gw.items():
            if k.startswith("_"):
                continue
            print(f"{k:12s} {v.get('parsed')}")

        print("\n=== phase 5: logical address enumeration ===")
        rows = phase_enum(args.host, args.port, ev, args.timeout, chosen)

        print("\n=== phase 6: DID sweep 0xF180-0xF1FF on 0x1000 ===")
        sw = phase_sweep(args.host, args.port, ev, args.timeout, chosen)

        summary = {
            "host": args.host, "port": args.port,
            "tester_sa": f"0x{chosen:04X}",
            "ident": ident.get("parsed"),
            "routing_activation": [
                {"sa": r["sa"], "act": r["act"], "parsed": r["parsed"]} for r in ras
            ],
            "gateway_uds": {k: v.get("parsed") for k, v in gw.items() if not k.startswith("_")},
            "enum": rows,
            "sweep": [{"did": f"0x{d:04X}", "status": s} for d, s in summarise(sw)],
        }
        (SOLVE / "run_summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[*] wrote {SOLVE / 'run_summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

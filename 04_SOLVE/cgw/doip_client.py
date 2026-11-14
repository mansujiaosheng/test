#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DoIP (ISO 13400-2) + UDS (ISO 14229-1) client for CyberCar T03 central gateway.

Targets: 10.229.221.2:13400  (== 10.230.164.4:13400)

Design notes
------------
* DoIP frame = generic header (8B) + payload:
      [0] proto version (0x02), [1] inverse (~ver), [2:4] payload type BE,
      [4:8] payload length BE, then payload.
* Flow used for UDS:
      connect -> optional 0x0005 routing activation -> 0x8001 diagnostic message
      <- optional 0x8002 diag ack  / 0x8003 diag nack
      <- 0x8001 diagnostic message (SA/TA + UDS response)
* UDS over DoIP is NOT ISO-TP segmented: the whole UDS message rides in one
  0x8001 payload.  Long *responses* are reassembled by reading 0x8001 frames
  from the same SA until an idle gap; UDS pending (7F xx 78) is handled by
  waiting for the following final response.
* All socket reads are deadline driven; we always drain multiple frames so a
  0x8002 ack that precedes the real response never desynchronises parsing.

CLI examples
------------
  python doip_client.py ident
  python doip_client.py ra --sa 0E00
  python doip_client.py uds --sa 0E00 --ta 1000 --uds 22F190
  python doip_client.py uds --ta 1000 --uds 22F190 --no-activate
  python doip_client.py sweep-ta --probe 3E00 --ranges 0000-00FF,07E0-07E7
  python doip_client.py raw --ptype 0004 --payload ''
  python doip_client.py compare --hosts 10.229.221.2,10.230.164.4
"""
from __future__ import annotations

import argparse
import binascii
import json
import os
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

DEFAULT_HOST = "10.229.221.2"
ALT_HOST = "10.230.164.4"
DEFAULT_PORT = 13400
DEFAULT_SA = 0x0E00
DEFAULT_TA = 0x1000

# ---------------------------------------------------------------- payload types
PT_GENERIC_NACK = 0x0000
PT_VEHICLE_ID_REQ = 0x0001
PT_VEHICLE_ID_REQ_EID = 0x0002
PT_VEHICLE_ID_REQ_VIN = 0x0003
PT_VEHICLE_ANNOUNCE = 0x0004
PT_ROUTING_ACT_REQ = 0x0005
PT_ROUTING_ACT_RESP = 0x0006
PT_ALIVE_CHECK_REQ = 0x0007
PT_ALIVE_CHECK_RESP = 0x0008
PT_ENTITY_STATUS_REQ = 0x4001
PT_ENTITY_STATUS_RESP = 0x4002
PT_ENTITY_STATUS_RESP2 = 0x4003
PT_DIAG_POWER_MODE_REQ = 0x4004
PT_DIAG_POWER_MODE_RESP = 0x4005
PT_DIAG_MSG = 0x8001
PT_DIAG_ACK = 0x8002
PT_DIAG_NACK = 0x8003

NRC_NAMES = {
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
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "requestCorrectlyReceived-ResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}

SID_NAMES = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x24: "ReadScalingDataByIdentifier",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x29: "Authentication",
    0x2A: "ReadDataByPeriodicIdentifier",
    0x2C: "DynamicallyDefineDataIdentifier",
    0x2E: "WriteDataByIdentifier",
    0x2F: "InputOutputControlByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x35: "RequestUpload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x38: "RequestFileTransfer",
    0x3D: "WriteMemoryByAddress",
    0x3E: "TesterPresent",
    0x83: "AccessTimingParameter",
    0x84: "SecuredDataTransmission",
    0x85: "ControlDTCSetting",
    0x86: "ResponseOnEvent",
    0x87: "LinkControl",
    0xBA: "OEM-BA",
}

RA_CODES = {
    0x00: "routing successfully activated",
    0x01: "unknown source address",
    0x02: "all sockets registered/active",
    0x03: "source address already active in different socket",
    0x04: "missing authentication",
    0x05: "rejected confirmation",
    0x06: "unsupported routing activation type",
    0x10: "routing successfully activated",
    0x11: "routing activation required confirmation",
}


# --------------------------------------------------------------------- helpers
def hexs(b: bytes) -> str:
    return binascii.hexlify(b).decode().upper()


def parse_hex(s: str) -> bytes:
    s = (s or "").strip().replace("0x", "").replace(" ", "").replace(":", "").replace("-", "")
    if not s:
        return b""
    if len(s) % 2:
        s = "0" + s
    return binascii.unhexlify(s)


def u16(v: int) -> bytes:
    return struct.pack(">H", v & 0xFFFF)


def uds_explain(blob: bytes) -> str:
    """Human readable one-liner for a UDS response."""
    if not blob:
        return "<empty>"
    if blob[0] == 0x7F and len(blob) >= 3:
        sid, nrc = blob[1], blob[2]
        return "NEGATIVE sid=0x%02X(%s) NRC=0x%02X (%s)" % (
            sid, SID_NAMES.get(sid, "?"), nrc, NRC_NAMES.get(nrc, "?"))
    sid = blob[0]
    base = sid - 0x40 if sid >= 0x40 else sid
    if base == 0x22 and len(blob) >= 3:
        # may carry several DIDs
        out, i = [], 1
        while i + 2 <= len(blob):
            did = struct.unpack(">H", blob[i:i + 2])[0]
            j = i + 2
            # take everything up to the next DID we cannot delimit -> show rest
            out.append("DID=0x%04X data=%s" % (did, hexs(blob[j:])))
            break
        return "POSITIVE 0x22 ReadDataByIdentifier " + "; ".join(out)
    return "POSITIVE sid=0x%02X(%s) data=%s" % (
        sid, SID_NAMES.get(base, "?"), hexs(blob[1:]))


@dataclass
class Frame:
    ptype: int
    payload: bytes
    ver: int = 0x02
    t: float = 0.0

    def as_dict(self) -> dict:
        d = {"ptype": "0x%04X" % self.ptype, "hex": hexs(self.payload),
             "len": len(self.payload)}
        if self.ptype == PT_DIAG_MSG and len(self.payload) >= 4:
            sa = struct.unpack(">H", self.payload[0:2])[0]
            ta = struct.unpack(">H", self.payload[2:4])[0]
            uds = self.payload[4:]
            d["sa"] = "0x%04X" % sa
            d["ta"] = "0x%04X" % ta
            d["uds"] = hexs(uds)
            d["uds_text"] = uds_explain(uds)
        return d


# ---------------------------------------------------------------------- client
class DoIPClient:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 timeout: float = 1.5, verbose: bool = True, log_path: Optional[str] = None):
        self.host, self.port = host, port
        self.timeout = timeout
        self.verbose = verbose
        self.log_path = log_path
        self.sock: Optional[socket.socket] = None
        self.activated_sa: Optional[int] = None
        self.last_latency_ms: Optional[float] = None

    # -- plumbing ---------------------------------------------------------
    def connect(self, attempts: int = 3, connect_timeout: float = 6.0) -> "DoIPClient":
        # The 10.229.221.2 side of the gateway sits behind a slow first hop
        # (~1.0 s on a cold ARP entry) while 10.230.164.4 answers in ~30 ms,
        # so connect gets its own, more generous budget + retries.
        last: Optional[Exception] = None
        for i in range(attempts):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(connect_timeout)
            t0 = time.time()
            try:
                s.connect((self.host, self.port))
            except OSError as e:
                last = e
                s.close()
                self._log("CONNECT %s:%d attempt %d failed: %s (%.0fms)"
                          % (self.host, self.port, i + 1, e, (time.time() - t0) * 1000))
                time.sleep(0.4)
                continue
            self.sock = s
            # switch to the request/response timeout for everything after connect
            s.settimeout(self.timeout)
            self._log("CONNECT %s:%d ok in %.1fms"
                      % (self.host, self.port, (time.time() - t0) * 1000))
            return self
        raise last if last else RuntimeError("connect failed")

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")

    @staticmethod
    def build(ptype: int, payload: bytes = b"", ver: int = 0x02) -> bytes:
        return bytes([ver & 0xFF, (~ver) & 0xFF]) + struct.pack(">HI", ptype, len(payload)) + payload

    def _recv_exact(self, n: int, deadline: float) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            remain = deadline - time.time()
            if remain <= 0:
                return None
            self.sock.settimeout(min(remain, 0.5))
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                continue
            except OSError as e:
                self._log("  ! socket error: %s" % e)
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def read_frames(self, duration: Optional[float] = None,
                    idle_gap: Optional[float] = None) -> List[Frame]:
        """Read frames until `duration` elapses or an idle gap with no data."""
        duration = self.timeout if duration is None else duration
        idle_gap = idle_gap if idle_gap is not None else min(0.35, max(0.12, self.timeout / 3))
        deadline = time.time() + duration
        frames: List[Frame] = []
        last = time.time()
        while time.time() < deadline:
            remain = deadline - time.time()
            if frames and (time.time() - last) > idle_gap:
                break
            self.sock.settimeout(max(0.02, min(remain, idle_gap)))
            try:
                hdr = self.sock.recv(8)
            except socket.timeout:
                if frames:
                    break
                continue
            except OSError:
                break
            if not hdr:
                break
            while len(hdr) < 8:
                more = self._recv_exact(8 - len(hdr), deadline)
                if not more:
                    break
                hdr += more
            if len(hdr) < 8:
                break
            ver, inv, ptype, plen = struct.unpack(">BBHI", hdr)
            payload = self._recv_exact(plen, deadline) if plen else b""
            if payload is None:
                payload = b""
            frames.append(Frame(ptype=ptype, payload=payload, ver=ver, t=time.time()))
            last = time.time()
            # keep reading briefly after each frame to catch multi-frame answers
            deadline = max(deadline, time.time() + idle_gap)
        return frames

    def send(self, ptype: int, payload: bytes = b"", ver: int = 0x02) -> bytes:
        raw = self.build(ptype, payload, ver)
        self._log("  >> %s" % hexs(raw))
        self.sock.sendall(raw)
        return raw

    def transact(self, ptype: int, payload: bytes = b"", duration: Optional[float] = None,
                 ver: int = 0x02) -> List[Frame]:
        t0 = time.time()
        self.send(ptype, payload, ver)
        frames = self.read_frames(duration)
        self.last_latency_ms = (time.time() - t0) * 1000
        for f in frames:
            self._log("  << %s" % json.dumps(f.as_dict(), ensure_ascii=False))
        if not frames:
            self._log("  << <no response, %.0fms>" % self.last_latency_ms)
        return frames

    # -- protocol verbs ---------------------------------------------------
    def vehicle_identification(self) -> List[Frame]:
        return self.transact(PT_VEHICLE_ID_REQ, b"")

    def routing_activation(self, sa: int = DEFAULT_SA, act_type: int = 0x00,
                           oem: bytes = b"", reserved: bytes = b"\x00\x00\x00\x00",
                           timeout: Optional[float] = None) -> Tuple[Optional[dict], List[Frame]]:
        payload = u16(sa) + bytes([act_type & 0xFF]) + reserved + oem
        frames = self.transact(PT_ROUTING_ACT_REQ, payload, duration=timeout)
        resp = None
        for f in frames:
            if f.ptype == PT_ROUTING_ACT_RESP and len(f.payload) >= 5:
                tsa = struct.unpack(">H", f.payload[0:2])[0]
                la = struct.unpack(">H", f.payload[2:4])[0]
                code = f.payload[4]
                resp = {
                    "tester_sa": "0x%04X" % tsa,
                    "entity_la": "0x%04X" % la,
                    "code": "0x%02X" % code,
                    "text": RA_CODES.get(code, "unknown"),
                    "trailing": hexs(f.payload[5:]),
                }
                if code in (0x00, 0x10):
                    self.activated_sa = tsa
        return resp, frames

    def read_one_frame(self, deadline: float) -> Optional[Frame]:
        """Read exactly one DoIP frame, or None if `deadline` passes."""
        remain = deadline - time.time()
        if remain <= 0:
            return None
        hdr = self._recv_exact(8, deadline)
        if not hdr or len(hdr) < 8:
            return None
        ver, inv, ptype, plen = struct.unpack(">BBHI", hdr)
        payload = self._recv_exact(plen, deadline) if plen else b""
        return Frame(ptype=ptype, payload=payload or b"", ver=ver, t=time.time())

    def drain(self, quiet: float = 0.15, max_bytes: int = 65536) -> int:
        """Throw away any bytes already queued on the socket.

        Sweeps must do this before every request: this gateway occasionally
        answers an earlier request *after* the client's timeout, and the stale
        frame would otherwise be attributed to the next request.  Detected by
        the negative response echoing the wrong SID.
        """
        if not self.sock:
            return 0
        dropped = 0
        end = time.time() + quiet
        while time.time() < end and dropped < max_bytes:
            self.sock.settimeout(max(0.01, end - time.time()))
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            dropped += len(chunk)
        return dropped

    def diag(self, sa: int, ta: int, uds: bytes, timeout: Optional[float] = None,
             wait_pending: bool = True, max_pending: int = 4,
             settle: float = 0.02) -> dict:
        """Send one UDS request inside a 0x8001 diagnostic message.

        The reader is *response driven*: it stops as soon as it holds a final
        UDS answer (or a DoIP nack), instead of draining until an idle gap.
        That keeps measured latency honest (~1 RTT) and makes the client fast
        enough to sweep without triggering any server-side rate limit.
        `settle` is a short grace window used to pick up frames that a stack
        emits back-to-back after the ack (0x8002 followed by 0x8001).
        """
        timeout = self.timeout if timeout is None else timeout
        payload = u16(sa) + u16(ta) + uds
        out = {"sa": "0x%04X" % sa, "ta": "0x%04X" % ta, "uds_req": hexs(uds),
               "acks": [], "nacks": [], "uds": [], "frames": [], "latency_ms": None}
        t0 = time.time()
        self.send(PT_DIAG_MSG, payload)
        deadline = t0 + timeout
        got_final = False
        pending_seen = 0
        while True:
            f = self.read_one_frame(deadline)
            if f is None:
                break
            out["frames"].append(f.as_dict())
            if f.ptype == PT_DIAG_ACK:
                out["acks"].append({"hex": hexs(f.payload),
                                    "code": "0x%02X" % f.payload[0] if f.payload else None})
                # an ack is followed by the real answer: extend a little
                deadline = max(deadline, time.time() + max(settle, 0.05))
                continue
            if f.ptype == PT_DIAG_NACK:
                out["nacks"].append({"hex": hexs(f.payload),
                                     "code": "0x%02X" % f.payload[0] if f.payload else None})
                got_final = True
                break
            if f.ptype == PT_DIAG_MSG and len(f.payload) >= 4:
                rsa = struct.unpack(">H", f.payload[0:2])[0]
                rta = struct.unpack(">H", f.payload[2:4])[0]
                uds_resp = f.payload[4:]
                out["uds"].append({"from": "0x%04X" % rsa, "to": "0x%04X" % rta,
                                   "hex": hexs(uds_resp), "text": uds_explain(uds_resp)})
                # ISO 14229 pending: 7F <sid> 78 -> keep waiting for the final answer
                if (wait_pending and len(uds_resp) == 3 and uds_resp[0] == 0x7F
                        and uds_resp[2] == 0x78 and pending_seen < max_pending):
                    pending_seen += 1
                    deadline = time.time() + max(timeout, 2.0)
                    continue
                got_final = True
                # keep a tiny window for trailing frames, then leave
                deadline = min(deadline, time.time() + settle)
                continue
            # any other payload type: keep going, deadline governs
        out["latency_ms"] = round((time.time() - t0) * 1000, 2)
        self.last_latency_ms = out["latency_ms"]
        return out


# ------------------------------------------------------------------- reporting
def emit(label: str, obj: dict, out_dir: Optional[str] = None) -> str:
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, "doip_%s.json" % label)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        return path
    return ""


def expand_ranges(spec: str) -> List[int]:
    """'0000-00FF,1000,18DA00F1' -> list of ints."""
    vals: List[int] = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a, 16), int(b, 16)
            if b >= a:
                vals.extend(range(a, b + 1))
            else:
                vals.extend(range(a, b - 1, -1))
        else:
            vals.append(int(part, 16))
    seen, uniq = set(), []
    for v in vals:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


# ------------------------------------------------------------------------ main
def cmd_ident(args) -> None:
    with DoIPClient(args.host, args.port, args.timeout, not args.quiet) as c:
        frames = c.vehicle_identification()
        info = {"label": "ident", "host": args.host, "responses": [f.as_dict() for f in frames]}
        for f in frames:
            if f.ptype == PT_VEHICLE_ANNOUNCE and len(f.payload) >= 19:
                info["vin"] = f.payload[:17].decode("ascii", "replace")
                info["logical_address"] = "0x%04X" % struct.unpack(">H", f.payload[17:19])[0]
                if len(f.payload) >= 25:
                    info["eid"] = hexs(f.payload[19:25])
                if len(f.payload) >= 31:
                    info["gid"] = hexs(f.payload[25:31])
                if len(f.payload) >= 32:
                    info["further_action"] = "0x%02X" % f.payload[31]
        emit("ident_%s" % args.host.replace(".", "_"), info, args.out_dir)


def cmd_ra(args) -> None:
    with DoIPClient(args.host, args.port, args.timeout, not args.quiet) as c:
        for sa in [int(x, 16) for x in args.sa_list.split(",")]:
            resp, frames = c.routing_activation(sa)
            emit("ra_%04x_%s" % (sa, args.host.replace(".", "_")),
                 {"label": "ra_0x%04X" % sa, "host": args.host, "request_sa": "0x%04X" % sa,
                  "response": resp, "frames": [f.as_dict() for f in frames]}, args.out_dir)
            time.sleep(args.gap)


def cmd_uds(args) -> None:
    sa = int(args.sa, 16)
    ta = int(args.ta, 16)
    uds = parse_hex(args.uds)
    with DoIPClient(args.host, args.port, args.timeout, not args.quiet) as c:
        ra_resp = None
        if not args.no_activate:
            ra_resp, _ = c.routing_activation(sa)
        res = c.diag(sa, ta, uds, timeout=args.timeout)
        res.update({"label": "uds", "host": args.host,
                    "routing_activation": ra_resp, "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
        lbl = "uds_%s_sa%04x_ta%04x_%s" % (args.host.replace(".", "_"), sa, ta, hexs(uds))
        emit(lbl, res, args.out_dir)


def cmd_raw(args) -> None:
    payload = parse_hex(args.payload)
    with DoIPClient(args.host, args.port, args.timeout, not args.quiet) as c:
        frames = c.transact(int(args.ptype, 16), payload, duration=args.timeout,
                            ver=int(args.version, 16))
        emit("raw_%04x_%s" % (int(args.ptype, 16), args.host.replace(".", "_")),
             {"label": "raw", "host": args.host, "request": {"ptype": args.ptype,
                                                             "payload": hexs(payload),
                                                             "version": args.version},
              "frames": [f.as_dict() for f in frames]}, args.out_dir)


def _addr_int(txt: Optional[str]) -> Optional[int]:
    """'0x1000' / '0X1000' / '1000' -> int, else None."""
    if not txt:
        return None
    try:
        return int(str(txt).strip().replace("0X", "0x"), 16)
    except (TypeError, ValueError):
        return None


def _classify(res: dict) -> Tuple[str, Optional[str]]:
    """Classify one probe answer against the gateway's two-level NRC scheme.

    baseline  : 7F <sid> 31 arriving from 0x1000 -> gateway says 'no such target'
    INTEREST  : anything else -> target either exists, or the gateway handled it
    """
    uds = res["uds"]
    if uds:
        first = uds[0]
        h = first["hex"].upper()
        nrc = h[4:6] if h.startswith("7F") and len(h) >= 6 else ""
        if (nrc == "31" and _addr_int(first.get("from")) == 0x1000
                and _addr_int(res.get("ta")) != 0x1000):
            return "BASELINE_NRC31", nrc
        return "INTERESTING", nrc
    if res["nacks"]:
        return "DIAG_NACK", None
    if res["acks"]:
        return "ACK_ONLY", None
    return "TIMEOUT", None


def cmd_sweep_ta(args) -> None:
    """Probe a list of target logical addresses and classify the answer.

    The gateway answers 7F <sid> 31 (requestOutOfRange) for targets it does not
    know, so any NRC other than 0x31 -- or a real positive response -- marks a
    target worth a second look.  Slow answers are expected (observed p95 close
    to 800 ms with occasional ~1 s outliers), therefore every non-baseline row
    is retried with a long timeout before it is believed.
    """
    tas = expand_ranges(args.ranges)
    probe = parse_hex(args.probe)
    rows: List[dict] = []
    with DoIPClient(args.host, args.port, args.timeout, not args.quiet) as c:
        ra, _ = c.routing_activation(int(args.sa, 16))
        print("[*] routing activation: %s" % (ra.get("text") if ra else "FAILED"), flush=True)
        t_start = time.time()
        for ta in tas:
            res = c.diag(int(args.sa, 16), ta, probe, timeout=args.timeout, wait_pending=False)
            klass, nrc = _classify(res)
            rows.append({"ta": ta, "class": klass, "nrc": nrc,
                         "latency_ms": res["latency_ms"], "attempts": 1,
                         "resp": res["uds"][0] if res["uds"] else None,
                         "nacks": res["nacks"]})
            time.sleep(args.gap)

        # -- retry pass: long timeout, several rounds, before believing a hit
        for rnd in range(args.retries):
            again = [r for r in rows if r["class"] in ("TIMEOUT", "DIAG_NACK", "ACK_ONLY")]
            if not again:
                break
            print("[*] retry round %d for %d suspicious TA(s), timeout=%.1fs"
                  % (rnd + 1, len(again), args.retry_timeout), flush=True)
            for r in again:
                res = c.diag(int(args.sa, 16), r["ta"], probe, timeout=args.retry_timeout,
                             wait_pending=False)
                klass, nrc = _classify(res)
                r["attempts"] += 1
                r.setdefault("history", []).append(
                    {"class": klass, "latency_ms": res["latency_ms"],
                     "resp": res["uds"][0] if res["uds"] else None})
                if klass not in ("TIMEOUT", "DIAG_NACK", "ACK_ONLY"):
                    r["class"], r["nrc"] = klass, nrc
                    r["resp"] = res["uds"][0] if res["uds"] else None
                    print("    TA=0x%04X reclassified -> %s %s"
                          % (r["ta"], klass, json.dumps(r["resp"], ensure_ascii=False)), flush=True)
                else:
                    r["latency_ms"] = max(r["latency_ms"], res["latency_ms"])
                time.sleep(args.gap)

        dt = time.time() - t_start

    counts: dict = {}
    for r in rows:
        counts[r["class"]] = counts.get(r["class"], 0) + 1
    hits = [r for r in rows if r["class"] not in ("BASELINE_NRC31",)]
    summary = {"label": "sweep_ta", "host": args.host, "probe": hexs(probe),
               "tester_sa": args.sa, "n_ta": len(tas), "counts": counts,
               "elapsed_s": round(dt, 1), "hits": hits}
    print("\n[+] classes: %s  (elapsed %.1fs)" % (counts, dt))
    for r in hits:
        print("  TA=0x%04X %-15s nrc=%s %s"
              % (r["ta"], r["class"], r["nrc"], json.dumps(r["resp"], ensure_ascii=False)), flush=True)
    emit("sweep_ta_%s" % args.host.replace(".", "_"), summary, args.out_dir)
    if args.out_dir:
        with open(os.path.join(args.out_dir, "doip_sweep_ta_all.jsonl"), "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        # human readable matrix, one row per TA
        mpath = os.path.join(args.out_dir, args.matrix_name)
        with open(mpath, "w", encoding="utf-8") as f:
            f.write("# DoIP target logical address matrix  host=%s sa=%s probe=%s\n"
                    % (args.host, args.sa, hexs(probe)))
            f.write("# baseline = 7F <sid> 31 (gateway: unknown target)\n")
            f.write("# %-8s %-15s %-6s %10s %4s %-14s %s\n"
                    % ("TA", "class", "nrc", "latency_ms", "att", "responder", "raw"))
            for r in rows:
                resp = r["resp"] or {}
                f.write("  %-8s %-15s %-6s %10.1f %4d %-14s %s\n"
                        % ("0x%04X" % r["ta"], r["class"], r["nrc"] or "-",
                           r["latency_ms"] or 0, r["attempts"],
                           resp.get("from", "-"), resp.get("hex", "-")))
        print("[+] matrix written: %s" % mpath)


def cmd_sweep(args) -> None:
    """Generic SWEEP over one or two byte parameters, e.g. SID or DID."""
    vals = expand_ranges(args.values)
    with DoIPClient(args.host, args.port, args.timeout, not args.quiet) as c:
        ra, _ = c.routing_activation(int(args.sa, 16))
        print("[*] routing activation: %s" % (ra.get("text") if ra else "FAILED"), flush=True)
        rows, t_start = [], time.time()
        base = None
        for v in vals:
            tmpl = args.template  # e.g. "22{did}" or "{sid}01"
            uds = parse_hex(tmpl.replace("{v}", "%0*X" % (args.width, v))
                              .replace("{did}", "%0*X" % (args.width, v))
                              .replace("{sid}", "%0*X" % (args.width, v)))
            res = c.diag(int(args.sa, 16), int(args.ta, 16), uds, timeout=args.timeout,
                         wait_pending=False)
            uds_r = res["uds"]
            key = uds_r[0]["hex"] if uds_r else ("NACK:" + json.dumps(res["nacks"]) if res["nacks"] else "TIMEOUT")
            if base is None:
                base = key
            row = {"v": "0x%0*X" % (args.width, v), "req": hexs(uds), "resp": key,
                   "from": uds_r[0]["from"] if uds_r else None}
            rows.append(row)
            if key != base or args.all:
                print("  %s -> %s" % (row["v"], key), flush=True)
            time.sleep(args.gap)
        dt = time.time() - t_start
    diff = [r for r in rows if r["resp"] != base]
    summary = {"label": "sweep_%s" % args.template, "host": args.host, "template": args.template,
               "ta": args.ta, "n": len(rows), "baseline": base, "elapsed_s": round(dt, 1),
               "non_baseline": diff}
    print("\n[+] n=%d baseline=%s non_baseline=%d elapsed=%.1fs"
          % (len(rows), base, len(diff), dt))
    emit("sweep_%s_%s" % (args.template.replace("{", "").replace("}", ""),
                          args.host.replace(".", "_")), summary, args.out_dir)
    if args.out_dir:
        with open(os.path.join(args.out_dir, "doip_sweep_%s_all.jsonl"
                               % args.template.replace("{", "").replace("}", "")), "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")


def cmd_compare(args) -> None:
    """Prove whether two hostnames are the same DoIP entity."""
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    out = {"label": "compare", "hosts": {}}
    for h in hosts:
        entry: dict = {}
        try:
            with DoIPClient(h, args.port, args.timeout, False) as c:
                frames = c.vehicle_identification()
                for f in frames:
                    if f.ptype == PT_VEHICLE_ANNOUNCE:
                        entry["ident_hex"] = hexs(f.payload)
                        entry["vin"] = f.payload[:17].decode("ascii", "replace")
                        break
                ra, _ = c.routing_activation(int(args.sa, 16))
                entry["ra"] = ra
                res = c.diag(int(args.sa, 16), int(args.ta, 16), parse_hex(args.uds), timeout=args.timeout)
                entry["uds"] = res["uds"]
        except Exception as e:  # noqa: BLE001
            entry["error"] = "%s: %s" % (type(e).__name__, e)
        out["hosts"][h] = entry
        print("[%s] %s" % (h, json.dumps(entry, ensure_ascii=False)[:400]), flush=True)
    vals = [json.dumps({k: v for k, v in e.items() if k != "error"}, sort_keys=True)
            for e in out["hosts"].values()]
    out["identical"] = len(set(vals)) == 1 and all("error" not in e for e in out["hosts"].values())
    print("\n[+] identical state across hosts: %s" % out["identical"])
    emit("compare", out, args.out_dir)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="DoIP/UDS client for CyberCar T03 CGW")
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--timeout", type=float, default=1.5)
    p.add_argument("--gap", type=float, default=0.06, help="delay between probes (s)")
    p.add_argument("--out-dir", default=None)
    p.add_argument("--quiet", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("ident", help="vehicle identification request").set_defaults(func=cmd_ident)

    sp = sub.add_parser("ra", help="routing activation")
    sp.add_argument("--sa-list", default="0E00")
    sp.set_defaults(func=cmd_ra)

    sp = sub.add_parser("uds", help="single UDS request")
    sp.add_argument("--sa", default="%04X" % DEFAULT_SA)
    sp.add_argument("--ta", default="%04X" % DEFAULT_TA)
    sp.add_argument("--uds", required=True)
    sp.add_argument("--no-activate", action="store_true")
    sp.set_defaults(func=cmd_uds)

    sp = sub.add_parser("raw", help="raw DoIP payload type")
    sp.add_argument("--ptype", required=True)
    sp.add_argument("--payload", default="")
    sp.add_argument("--version", default="02")
    sp.set_defaults(func=cmd_raw)

    sp = sub.add_parser("sweep-ta", help="enumerate target logical addresses")
    sp.add_argument("--sa", default="%04X" % DEFAULT_SA)
    sp.add_argument("--ranges", required=True)
    sp.add_argument("--probe", default="3E00")
    sp.add_argument("--retries", type=int, default=2)
    sp.add_argument("--retry-timeout", type=float, default=4.0)
    sp.add_argument("--matrix-name", default="doip_ta_matrix.txt")
    sp.add_argument("--all", action="store_true")
    sp.set_defaults(func=cmd_sweep_ta)

    sp = sub.add_parser("sweep", help="sweep one value against a UDS template")
    sp.add_argument("--sa", default="%04X" % DEFAULT_SA)
    sp.add_argument("--ta", default="%04X" % DEFAULT_TA)
    sp.add_argument("--template", required=True, help="e.g. '22{did}' or '{sid}01'")
    sp.add_argument("--values", required=True)
    sp.add_argument("--width", type=int, default=2)
    sp.add_argument("--all", action="store_true")
    sp.set_defaults(func=cmd_sweep)

    sp = sub.add_parser("compare", help="compare DoIP state across hosts")
    sp.add_argument("--hosts", default="%s,%s" % (DEFAULT_HOST, ALT_HOST))
    sp.add_argument("--sa", default="%04X" % DEFAULT_SA)
    sp.add_argument("--ta", default="%04X" % DEFAULT_TA)
    sp.add_argument("--uds", default="22F190")
    sp.set_defaults(func=cmd_compare)

    args = p.parse_args(argv)
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())

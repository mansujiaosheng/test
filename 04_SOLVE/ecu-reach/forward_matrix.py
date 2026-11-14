#!/usr/bin/env python3
"""DoIP forwarding / logical-address matrix against the CGW (ISO 13400-2).

Purpose: decide whether the gateway forwards diagnostic requests to the BCM/BMS/VCU
CAN diagnostic IDs (0x07E0/0x07E8/0x07E1/0x07E9) or any other logical address,
and record the *source address* of every response.

Read-only: only UDS 0x22 (read), 0x10 0x02 (session control, non-destructive),
0x3E 0x00 (tester present). No writes, no security access, no resets.

Modes
  matrix  : explicit (target, uds) pairs -> one request each, full frame record
  sweep   : one RA per connection, then 3E00 to every TA in given ranges
            (fast; used to enumerate live logical addresses)

Usage
  python forward_matrix.py --host 10.226.193.2 matrix --tas 07E0,07E8,07E1,07E9,E400,1000 --uds 3E00,22F190,1002
  python forward_matrix.py --host 10.226.193.2 sweep --ranges 0000-00FF,0700-07FF,0E00-0EFF,1000-10FF
"""
from __future__ import annotations

import argparse
import binascii
import json
import select
import socket
import struct
import sys
import time
from datetime import datetime

PT_VEHICLE_ID_REQ = 0x0001
PT_ROUTING_ACT_REQ = 0x0005
PT_ROUTING_ACT_RESP = 0x0006
PT_DIAG_MSG = 0x8001
PT_DIAG_ACK = 0x8002
PT_DIAG_NACK = 0x8003

NRC = {
    0x10: "generalReject", 0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat", 0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect", 0x24: "requestSequenceError",
    0x31: "requestOutOfRange", 0x33: "securityAccessDenied", 0x35: "invalidKey",
    0x72: "generalProgrammingFailure", 0x78: "responsePending", 0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}


def frame(ptype: int, payload: bytes, ver: int = 0x02) -> bytes:
    return bytes([ver, 0xFF - ver]) + struct.pack(">H", ptype) + struct.pack(">I", len(payload)) + payload


def recv_one(sock: socket.socket, deadline: float):
    """read exactly one DoIP frame; return (ptype, payload) or None on deadline/EOF"""
    def recvn(n):
        buf = b""
        while len(buf) < n:
            remain = deadline - time.time()
            if remain <= 0:
                return None
            r, _, _ = select.select([sock], [], [], remain)
            if not r:
                return None
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf
    hdr = recvn(8)
    if hdr is None:
        return None
    ver, inv, ptype, plen = struct.unpack(">BBHI", hdr)
    payload = recvn(plen) if plen else b""
    if payload is None:
        return None
    return ver, ptype, payload


def connect(host, port, timeout):
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def activate(sock, sa: int, deadline: float):
    sock.sendall(frame(PT_ROUTING_ACT_REQ, struct.pack(">H", sa) + b"\x00" * 5))
    while True:
        f = recv_one(sock, deadline)
        if f is None:
            return None, []
        ver, ptype, payload = f
        if ptype == PT_ROUTING_ACT_RESP:
            return payload, [payload.hex()]
        if ptype == 0x0000:
            return payload, [payload.hex()]


def diag(sock, sa: int, ta: int, uds: bytes, timeout: float, drain: float = 0.25):
    """send one diagnostic message, collect frames until the 0x8001 terminal reply or timeout"""
    t0 = time.time()
    deadline = t0 + timeout
    sock.sendall(frame(PT_DIAG_MSG, struct.pack(">HH", sa, ta) + uds))
    seen = []
    terminal = None
    while time.time() < deadline:
        f = recv_one(sock, min(deadline, time.time() + 0.6))
        if f is None:
            break
        ver, ptype, payload = f
        seen.append({"ptype": f"0x{ptype:04x}", "hex": payload.hex()})
        if ptype == PT_DIAG_MSG:
            terminal = payload
            # a request may produce ack + response; keep draining very briefly for extras
            while True:
                f2 = recv_one(sock, time.time() + drain)
                if f2 is None:
                    break
                seen.append({"ptype": f"0x{f2[1]:04x}", "hex": f2[2].hex()})
            break
        if ptype == PT_DIAG_NACK:
            terminal = payload
            break
    dt = (time.time() - t0) * 1000
    out = {"ta": f"0x{ta:04X}", "uds": uds.hex().upper(), "elapsed_ms": round(dt, 1), "frames": seen}
    if terminal is not None and len(terminal) >= 4:
        from_sa, to_sa = struct.unpack(">HH", terminal[:4])
        resp = terminal[4:]
        out["from"] = f"0x{from_sa:04X}"
        out["to"] = f"0x{to_sa:04X}"
        out["resp_hex"] = resp.hex().upper()
        if resp:
            if resp[0] == 0x7F and len(resp) >= 3:
                out["verdict"] = f"NRC(0x{resp[1]:02X})={NRC.get(resp[2], '?')}"
            elif resp[0] == 0x7F:
                out["verdict"] = "NEGATIVE(short)"
            else:
                out["verdict"] = f"POSITIVE sid=0x{resp[0]:02X}"
    else:
        out["from"] = None
        out["verdict"] = "NO-DIAG-RESPONSE"
    return out


def expand_ranges(spec: str):
    vals = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-")
            vals.extend(range(int(a, 16), int(b, 16) + 1))
        else:
            vals.append(int(part, 16))
    return vals


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.226.193.2")
    ap.add_argument("--port", type=int, default=13400)
    ap.add_argument("--sa", default="0E00")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--out", default=None)
    ap.add_argument("--note", default="")
    sub = ap.add_subparsers(dest="mode", required=True)

    m = sub.add_parser("matrix")
    m.add_argument("--tas", required=True)
    m.add_argument("--uds", required=True)

    s = sub.add_parser("sweep")
    s.add_argument("--ranges", required=True)
    s.add_argument("--probe", default="3E00")
    s.add_argument("--only-live", action="store_true")

    a = ap.parse_args()
    sa = int(a.sa, 16)
    result = {"mode": a.mode, "host": a.host, "port": a.port, "tester_sa": f"0x{sa:04X}",
              "started": datetime.now().astimezone().isoformat(timespec="seconds")}
    if a.note:
        result["note"] = a.note

    if a.mode == "matrix":
        tas = [int(x, 16) for x in a.tas.split(",") if x.strip()]
        uds_list = [bytes.fromhex(x.strip()) for x in a.uds.split(",") if x.strip()]
        rows = []
        sock = connect(a.host, a.port, 5.0)
        act, act_frames = activate(sock, sa, time.time() + 5.0)
        result["routing_activation"] = {"frames": act_frames,
                                        "resp_hex": act.hex() if act else None}
        for ta in tas:
            for uds in uds_list:
                rows.append(diag(sock, sa, ta, uds, a.timeout))
                time.sleep(0.02)
        sock.close()
        result["rows"] = rows
    else:
        tas = expand_ranges(a.ranges)
        sock = connect(a.host, a.port, 5.0)
        act, act_frames = activate(sock, sa, time.time() + 5.0)
        result["routing_activation"] = {"frames": act_frames, "resp_hex": act.hex() if act else None}
        rows = []
        t0 = time.time()
        for i, ta in enumerate(tas):
            r = diag(sock, sa, ta, bytes.fromhex(a.probe), a.timeout, drain=0.08)
            r["ta"] = f"0x{ta:04X}"
            if not a.only_live or r["verdict"] != "NO-DIAG-RESPONSE":
                rows.append(r)
            if i and i % 128 == 0:
                print(f"[sweep] {i}/{len(tas)} elapsed={time.time()-t0:.1f}s "
                      f"live={sum(1 for x in rows if x['verdict'] != 'NO-DIAG-RESPONSE')}", flush=True)
        sock.close()
        result["rows"] = rows
        result["elapsed_s"] = round(time.time() - t0, 1)
        result["probed"] = len(tas)

    text = json.dumps(result, ensure_ascii=False, indent=2)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(text)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Probe CGW TCP/13401 with a battery of plausible framings and record exactly what comes back.

Read-only. Each case: fresh connection, optional banner read, send payload, read until
timeout or EOF, report rx bytes + whether the peer closed and after how long.

Cases
  banner          : connect and read 1.0s without sending (does the server speak first?)
  doip-ident      : DoIP 0x0001 vehicle identification request
  doip-ra         : DoIP 0x0005 routing activation
  doip-diag       : DoIP 0x8001 diagnostic message (SA 0E00 -> TA 1000, 22F190)
  can-raw-8       : 11-bit CAN id 0x7E0 as 2B BE id + 1B dlc + 8B data
  can-4b-id       : 4B BE id + 1B dlc + 8B data (SocketCAN-ish)
  can-fd          : CAN FD frame layout (id 4B, flags, dlc, data)
  isotp-sf        : ISO-TP single frame carrying UDS 22 F1 90 (02 22 F1 90 ...)
  tls             : TLS ClientHello (record layer)
  len2le / len2be / len4le / len4be : JSON body wrapped in a length prefix
  len4be-doip     : DoIP frame wrapped in a 4B BE length prefix
  json-line       : {"cmd":"..."}\n
  text-line       : ATZ\r\n / help\r\n
  raw-uds         : bare UDS bytes 22 F1 90
  zeroes          : 16 zero bytes (probe for echo/keepalive behaviour)
"""
from __future__ import annotations

import argparse
import json
import select
import socket
import struct
import time
from datetime import datetime

HOST = "10.226.193.2"
PORT = 13401


def doip(ptype: int, payload: bytes) -> bytes:
    return bytes([0x02, 0xFD]) + struct.pack(">H", ptype) + struct.pack(">I", len(payload)) + payload


def can_frame(can_id: int, data: bytes, dlc: int = None) -> bytes:
    dlc = len(data) if dlc is None else dlc
    return struct.pack(">H", can_id) + bytes([dlc]) + data


def iso_tp_sf(uds: bytes) -> bytes:
    assert len(uds) <= 7
    return bytes([len(uds)]) + uds + b"\x00" * (7 - len(uds))


CASES = {
    "banner": (None, 1.0),
    "doip-ident": (doip(0x0001, b""), 1.0),
    "doip-ra": (doip(0x0005, b"\x0e\x00" + b"\x00" * 5), 1.0),
    "doip-diag": (doip(0x8001, b"\x0e\x00\x10\x00" + bytes.fromhex("22F190")), 1.0),
    "can-raw-8": (can_frame(0x7E0, iso_tp_sf(bytes.fromhex("22F190"))), 1.0),
    "can-4b-id": (struct.pack(">I", 0x7E0) + bytes([8]) + iso_tp_sf(bytes.fromhex("22F190")), 1.0),
    "can-fd": (struct.pack(">I", 0x7E0) + bytes([0x00, 0x08]) + iso_tp_sf(bytes.fromhex("22F190")), 1.0),
    "isotp-sf": (iso_tp_sf(bytes.fromhex("22F190")), 1.0),
    # minimal TLS 1.2 ClientHello (record layer), no extensions beyond SNI-less default
    "tls": (bytes.fromhex(
        "160301002a010000260303" + "00" * 32 +
        "000002002f0100"), 1.5),
    "len2le": (struct.pack("<H", 5) + b'{"a":1}', 1.0),
    "len2be": (struct.pack(">H", 5) + b'{"a":1}', 1.0),
    "len4le": (struct.pack("<I", 5) + b'{"a":1}', 1.0),
    "len4be": (struct.pack(">I", 5) + b'{"a":1}', 1.0),
    "len4be-doip": (struct.pack(">I", 8) + doip(0x0001, b""), 1.0),
    "json-line": (b'{"cmd":"vehicle.identify"}\n', 1.0),
    "text-line": (b"ATZ\r\n", 1.0),
    "raw-uds": (bytes.fromhex("22F190"), 1.0),
    "zeroes": (b"\x00" * 16, 1.0),
}


def run_case(host, port, name, payload, wait, pre=0.0):
    t0 = time.time()
    ev = {"case": name, "tx_hex": payload.hex() if payload else "", "rx_hex": "",
          "rx_len": 0, "eof": False, "eof_after_ms": None, "error": None,
          "banner_hex": ""}
    s = socket.socket()
    s.settimeout(0.2)
    try:
        s.connect((host, port))
        ev["connect_ms"] = round((time.time() - t0) * 1000, 1)
        if pre:
            time.sleep(pre)
        if payload is not None:
            s.sendall(payload)
        buf = b""
        deadline = time.time() + wait
        while time.time() < deadline:
            r, _, _ = select.select([s], [], [], 0.05)
            if not r:
                continue
            chunk = s.recv(4096)
            if not chunk:
                ev["eof"] = True
                ev["eof_after_ms"] = round((time.time() - t0) * 1000, 1)
                break
            buf += chunk
        ev["rx_hex"] = buf.hex()
        ev["rx_len"] = len(buf)
    except OSError as e:
        ev["error"] = f"{type(e).__name__}:{e}"
    finally:
        try:
            s.close()
        except Exception:
            pass
    ev["total_ms"] = round((time.time() - t0) * 1000, 1)
    return ev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--out", required=True)
    ap.add_argument("--note", default="")
    a = ap.parse_args()

    res = {"host": a.host, "port": a.port,
           "started": datetime.now().astimezone().isoformat(timespec="seconds"),
           "note": a.note, "cases": []}
    for name, (payload, wait) in CASES.items():
        ev = run_case(a.host, a.port, name, payload, wait)
        res["cases"].append(ev)
        print(f"{name:<14} rx={ev['rx_len']:>3}B eof={ev['eof']} "
              f"eof_ms={ev['eof_after_ms']} err={ev['error']} rx={ev['rx_hex'][:80]}", flush=True)
    text = json.dumps(res, ensure_ascii=False, indent=2)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    print(f"# wrote {a.out}")


if __name__ == "__main__":
    main()

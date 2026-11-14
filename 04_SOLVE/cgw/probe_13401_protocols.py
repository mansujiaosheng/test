#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fingerprint 10.230.164.4:13401 (open TCP port next to the DoIP port).

The port accepts TCP but ignores DoIP 0x0001 and HTTP, and resets on a plain
TLS ClientHello.  This script tries the protocol families that a "CAN FD /
ISO-TP bridge" or an alternate DoIP channel could plausibly speak, and records
every byte sent/received under 03_EVIDENCE/cgw/.

All probes are read-only application-layer strings / empty frames; nothing here
asks a vehicle to change state.
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVID = ROOT / "03_EVIDENCE" / "cgw"
HOST = "10.230.164.4"
PORT = 13401


def record(label, purpose, request_hex, response_hex, note=""):
    EVID.mkdir(parents=True, exist_ok=True)
    mx = 0
    for p in EVID.glob("[0-9][0-9][0-9][0-9]_*"):
        m = re.match(r"(\d{4})_", p.name)
        if m:
            mx = max(mx, int(m.group(1)))
    seq = mx + 1
    rec = {"label": label, "purpose": purpose, "host": HOST, "port": PORT,
           "request": {"hex": request_hex}, "responses": [{"hex": response_hex}],
           "note": note, "seq": seq,
           "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    safe = re.sub(r"[^0-9A-Za-z_.-]+", "_", label)[:60]
    (EVID / f"{seq:04d}_{safe}.json").write_text(
        json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
    with open(EVID / "trace.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"[{label}] sent={len(request_hex)//2 if re.fullmatch(r'[0-9A-Fa-f]*', request_hex or '') else '?'}B "
          f"recv={len(response_hex)//2}B {note}")


def exchange(label, payload, wait=2.0, purpose="", server_first=False):
    try:
        s = socket.create_connection((HOST, PORT), timeout=3)
        s.settimeout(wait)
        if payload:
            s.sendall(payload)
        data = b""
        try:
            while len(data) < 4096:
                c = s.recv(4096)
                if not c:
                    break
                data += c
        except socket.timeout:
            pass
        s.close()
        record(label, purpose, payload.hex().upper(), data.hex().upper(),
               f"{len(data)}B" if data else "silent")
        return data
    except ConnectionResetError:
        record(label, purpose, payload.hex().upper(), "", "connection reset")
        return None
    except Exception as exc:  # noqa: BLE001
        record(label, purpose, payload.hex().upper(), "", f"{type(exc).__name__}: {exc}")
        return None


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    # 0) does the server speak first?
    exchange("p13401_server_first", b"", wait=3.0, purpose="read-only: wait for a server banner")
    # 1) text protocols
    exchange("p13401_socketcand_hello", b"< hello >\n", purpose="socketcand handshake")
    exchange("p13401_socketcand_open", b"< open can0 >\n", purpose="socketcand open channel")
    exchange("p13401_socketcand_rawmode", b"< rawmode >\n", purpose="socketcand raw mode")
    # 2) length-prefixed CAN frame candidates (big endian / little endian)
    frame = bytes.fromhex("07E0" "02" "1003" "000000000000")  # id + dlc + uds + pad
    exchange("p13401_len_be", struct.pack(">I", len(frame)) + frame,
             purpose="4-byte BE length prefix + CAN-ish frame")
    exchange("p13401_len_le", struct.pack("<I", len(frame)) + frame,
             purpose="4-byte LE length prefix + CAN-ish frame")
    exchange("p13401_raw_canframe", frame, purpose="raw 11-bit CAN frame bytes")
    # 3) HTTP/2 preface and a minimal HTTP/2 SETTINGS frame
    exchange("p13401_h2_preface", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
             purpose="HTTP/2 connection preface")
    # 4) DoIP with the older on-wire version byte
    doip_ident_v1 = bytes([0x01, 0xFE]) + struct.pack(">H", 0x0001) + struct.pack(">I", 0)
    exchange("p13401_doip_v1_ident", doip_ident_v1, purpose="DoIP 0x0001 with version 0x01")
    doip_ra_v1 = (bytes([0x01, 0xFE]) + struct.pack(">H", 0x0005) + struct.pack(">I", 7)
                  + struct.pack(">H", 0x0E00) + b"\x00" + b"\x00" * 4)
    exchange("p13401_doip_v1_ra", doip_ra_v1, purpose="DoIP routing activation with version 0x01")
    # 5) TLS with SNI tbox and ALPN
    for sni in (None, "tbox", "cgw"):
        label = f"p13401_tls_sni_{sni or 'none'}"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((HOST, PORT), timeout=5)
            tls = ctx.wrap_socket(raw, server_hostname=sni)
            record(label, "TLS ClientHello with SNI", "TLS ClientHello", "",
                   f"TLS established: {tls.version()} {tls.cipher()}")
            tls.close()
        except Exception as exc:  # noqa: BLE001
            record(label, "TLS ClientHello with SNI", "TLS ClientHello", "",
                   f"{type(exc).__name__}: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

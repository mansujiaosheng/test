#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identify 10.229.221.2:13401 / 10.230.164.4:13401 (adjacent to DoIP 13400).

Test ladder (all read-only, no state change):
  0 passive   : connect, send nothing, wait 3s -- does the server speak first?
  1 doip_v2   : DoIP 8-byte header, protocol version 0x02, ident request
  2 doip_v1   : protocol version 0x01
  3 doip_v3   : protocol version 0x03
  4 len2      : 2-byte length prefix framing
  5 len4_be   : 4-byte BE length prefix only (no DoIP header)
  6 len2_pl   : 2-byte len + payload, ISO-TP style single frame 0x02
  7 istp      : raw ISO-TP single frame 02 3E 00 padded
  8 tls       : TLS ClientHello (ssl module)
  9 tls_gmtls : TLS ClientHello with TLS1.3 only
"""
from __future__ import annotations

import json
import socket
import ssl
import struct
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVID = ROOT / "03_EVIDENCE" / "cgwweb"
EVID.mkdir(parents=True, exist_ok=True)

_seq = [4000]


def now():
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def hx(b: bytes) -> str:
    return b.hex().upper()


def record(rec: dict):
    _seq[0] += 1
    rec["seq"] = _seq[0]
    rec["ts"] = now()
    p = EVID / f"{_seq[0]:04d}_{rec.get('label', 'rec')}.json"
    p.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: v for k, v in rec.items()
                      if k in ("label", "sent_hex", "recv_hex", "note", "seq")},
                     ensure_ascii=False))
    return rec


def talk(host, port, payload, wait=2.5, note="", label="", connect_timeout=4.0):
    """Send payload (may be None = passive), read whatever comes back."""
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=connect_timeout)
    except Exception as e:
        return record({"label": label, "host": host, "port": port,
                       "sent_hex": hx(payload) if payload else "",
                       "recv_hex": "", "note": f"connect failed: {type(e).__name__}: {e}"})
    s.settimeout(0.5)
    data = b""
    closed_by_peer = False
    try:
        if payload:
            s.sendall(payload)
        end = time.time() + wait
        while time.time() < end:
            try:
                c = s.recv(4096)
            except socket.timeout:
                continue
            if not c:
                closed_by_peer = True
                break
            data += c
    except ConnectionResetError:
        closed_by_peer = True
        note += " | RST"
    except Exception as e:
        note += f" | {type(e).__name__}: {e}"
    finally:
        try:
            s.close()
        except OSError:
            pass
    n = note
    if closed_by_peer:
        n += " | peer closed"
    n += f" | {len(data)}B in {round((time.time()-t0)*1000)}ms"
    return record({"label": label, "host": host, "port": port,
                   "sent_hex": hx(payload) if payload else "",
                   "recv_hex": hx(data), "recv_ascii": data[:160].decode("latin-1", "replace"),
                   "note": n})


def doip_ident(ver):
    return bytes([ver, 0xFF - ver]) + struct.pack(">H", 0x0001) + struct.pack(">I", 0)


def tls_probe(host, port, maxver=None, label="tls"):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if maxver:
        ctx.maximum_version = maxver
    try:
        raw = socket.create_connection((host, port), timeout=5)
        t = ctx.wrap_socket(raw, server_hostname=host)
        note = f"TLS OK {t.version()} {t.cipher()}"
        data = b""
        try:
            data = t.recv(4096)
        except Exception:
            pass
        t.close()
        return record({"label": label, "host": host, "port": port,
                       "sent_hex": "TLS ClientHello", "recv_hex": hx(data), "note": note})
    except Exception as e:
        return record({"label": label, "host": host, "port": port,
                       "sent_hex": "TLS ClientHello", "recv_hex": "",
                       "note": f"{type(e).__name__}: {e}"})


def main():
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "10.229.221.2"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 13401
    print(f"### {host}:{port}")

    talk(host, port, None, wait=3.0, label=f"p{port}_passive",
         note="connected, sent nothing, listening 3s")

    for ver, tag in ((0x02, "v2"), (0x01, "v1"), (0x03, "v3"), (0x04, "v4")):
        talk(host, port, doip_ident(ver), wait=2.0, label=f"p{port}_doip_{tag}",
             note=f"DoIP ident, protocol version 0x{ver:02X}")

    # length-prefix framing variants carrying a DoIP ident payload
    body = struct.pack(">H", 0x0001)
    talk(host, port, struct.pack(">H", len(body)) + body, wait=2.0,
         label=f"p{port}_len2", note="2-byte BE length + ident ptype")
    talk(host, port, struct.pack(">I", len(body)) + body, wait=2.0,
         label=f"p{port}_len4", note="4-byte BE length + ident ptype")
    talk(host, port, b"\x02\x3e\x00" + b"\x00" * 5, wait=2.0,
         label=f"p{port}_isotp", note="ISO-TP single frame, UDS 3E00 padded to 8")
    talk(host, port, b"\x00" * 8, wait=2.0, label=f"p{port}_zeros",
         note="8 zero bytes")

    tls_probe(host, port, label=f"p{port}_tls")
    tls_probe(host, port, maxver=ssl.TLSVersion.TLSv1_2, label=f"p{port}_tls12")


if __name__ == "__main__":
    main()

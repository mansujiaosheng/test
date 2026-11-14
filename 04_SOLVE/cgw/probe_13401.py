#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Port 13401 framing probe.

13401 accepts TCP then stays silent; any data (per tbox-mtls) triggers RST.
We try a catalogue of plausible framings and record: silent / RST / reply bytes.

Evidence: 03_EVIDENCE/cgw/sec04/13401_framing.jsonl
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
EVID = ROOT / "03_EVIDENCE" / "cgw" / "sec04"
EVID.mkdir(parents=True, exist_ok=True)

HOST = "10.230.164.4"
PORT = 13401


def ts() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def attempt(name: str, payload: bytes, wait: float = 1.2, pre_wait: float = 0.0):
    rec = {"ts": ts(), "name": name, "sent": payload.hex(), "len": len(payload)}
    s = socket.socket()
    s.settimeout(2.0)
    try:
        s.connect((HOST, PORT))
        # 1) does the server speak first?
        s.settimeout(0.6)
        first = b""
        pre = "silent"
        if pre_wait:
            time.sleep(pre_wait)
        t_pre = time.time()
        try:
            first = s.recv(4096)
            if first == b"":
                pre = "FIN before send after %.0f ms" % ((time.time() - t_pre) * 1000)
            else:
                pre = "server spoke %d B" % len(first)
        except socket.timeout:
            pre = "silent (no FIN, no data) at 600 ms"
        except ConnectionResetError:
            pre = "RST-before-send"
        rec["pre"] = pre
        rec["server_first"] = first.hex()
        # 2) send
        s.settimeout(wait)
        s.sendall(payload)
        buf = b""
        err = None
        try:
            while len(buf) < 8192:
                c = s.recv(4096)
                if not c:
                    err = "EOF"
                    break
                buf += c
                if len(c) < 4096:
                    break
        except socket.timeout:
            err = "timeout(no reply)"
        except ConnectionResetError:
            err = "RST"
        rec["reply"] = buf.hex()
        rec["result"] = err or ("reply %d B" % len(buf))
    except Exception as e:  # noqa: BLE001
        rec["error"] = repr(e)
    finally:
        try:
            s.close()
        except OSError:
            pass
    return rec


def variants():
    v = []
    # --- DoIP flavoured
    doip_id = bytes.fromhex("02FD000100000000")
    v.append(("doip_ident_v2", doip_id))
    v.append(("doip_ident_v1", bytes.fromhex("01FE000100000000")))
    v.append(("doip_ident_v3", bytes.fromhex("03FC000100000000")))
    v.append(("doip_ra_v2", bytes.fromhex("02FD000500060E0000000000000000")))
    # --- length-prefixed
    body = b'{"type":"diagnostic","target":4096,"uds":"3E00"}'
    v.append(("be4_len+json", struct.pack(">I", len(body)) + body))
    v.append(("le4_len+json", struct.pack("<I", len(body)) + body))
    v.append(("be2_len+json", struct.pack(">H", len(body)) + body))
    v.append(("be4_len+raw", struct.pack(">I", 4) + bytes.fromhex("0E001000")))
    # --- text protocols
    v.append(("json_line", b'{"uds":"3E00","target":"0x1000"}\n'))
    v.append(("http_get", b"GET / HTTP/1.1\r\nHost: cgw\r\n\r\n"))
    v.append(("uds_hex_text", b"3E00\n"))
    # --- CAN FD-ish
    # socketCAN struct canfd_frame: can_id(u32 BE) + len(u8) + flags(u8) + __res0/1 + data[64]
    for cid in (0x7E0, 0x7E8, 0x100, 0x18DA1000 | 0x80000000):
        f = struct.pack(">I", cid) + bytes([8, 0, 0, 0]) + bytes.fromhex("0210030000000000") + b"\x00" * 56
        v.append((f"socketcan_fd_{cid:08X}", f))
        f2 = struct.pack("<I", cid) + bytes([8, 0, 0, 0]) + bytes.fromhex("0210030000000000") + b"\x00" * 56
        v.append((f"socketcan_fd_le_{cid:08X}", f2))
    # --- bare 29-bit id + dlc + data (no padding)
    v.append(("canfd_compact", struct.pack(">I", 0x18DA1000) + bytes([8]) + bytes.fromhex("0210030000000000")))
    v.append(("canfd_compact_11bit", struct.pack(">I", 0x7E0) + bytes([8]) + bytes.fromhex("0210030000000000")))
    # --- ISO-TP / UDS raw
    v.append(("isotp_sf", bytes.fromhex("0210030000000000")))
    v.append(("uds_raw", bytes.fromhex("021003")))
    # --- gRPC-ish h2 preface
    v.append(("h2_preface", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
    # --- TLS
    v.append(("tls_clienthello_min", bytes.fromhex("16030100050100010000")))
    # --- empty / single byte
    v.append(("empty", b""))
    v.append(("one_zero", b"\x00"))
    return v


def main():
    out = EVID / "13401_framing.jsonl"
    open(out, "w").close()
    for name, payload in variants():
        rec = attempt(name, payload)
        with open(out, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"{name:28s} len={len(payload):4d} first={rec.get('server_first','')[:24]:24s} "
              f"-> {rec.get('result') or rec.get('error')} reply={rec.get('reply','')[:60]}",
              flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

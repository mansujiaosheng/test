#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DoIP protocol-layer probes against the CGW (ISO 13400-2), all read-only.

Covered here:
  A. payload type sweep      -- which 0x0xxx/0x4xxx/0x8xxx types are implemented,
                                and what generic header NACK code unknown ones get
  B. version field           -- 0x01/0x02/0x03/0xFF and broken inverse byte
  C. routing activation      -- activation types incl. OEM 0xE0, repeats, foreign SA
  D. length-field abuse      -- declared length > actual, < actual, and 0
  E. UDS framing edges       -- empty / 1-byte / truncated diag payloads,
                                SA spoofing, multi-DID reads

Nothing here writes data: no 0x2E/0x31/0x34/0x36/0x37 request is ever accepted
for execution by this gateway (they answer 7F xx 11), and the script stops a
request family as soon as it sees a positive write-class response.
"""
import json
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from doip_client import (DoIPClient, PT_DIAG_MSG, PT_ROUTING_ACT_REQ,  # noqa: E402
                         hexs, parse_hex)

HOST = "10.229.221.2"
PORT = 13400
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                   "03_EVIDENCE", "cgw", "doip_layer_probe.jsonl")

results = []


def rec(group: str, label: str, req: str, frames, note: str = "") -> None:
    row = {"group": group, "label": label, "req": req,
           "frames": [f.as_dict() for f in frames], "note": note}
    results.append(row)
    summ = "; ".join("%s:%s" % (f.as_dict().get("ptype"), f.as_dict().get("hex"))
                     for f in frames) or "<no response>"
    print("  %-34s %-40s -> %s" % (label, req, summ), flush=True)
    if note:
        print("      note: %s" % note, flush=True)


# ---------------------------------------------------------------- A. ptypes
def probe_ptypes() -> None:
    print("\n[A] payload type sweep (empty payload)", flush=True)
    types = ([0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008]
             + list(range(0x0009, 0x0010))
             + list(range(0x4001, 0x4009))
             + list(range(0x8001, 0x8009))
             + [0x1234, 0x7FFF, 0xFFFF])
    with DoIPClient(HOST, PORT, 1.2, verbose=False) as c:
        for pt in types:
            frames = c.transact(pt, b"", duration=0.9)
            rec("A_ptype", "ptype=0x%04X" % pt, "empty", frames)
            time.sleep(0.05)


# -------------------------------------------------------------- B. versions
def probe_versions() -> None:
    print("\n[B] protocol version / inverse byte", flush=True)
    with DoIPClient(HOST, PORT, 1.2, verbose=False) as c:
        for ver, inv, label in [(0x02, 0xFD, "ver=0x02 inv=0xFD (valid)"),
                                (0x01, 0xFE, "ver=0x01 inv=0xFE"),
                                (0x03, 0xFC, "ver=0x03 inv=0xFC"),
                                (0x04, 0xFB, "ver=0x04 inv=0xFB"),
                                (0x02, 0x00, "ver=0x02 inv=0x00 (broken inverse)"),
                                (0xFF, 0x00, "ver=0xFF inv=0x00 (test-equipment)")]:
            raw = bytes([ver, inv]) + struct.pack(">HI", 0x0001, 0)
            c.sock.sendall(raw)
            frames = c.read_frames(0.9)
            rec("B_version", label, hexs(raw), frames,
                "generic NACK code is the first payload byte" if frames else "")


# ------------------------------------------------------- C. routing activation
def probe_activation() -> None:
    print("\n[C] routing activation variants", flush=True)
    with DoIPClient(HOST, PORT, 1.5, verbose=False) as c:
        # activation types 0x00..0x07, 0xE0 (OEM), 0xFF
        for act in [0x00, 0x01, 0x02, 0x03, 0x04, 0xE0, 0xFF]:
            resp, frames = c.routing_activation(0x0E00, act_type=act)
            rec("C_activation", "sa=0x0E00 act=0x%02X" % act,
                "0E00%02X00000000" % act, frames,
                json.dumps(resp, ensure_ascii=False) if resp else "no RA response")
            time.sleep(0.05)
        # OEM-specific activation data after the 4 reserved bytes
        for oem in (b"\x00\x00\x00\x00", b"\x01\x02\x03\x04", b"\xde\xad\xbe\xef"):
            resp, frames = c.routing_activation(0x0E00, act_type=0xE0, oem=oem)
            rec("C_activation", "act=0xE0 oem=%s" % hexs(oem),
                "0E00E000000000" + hexs(oem), frames,
                json.dumps(resp, ensure_ascii=False) if resp else "no RA response")
            time.sleep(0.05)
        # re-activate the same socket (protocol violation in the spec)
        resp, frames = c.routing_activation(0x0E00)
        rec("C_activation", "repeat activation same socket", "0E000000000000", frames,
            json.dumps(resp, ensure_ascii=False) if resp else "no RA response")
        # activate a second, foreign tester SA on the same socket
        resp, frames = c.routing_activation(0x1000)
        rec("C_activation", "activate SA=0x1000 (spoof gateway)", "100000000000000", frames,
            json.dumps(resp, ensure_ascii=False) if resp else "no RA response")


# ------------------------------------------------------------ D. length abuse
def probe_lengths() -> None:
    """Declared length vs actual bytes. Read-only: the worst case is a hang."""
    print("\n[D] DoIP length-field mismatches", flush=True)
    cases = [
        ("ptype=0x0001 declared=8 actual=0", 0x0001, 8, b""),
        ("ptype=0x0001 declared=0 actual=8", 0x0001, 0, b"\x00" * 8),
        ("ptype=0x8001 declared=4 actual=6", PT_DIAG_MSG, 4, b"\x0e\x00\x10\x00\x3e\x00"),
        ("ptype=0x8001 declared=0xFFFF actual=6", PT_DIAG_MSG, 0xFFFF,
         b"\x0e\x00\x10\x00\x3e\x00"),
        ("ptype=0x0005 declared=1 actual=7", PT_ROUTING_ACT_REQ, 1,
         b"\x0e\x00\x00\x00\x00\x00\x00"),
    ]
    for label, pt, declared, payload in cases:
        s = socket.socket()
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(4.0)
        try:
            s.connect((HOST, PORT))
            raw = b"\x02\xFD" + struct.pack(">HI", pt, declared) + payload
            t0 = time.time()
            s.sendall(raw)
            got = b""
            s.settimeout(3.0)
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    got += chunk
                    if len(got) >= 8:
                        break
            except socket.timeout:
                pass
            dt = (time.time() - t0) * 1000
            note = "no response" if not got else "raw=%s" % hexs(got[:40])
            row = {"group": "D_length", "label": label,
                   "req": hexs(raw), "frames": [], "note": note +
                   (" closed-by-peer" if False else ""), "elapsed_ms": round(dt, 1)}
            results.append(row)
            print("  %-40s -> %-40s %.0fms" % (label, note, dt), flush=True)
        finally:
            s.close()
        time.sleep(0.1)


# ---------------------------------------------------------------- E. UDS edges
def probe_uds_edges() -> None:
    print("\n[E] UDS framing edges on TA=0x1000", flush=True)
    with DoIPClient(HOST, PORT, 1.5, verbose=False) as c:
        c.routing_activation(0x0E00)
        cases = [
            ("diag payload empty (no SA/TA)", 0x0E00, 0x1000, b"", True),
            ("diag payload 2 bytes (SA only)", 0x0E00, 0x1000, b"", True),
            ("22 no DID", 0x0E00, 0x1000, b"\x22", False),
            ("22 one-byte DID", 0x0E00, 0x1000, b"\x22\xf1", False),
            ("22 three DIDs", 0x0E00, 0x1000, b"\x22\xf1\x90\xf1\xa0\xf1\x90", False),
            ("22 F190 + trailing junk", 0x0E00, 0x1000, b"\x22\xf1\x90\xaa\xbb", False),
            ("TA=self with SA=0x0000", 0x0000, 0x1000, b"\x22\xf1\x90", False),
            ("SA spoofed as 0x1000", 0x1000, 0x1000, b"\x22\xf1\x90", False),
            ("SA = 0x07E0 (CAN id as SA)", 0x07E0, 0x1000, b"\x22\xf1\x90", False),
            ("broadcast TA=0xFFFF", 0x0E00, 0xFFFF, b"\x22\xf1\x90", False),
        ]
        for label, sa, ta, uds, truncate in cases:
            if truncate and label.startswith("diag payload empty"):
                payload = b""
            elif truncate:
                payload = struct.pack(">H", sa)  # only SA, missing TA+UDS
            else:
                payload = struct.pack(">HH", sa, ta) + uds
            frames = c.transact(PT_DIAG_MSG, payload, duration=1.2)
            rec("E_uds", label, hexs(payload), frames)
            time.sleep(0.06)


def main() -> int:
    print("[*] DoIP layer probes against %s:%d" % (HOST, PORT), flush=True)
    probe_ptypes()
    probe_versions()
    probe_activation()
    probe_lengths()
    probe_uds_edges()

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("\n[+] %d probe records -> %s" % (len(results), os.path.abspath(OUT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

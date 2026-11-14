#!/usr/bin/env python3
"""Full 16-bit DoIP logical-address sweep on the CGW, pipelined.

Why pipelining: one request/response costs ~4 ms server-side; asking 65536 addresses
sequentially at 1 request per RTT would take hours. The gateway processes requests in
order on one TCP connection, answering each with exactly one 0x8001 frame, so we can
send a chunk and count the replies. Reply frames do NOT echo the requested target
address, therefore ordering + per-chunk reply count is the correctness anchor:

  * if a chunk returns exactly len(chunk) frames -> map replies positionally
  * otherwise re-probe that chunk sequentially (1 s timeout) and flag it

Read-only: UDS 3E 00 (tester present) only.

Usage:
  python full_ta_sweep.py --host 10.226.193.2 --out 03_EVIDENCE/ecu-reach/18_ta_full.json
"""
from __future__ import annotations

import argparse
import json
import select
import socket
import struct
import sys
import time
from collections import Counter
from datetime import datetime

SA = 0x0E00


def doip(ptype: int, payload: bytes) -> bytes:
    return bytes([2, 0xFD]) + struct.pack(">H", ptype) + struct.pack(">I", len(payload)) + payload


def read_frames(sock, want: int, deadline: float):
    """read up to `want` DoIP frames or until deadline; returns list[(ptype, payload)]"""
    buf = b""
    out = []
    while len(out) < want and time.time() < deadline:
        remain = deadline - time.time()
        r, _, _ = select.select([sock], [], [], min(0.2, max(0.0, remain)))
        if r:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        while len(buf) >= 8 and len(out) < want:
            ver, inv, ptype, plen = struct.unpack(">BBHI", buf[:8])
            if len(buf) < 8 + plen:
                break
            out.append((ptype, buf[8:8 + plen]))
            buf = buf[8 + plen:]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.226.193.2")
    ap.add_argument("--port", type=int, default=13400)
    ap.add_argument("--start", default="0000")
    ap.add_argument("--end", default="FFFF")
    ap.add_argument("--probe", default="3E00", help="UDS request bytes, hex")
    ap.add_argument("--chunk", type=int, default=64)
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--pause", type=float, default=0.05, help="sleep between chunks (politeness)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    lo, hi = int(a.start, 16), int(a.end, 16)
    targets = list(range(lo, hi + 1))
    res = {"host": a.host, "port": a.port, "range": [f"0x{lo:04X}", f"0x{hi:04X}"],
           "probe": a.probe.upper(), "tester_sa": f"0x{SA:04X}",
           "started": datetime.now().astimezone().isoformat(timespec="seconds"),
           "chunks": 0, "pipelined_frames": 0, "sequential_repairs": 0, "rows": []}

    s = socket.socket()
    s.settimeout(5.0)
    s.connect((a.host, a.port))
    s.sendall(doip(0x0005, struct.pack(">H", SA) + b"\x00" * 5))
    ra = read_frames(s, 1, time.time() + 5.0)
    res["routing_activation"] = ra[0][1].hex() if ra else None
    print(f"RA={res['routing_activation']}", flush=True)

    odd = []
    t0 = time.time()
    for i in range(0, len(targets), a.chunk):
        chunk = targets[i:i + a.chunk]
        tx = b"".join(doip(0x8001, struct.pack(">HH", SA, ta) + bytes.fromhex(a.probe))
                      for ta in chunk)
        s.sendall(tx)
        frames = read_frames(s, len(chunk), time.time() + max(2.0, a.timeout * 2))
        res["chunks"] += 1
        res["pipelined_frames"] += len(frames)
        if len(frames) == len(chunk):
            for ta, (ptype, payload) in zip(chunk, frames):
                res["rows"].append([ta, ptype, payload.hex()])
        else:
            # repair sequentially: one request, one reply each
            res["sequential_repairs"] += 1
            for ta in chunk:
                s2 = socket.socket(); s2.settimeout(3.0)
                try:
                    s2.connect((a.host, a.port))
                    s2.sendall(doip(0x0005, struct.pack(">H", SA) + b"\x00" * 5))
                    read_frames(s2, 1, time.time() + 3.0)
                    s2.sendall(doip(0x8001, struct.pack(">HH", SA, ta) + bytes.fromhex(a.probe)))
                    fr = read_frames(s2, 1, time.time() + a.timeout)
                    if fr:
                        res["rows"].append([ta, fr[0][0], fr[0][1].hex()])
                    else:
                        res["rows"].append([ta, None, None]); odd.append(ta)
                finally:
                    s2.close()
        if i and (i // a.chunk) % 64 == 0:
            print(f"[sweep] {i}/{len(targets)} elapsed={time.time()-t0:.1f}s "
                  f"repairs={res['sequential_repairs']}", flush=True)
        if a.pause:
            time.sleep(a.pause)
    s.close()
    res["elapsed_s"] = round(time.time() - t0, 1)
    res["replies"] = len(res["rows"])

    # classify
    classes = Counter()
    interesting = []
    for ta, ptype, hexpayload in res["rows"]:
        if hexpayload is None:
            classes["NO-REPLY"] += 1
            interesting.append([ta, "NO-REPLY", None])
            continue
        payload = bytes.fromhex(hexpayload)
        if len(payload) >= 4:
            frm, to = struct.unpack(">HH", payload[:4])
            uds = payload[4:]
            if uds[:2] == b"\x7f\x3e" and len(uds) >= 3:
                key = f"NRC31-from-0x{frm:04X}" if uds[2] == 0x31 else f"NRC{uds[2]:02X}-from-0x{frm:04X}"
            else:
                key = f"OTHER-from-0x{frm:04X}"
            classes[key] += 1
            if not (uds[:3] == b"\x7f\x3e\x31" and frm == 0x1000):
                interesting.append([ta, key, hexpayload])
        else:
            classes["SHORT"] += 1
            interesting.append([ta, "SHORT", hexpayload])
    res["classes"] = dict(classes)
    res["interesting"] = interesting
    text = json.dumps(res, ensure_ascii=False, indent=1)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    print(f"# done targets={len(targets)} replies={res['replies']} "
          f"elapsed={res['elapsed_s']}s repairs={res['sequential_repairs']}", flush=True)
    print("# classes:", dict(classes), flush=True)
    print(f"# interesting (non NRC31-from-0x1000): {len(interesting)}", flush=True)
    for row in interesting[:40]:
        print("   ", row, flush=True)


if __name__ == "__main__":
    sys.exit(main())

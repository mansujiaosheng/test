#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CGW DoIP logical-address scanner (pipelined, single routing activation).

Ground truth established 2026-11-14:
  * ONE routing activation (SA 0x0E00) is enough; diagnostic messages pipeline
    on the same socket and every reply arrives within ~100 ms.
  * The entity answers EVERY target logical address, and the reply always
    carries source address 0x1000.  So "did I get a bytes back" is NOT
    evidence that a downstream ECU exists.
  * The discriminator is the reply CONTENT:
        target 0x1000        -> 7F 3E 11   (serviceNotSupported  - handled locally)
        any other target     -> 7F 3E 31   (requestOutOfRange     - cannot route)
    A real downstream ECU would either answer from its own LA, or produce a
    positive response, or at least a different NRC.

Therefore the sweep does not map reply->target.  It counts replies by
(source_LA, uds_bytes) and flags any batch whose reply multiset deviates from
the known baseline, then re-probes that batch one address at a time so the
deviating address can be named.

Sub-commands
------------
  probe   --targets 0x07E0,0x07E8 --uds 22F190,3E00
  sweep   --start 0x0001 --end 0x0FFF
  seq     --target 0x1000 --uds "10 03" --uds "27 01"

Evidence: 03_EVIDENCE/cgw-doip/<tag>.jsonl + <tag>_summary.json
"""
import argparse
import json
import os
import socket
import struct
import sys
import time
from collections import Counter

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
EVID = os.path.join(ROOT, "03_EVIDENCE", "cgw-doip")
os.makedirs(EVID, exist_ok=True)

T_ROUTING_ACT_REQ = 0x0005
T_ROUTING_ACT_RES = 0x0006
T_DIAG_MSG = 0x8001
T_DIAG_ACK = 0x8002
T_DIAG_NAK = 0x8003

SA = 0x0E00
HOST = "10.229.221.2"
PORT = 13400

# NRC names for the summary
NRC = {0x10: "generalReject", 0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
       0x13: "incorrectMessageLength", 0x22: "conditionsNotCorrect", 0x24: "requestSequenceError",
       0x31: "requestOutOfRange", 0x33: "securityAccessDenied", 0x35: "invalidKey",
       0x37: "requiredTimeDelayNotExpired", 0x72: "generalProgrammingFailure",
       0x78: "responsePending", 0x7E: "subFunctionNotSupportedInActiveSession",
       0x7F: "serviceNotSupportedInActiveSession"}


def build(t, p=b""):
    return b"\x02\xfd" + struct.pack(">H", t) + struct.pack(">I", len(p)) + p


class Conn:
    """One TCP connection + one routing activation, driven by a resyncable RX buffer."""

    def __init__(self, host=HOST, port=PORT, sa=SA, act=0xE0, timeout=8.0, quiet=False):
        self.host, self.port, self.sa, self.act = host, port, sa, act
        self.quiet = quiet
        self.s = None
        self.buf = b""
        self.ra = None
        self.open()

    def open(self):
        if self.s:
            try:
                self.s.close()
            except Exception:
                pass
        self.buf = b""
        self.ra = None
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(20.0)
        self.s.connect((self.host, self.port))
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        pl = struct.pack(">H", self.sa) + bytes([self.act]) + b"\x00" * 4 + b"\x00" * 4
        self.s.sendall(build(T_ROUTING_ACT_REQ, pl))
        for mt, payload in self.recv_msgs(idle=1.5, deadline=12.0):
            if mt == T_ROUTING_ACT_RES:
                self.ra = payload
                break
        if not self.quiet:
            print("[*] RA ->", self.ra.hex() if self.ra else "NONE")

    def _fill(self, idle):
        self.s.settimeout(idle)
        try:
            chunk = self.s.recv(65536)
        except socket.timeout:
            return False
        except OSError:
            return False
        if not chunk:
            return False
        self.buf += chunk
        return True

    def recv_msgs(self, idle=0.6, deadline=20.0, want=None):
        """Read whole DoIP frames.  Stops when `want` replies are collected,
        on socket idle, or at deadline."""
        out = []
        end = time.time() + deadline
        while time.time() < end:
            while len(self.buf) >= 8:
                ver, inv, mt, plen = struct.unpack(">BBHI", self.buf[:8])
                if ver != 0x02 or inv != 0xFD:
                    self.buf = self.buf[1:]       # resync after framing loss
                    continue
                if len(self.buf) < 8 + plen:
                    break
                payload = self.buf[8:8 + plen]
                self.buf = self.buf[8 + plen:]
                out.append((mt, payload))
            if want is not None and len(out) >= want:
                break
            if not self._fill(idle):
                break
        return out

    def send_diag(self, target, uds):
        self.s.sendall(build(T_DIAG_MSG,
                             struct.pack(">H", self.sa) + struct.pack(">H", target) + uds))

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


def parse(mt, payload):
    """(source_la, uds_hex, kind) for a diagnostic reply, else None."""
    if mt == T_DIAG_MSG and len(payload) >= 4:
        return (struct.unpack(">H", payload[0:2])[0], payload[4:].hex(), "diag")
    if mt in (T_DIAG_ACK, T_DIAG_NAK) and len(payload) >= 5:
        return (struct.unpack(">H", payload[2:4])[0], "ACK%02X" % payload[4],
                "ack" if mt == T_DIAG_ACK else "nak")
    return None


def one_by_one(c, addrs, uds, idle):
    """Sequential probe of a small address list; returns per-address replies."""
    res = {}
    for a in addrs:
        c.send_diag(a, uds)
        msgs = c.recv_msgs(idle=idle, deadline=idle * 3, want=1)
        res[a] = [parse(mt, pl) for mt, pl in msgs]
        res[a] = [x for x in res[a] if x]
        time.sleep(0.01)
    return res


def cmd_probe(args):
    targets = [int(x, 0) for x in args.targets.split(",") if x.strip()]
    udss = [bytes.fromhex(x.replace(" ", "")) for x in args.uds.split(",") if x.strip()]
    c = Conn(args.host, args.port, act=args.act)
    rows = []
    for t in targets:
        for u in udss:
            t0 = time.time()
            c.send_diag(t, u)
            msgs = c.recv_msgs(idle=args.idle, deadline=args.idle * 3, want=1)
            got = [x for x in (parse(mt, pl) for mt, pl in msgs) if x]
            rows.append({"la": "0x%04X" % t, "req": u.hex(), "resp": got,
                         "ms": round((time.time() - t0) * 1000, 1)})
            print("  0x%04X %-12s -> %s" % (
                t, u.hex(),
                "  ".join("src=0x%04X %s%s" % (s, u2, " (" + NRC.get(int(u2[4:6], 16), "") + ")"
                                               if u2.startswith("7f") and len(u2) >= 6 else "")
                          for s, u2, _ in got) or "NO REPLY"))
    c.close()
    append_jsonl(args.tag + ".jsonl", rows)
    return rows


def cmd_sweep(args):
    start, end = args.start, args.end
    uds = bytes.fromhex(args.uds.replace(" ", ""))
    addrs = list(range(start, end + 1))
    def _parse_base(s):
        la_s, uds_s = s.split("|")
        return (int(la_s, 0), uds_s.strip().lower().replace(" ", ""))

    baseline_set = {_parse_base(x) for x in args.baseline.split(",") if x.strip()}
    baseline = sorted(baseline_set)

    c = Conn(args.host, args.port, act=args.act)
    print("[*] sweeping 0x%04X..0x%04X (%d addrs) uds=%s batch=%d rate=%.0f/s"
          % (start, end, len(addrs), uds.hex(), args.batch, args.rate))
    print("[*] baseline replies (any other reply multiset is a lead): %s" % (baseline,))

    hits, anomalies, shortfalls = [], [], []
    tally = Counter()
    t_start = time.time()
    per = 1.0 / args.rate
    i = 0
    while i < len(addrs):
        chunk = addrs[i:i + args.batch]
        try:
            for a in chunk:
                c.send_diag(a, uds)
                time.sleep(per)
            msgs = c.recv_msgs(idle=args.idle, deadline=len(chunk) * per + 4.0,
                               want=len(chunk))
        except OSError as e:
            print("  !! socket error %r - reconnecting" % (e,))
            c.open()
            i += len(chunk)
            continue
        replies = [x for x in (parse(mt, pl) for mt, pl in msgs) if x]
        tally.update(replies)
        pair = Counter((s, u) for s, u, _ in replies)

        deviated = [(s, u) for (s, u) in pair if (s, u) not in baseline_set]
        if deviated or len(replies) != len(chunk):
            # narrow down to the individual address
            detail = one_by_one(c, chunk, uds, args.idle)
            for a, got in detail.items():
                for s, u, k in got:
                    if (s, u) not in baseline_set:
                        hits.append({"la": "0x%04X" % a, "req": uds.hex(),
                                     "src": "0x%04X" % s, "resp": u, "kind": k})
                        print("  *** HIT 0x%04X -> src=0x%04X %s" % (a, s, u))
                if not got:
                    shortfalls.append({"la": "0x%04X" % a, "req": uds.hex()})
                    print("  *** NO-REPLY 0x%04X" % a)
            anomalies.append({"chunk": "0x%04X-0x%04X" % (chunk[0], chunk[-1]),
                              "replies": len(replies), "sent": len(chunk),
                              "pairs": {"0x%04X|%s" % k: v for k, v in pair.items()}})
        i += len(chunk)
        if (i // args.batch) % 8 == 0:
            print("  ... 0x%04X  %d/%d  hits=%d  %.0fs"
                  % (chunk[-1], i, len(addrs), len(hits), time.time() - t_start))

    c.close()
    summary = {
        "range": "0x%04X-0x%04X" % (start, end), "req_uds": uds.hex(),
        "tested": len(addrs), "elapsed_s": round(time.time() - t_start, 1),
        "reply_multiset": {"0x%04X|%s|%s" % (s, u, k): v for (s, u, k), v in tally.items()},
        "hits": hits, "no_reply": shortfalls, "anomalous_chunks": anomalies,
        "baseline": sorted("%04x|%s" % b for b in baseline_set),
    }
    with open(os.path.join(EVID, args.tag + "_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    append_jsonl(args.tag + ".jsonl", hits or [{"note": "no deviation from baseline"}])
    print("\n=== SWEEP SUMMARY ===")
    print(json.dumps({k: v for k, v in summary.items() if k != "anomalous_chunks"},
                     ensure_ascii=False, indent=2))
    if anomalies:
        print("[!] %d anomalous chunks (see _summary.json)" % len(anomalies))
    return summary


def cmd_seq(args):
    target = args.target
    c = Conn(args.host, args.port, act=args.act)
    rows = []
    for u in args.uds:
        raw = bytes.fromhex(u.replace(" ", ""))
        t0 = time.time()
        c.send_diag(target, raw)
        msgs = c.recv_msgs(idle=args.idle, deadline=args.idle * 4, want=1)
        got = [x for x in (parse(mt, pl) for mt, pl in msgs) if x]
        rows.append({"cmd": raw.hex(), "target": "0x%04X" % target, "resp": got,
                     "ms": round((time.time() - t0) * 1000, 1)})
        print("  %-14s -> %s" % (raw.hex(), "  ".join(
            "src=0x%04X %s" % (s, u2) for s, u2, _ in got) or "NO REPLY"))
        time.sleep(args.gap)
    c.close()
    append_jsonl(args.tag + ".jsonl", rows)
    return rows


def append_jsonl(name, rows):
    path = os.path.join(EVID, name)
    with open(path, "a", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")
    print("[evidence] %s (+%d)" % (path, len(rows)))


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--act", type=lambda x: int(x, 0), default=0xE0)
    ap.add_argument("--idle", type=float, default=0.6)
    ap.add_argument("--gap", type=float, default=0.05)
    ap.add_argument("--tag", default="scan")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("probe")
    p.add_argument("--targets", required=True)
    p.add_argument("--uds", default="22F190")
    p.set_defaults(fn=cmd_probe)

    s = sub.add_parser("sweep")
    s.add_argument("--start", type=lambda x: int(x, 0), required=True)
    s.add_argument("--end", type=lambda x: int(x, 0), required=True)
    s.add_argument("--uds", default="3E00")
    s.add_argument("--batch", type=int, default=20)
    s.add_argument("--rate", type=float, default=40.0)
    s.add_argument("--baseline", default="0x1000|7f3e31,0x1000|7f3e11")
    s.set_defaults(fn=cmd_sweep)

    q = sub.add_parser("seq")
    q.add_argument("--target", type=lambda x: int(x, 0), default=0x1000)
    q.add_argument("--uds", action="append", required=True)
    q.set_defaults(fn=cmd_seq)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

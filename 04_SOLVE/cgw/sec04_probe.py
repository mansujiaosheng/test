#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Task 04 probe: DoIP routing-activation surface + LA discovery + SecurityAccess.

Sub-commands
------------
  ra       routing activation matrix (activation type 0x00..0xFF, OEM ticket payloads)
  la       logical-address sweep, liveness oracle = 3E00 -> 7E00 (positive)
  uds      targeted UDS probe against a discovered LA (10 03 / 27 01)

Writes: 03_EVIDENCE/cgw/sec04/  (one jsonl + numbered json per interesting event)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import select
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVID = ROOT / "03_EVIDENCE" / "cgw" / "sec04"
EVID.mkdir(parents=True, exist_ok=True)

PT_ROUTING_REQ = 0x0005
PT_ROUTING_RSP = 0x0006
PT_DIAG = 0x8001
PT_ACK = 0x8002
PT_NACK = 0x8003
PT_VEH_ID = 0x0001

RA_CODES = {
    0x00: "denied: unknown source address",
    0x01: "denied: all sockets registered to other SAs",
    0x02: "denied: SA differs from activated socket",
    0x03: "denied: SA already registered on another socket",
    0x04: "denied: missing authentication",
    0x05: "denied: rejected confirmation",
    0x06: "denied: unsupported routing activation type",
    0x07: "denied: TLS required",
    0x10: "OK: routing successfully activated",
    0x11: "OK: routing will be activated, confirmation required",
}
NRC = {
    0x10: "generalReject", 0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
    0x13: "incorrectLength", 0x21: "busyRepeatRequest", 0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError", 0x31: "requestOutOfRange", 0x33: "securityAccessDenied",
    0x35: "invalidKey", 0x36: "exceedNumberOfAttempts", 0x37: "delayNotExpired",
    0x7E: "subFuncNotSupportedInActiveSession", 0x7F: "serviceNotSupportedInActiveSession",
}


def hx(b: bytes) -> str:
    return b.hex().upper()


def ts() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


class Conn:
    def __init__(self, host: str, port: int, timeout: float = 3.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b""

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass

    def send(self, ptype: int, payload: bytes) -> None:
        self.s.sendall(bytes([0x02, 0xFD]) + struct.pack(">H", ptype) +
                       struct.pack(">I", len(payload)) + payload)

    def recv(self, timeout: float = 2.0):
        end = time.time() + timeout
        while True:
            if len(self.buf) >= 8:
                ver, inv, ptype, plen = struct.unpack(">BBHI", self.buf[:8])
                if len(self.buf) >= 8 + plen:
                    payload = self.buf[8:8 + plen]
                    self.buf = self.buf[8 + plen:]
                    return ptype, payload
            rem = end - time.time()
            if rem <= 0:
                return None
            r, _, _ = select.select([self.s], [], [], rem)
            if not r:
                return None
            chunk = self.s.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk

    def drain(self, quiet: float = 0.25, total: float = 3.0):
        frames = []
        end = time.time() + total
        while time.time() < end:
            f = self.recv(min(quiet, max(0.01, end - time.time())))
            if f is None:
                break
            frames.append(f)
        return frames


def log(path: Path, rec: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# --------------------------------------------------------------- routing activation
def ra_request(sa: int, act: int, oem: bytes = b"\x00\x00\x00\x00") -> bytes:
    return struct.pack(">H", sa) + bytes([act]) + oem


def try_ra(host, port, sa, act, oem, timeout=2.5):
    c = None
    rec = {"label": "ra", "ts": ts(), "sa": f"0x{sa:04X}", "act": f"0x{act:02X}",
           "oem": hx(oem), "req": hx(ra_request(sa, act, oem))}
    try:
        c = Conn(host, port, timeout)
        c.send(PT_ROUTING_REQ, ra_request(sa, act, oem))
        frames = c.drain()
        rec["frames"] = [{"ptype": f"0x{p:04X}", "hex": hx(d)} for p, d in frames]
        parsed = []
        for p, d in frames:
            if p == PT_ROUTING_RSP and len(d) >= 5:
                rsa = struct.unpack(">H", d[0:2])[0]
                ela = struct.unpack(">H", d[2:4])[0]
                code = d[4]
                parsed.append({"sa": f"0x{rsa:04X}", "entity_la": f"0x{ela:04X}",
                               "code": f"0x{code:02X}",
                               "text": RA_CODES.get(code, "?"),
                               "trailing": hx(d[5:])})
        rec["parsed"] = parsed
    except Exception as e:  # noqa: BLE001
        rec["error"] = repr(e)
    finally:
        if c:
            c.close()
    return rec


def cmd_ra(args):
    out = EVID / "ra_matrix.jsonl"
    open(out, "w").close()
    results = {}
    acts = list(range(0x00, 0x100)) if args.full else [0x00, 0x01, 0x02, 0x03, 0x04, 0xE0, 0xE1, 0xE2]
    oems = [b"\x00\x00\x00\x00"]
    if args.tickets:
        for t in args.tickets:
            oems.append(bytes.fromhex(t))
    for act in acts:
        for oem in oems:
            rec = try_ra(args.host, args.port, args.sa, act, oem)
            log(out, rec)
            key = (act, hx(oem))
            ps = rec.get("parsed") or []
            code = ps[0]["code"] if ps else (rec.get("error") or "none")
            results[key] = code
            print(f"act=0x{act:02X} oem={hx(oem):8s} -> {code} "
                  f"{(ps[0]['text'] if ps else '')}", flush=True)
    # summary
    summary = {}
    for (act, oem), code in results.items():
        summary.setdefault(code, []).append({"act": f"0x{act:02X}", "oem": oem})
    (EVID / "ra_matrix_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    print("\n=== summary by code ===")
    for code, items in summary.items():
        acts = sorted({i["act"] for i in items})
        print(f"{code}: {len(items)} combos, acts={acts[:20]}")
    return 0


# --------------------------------------------------------------- LA sweep
def probe_la(host, port, sa, la, uds: bytes, timeout=1.6):
    c = None
    t0 = time.time()
    try:
        c = Conn(host, port, timeout)
        c.send(PT_ROUTING_REQ, ra_request(sa, 0x00))
        fr = c.drain(quiet=0.15, total=1.5)
        if not fr:
            return {"la": f"0x{la:04X}", "err": "no RA response"}
        c.send(PT_DIAG, struct.pack(">HH", sa, la) + uds)
        frames = c.drain(quiet=0.20, total=timeout)
        resp = []
        for p, d in frames:
            if p == PT_DIAG and len(d) >= 4:
                src = struct.unpack(">H", d[0:2])[0]
                dst = struct.unpack(">H", d[2:4])[0]
                resp.append({"src": f"0x{src:04X}", "dst": f"0x{dst:04X}",
                             "uds": hx(d[4:])})
            elif p == PT_NACK:
                resp.append({"nack": hx(d)})
            elif p == PT_ACK:
                resp.append({"ack": hx(d)})
        return {"la": f"0x{la:04X}", "resp": resp, "ms": round((time.time()-t0)*1000, 1)}
    except Exception as e:  # noqa: BLE001
        return {"la": f"0x{la:04X}", "err": repr(e)}
    finally:
        if c:
            c.close()


def classify(resp: list):
    """-> (kind, uds_hex)"""
    for r in resp or []:
        u = r.get("uds")
        if not u:
            continue
        if u.startswith("7F") and len(u) >= 6:
            return ("nrc", u)
        if u.startswith("7E") or not u.startswith("7F"):
            return ("pos", u)
    return ("none", "")


def cmd_la(args):
    out = EVID / f"la_sweep_{args.start:04X}_{args.end:04X}.jsonl"
    open(out, "w").close()
    uds = bytes.fromhex(args.uds)
    sas = [args.sa + i for i in range(args.workers)]
    hits = []
    t0 = time.time()
    done = 0

    def work(job):
        idx, la = job
        return probe_la(args.host, args.port, sas[idx % len(sas)], la, uds, args.timeout)

    jobs = [(i, la) for i, la in enumerate(range(args.start, args.end + 1))]
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for rec in ex.map(work, jobs):
            done += 1
            kind, u = classify(rec.get("resp"))
            rec["kind"] = kind
            rec["uds"] = u
            if kind != "nrc" or not u.startswith("7F311"):
                log(out, rec)
                if kind == "pos" or (kind == "nrc" and not u.startswith("7F" + args.uds[:2].upper() + "31")):
                    hits.append(rec)
                    print(f"[{kind}] {rec['la']} uds={u} {rec}", flush=True)
            if done % 200 == 0:
                el = time.time() - t0
                print(f"  ... {done}/{len(jobs)} {el:.0f}s {done/el:.1f}/s", flush=True)
    el = time.time() - t0
    print(f"\n[done] {done} LAs in {el:.0f}s ({done/el:.1f}/s), hits={len(hits)}")
    (EVID / f"la_sweep_{args.start:04X}_{args.end:04X}_hits.json").write_text(
        json.dumps(hits, indent=2), encoding="utf-8")
    for h in hits:
        print("  HIT", h["la"], h.get("kind"), h.get("uds"))
    return 0


# --------------------------------------------------------------- targeted uds
def cmd_uds(args):
    out = EVID / "uds_targeted.jsonl"
    for la in args.las:
        for svc in args.services:
            uds = bytes.fromhex(svc)
            rec = probe_la(args.host, args.port, args.sa, int(la, 16), uds, args.timeout)
            rec["svc"] = svc
            rec["ts"] = ts()
            log(out, rec)
            kind, u = classify(rec.get("resp"))
            print(f"{la} {svc:8s} -> {kind} {u}", flush=True)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["ra", "la", "uds"])
    ap.add_argument("--host", default="10.229.221.2")
    ap.add_argument("--port", type=int, default=13400)
    ap.add_argument("--sa", type=lambda x: int(x, 16), default=0x0E00)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--timeout", type=float, default=1.6)
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--tickets", nargs="*", default=None)
    ap.add_argument("--start", type=lambda x: int(x, 16), default=0x1000)
    ap.add_argument("--end", type=lambda x: int(x, 16), default=0x10FF)
    ap.add_argument("--uds", default="3E00")
    ap.add_argument("--las", nargs="*", default=[])
    ap.add_argument("--services", nargs="*",
                    default=["1003", "1002", "2701", "2703", "22F190", "1902FF"])
    args = ap.parse_args()
    return {"ra": cmd_ra, "la": cmd_la, "uds": cmd_uds}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

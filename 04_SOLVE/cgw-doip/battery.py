#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UDS service batteries against the CGW DoIP entity (target LA 0x1000).

Each battery is a scripted sequence of UDS requests on ONE connection with ONE
routing activation.  Every request/reply pair goes to
03_EVIDENCE/cgw-doip/<tag>.jsonl, and any reply that is not a plain negative
response is echoed loudly.

Batteries
---------
  session   10 01/02/03/04  -- which sessions are accepted
  sec27     27 01..7F in default AND in extended  -- look for a seed
  mem       23 ReadMemoryByAddress: ALFID x size format discovery, then dump
  routine   31 01/02/03 across a routine-id candidate list
  dl        34/36/37 RequestDownload support probe (support only, no real flash)
  io        2E / 2F support probe (probe only, no real write)
  dtc       19 01/02/0A/04/06, 14
  did       22 DID sweep over several ID spaces

Usage
  python battery.py session
  python battery.py sec27 --target 0x1000
  python battery.py mem --start 0x0 --len 0x100
"""
import argparse
import json
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scan_la as S

NRC = S.NRC


def describe(got):
    if not got:
        return "NO REPLY"
    out = []
    for src, uds, kind in got:
        if uds.startswith("7f") and len(uds) >= 6:
            code = int(uds[4:6], 16)
            out.append("src=0x%04X NRC 0x%02X %s" % (src, code, NRC.get(code, "?")))
        else:
            out.append("src=0x%04X %s" % (src, uds))
    return "  ".join(out)


def ask(c, target, uds, idle=0.6, pending_max=12.0):
    """Send one UDS request; absorb NRC 0x78 until the final answer."""
    c.send_diag(target, uds)
    got, deadline = [], time.time() + pending_max
    while time.time() < deadline:
        msgs = c.recv_msgs(idle=idle, deadline=idle * 2 + 0.2, want=1)
        got += [x for x in (S.parse(mt, pl) for mt, pl in msgs) if x]
        if not got:
            break
        last = got[-1][1]
        if last.startswith("7f") and len(last) >= 6 and int(last[4:6], 16) == 0x78:
            time.sleep(0.2)
            continue
        break
    return got


def run_seq(c, target, steps, tag, gap=0.05):
    rows = []
    for raw in steps:
        t0 = time.time()
        got = ask(c, target, raw)
        rows.append({"target": "0x%04X" % target, "req": raw.hex(), "resp": got,
                     "ms": round((time.time() - t0) * 1000, 1)})
        print("  %-24s -> %s" % (raw.hex(), describe(got)))
        # hard delay handling
        for _s, u, _k in got:
            if u.startswith("7f") and len(u) >= 6 and int(u[4:6], 16) == 0x37:
                print("      (NRC 0x37 rate limit - sleeping 6s)")
                time.sleep(6.0)
        time.sleep(gap)
    S.append_jsonl(tag + ".jsonl", rows)
    return rows


# ---------------------------------------------------------------- batteries
def b_session(c, a):
    print("[session] session control 10 01..04 on target 0x%04X" % a.target)
    return run_seq(c, a.target, [bytes.fromhex("10%02x" % s) for s in (1, 2, 3, 4)],
                   "E-session")


def b_sec27(c, a):
    subs = list(range(0x01, 0x80))
    rows = []
    for sess_name, pre in (("default", None), ("extended", bytes.fromhex("1003"))):
        print("\n[sec27] === session=%s ===" % sess_name)
        if pre:
            got = ask(c, a.target, pre)
            print("  10 03 ->", describe(got))
            rows.append({"target": "0x%04X" % a.target, "req": pre.hex(), "resp": got})
            if not any(u[:2] == "50" for _s, u, _k in got):
                print("  !! could not enter extended session")
        for sub in subs:
            raw = bytes([0x27, sub])
            got = ask(c, a.target, raw)
            rows.append({"target": "0x%04X" % a.target, "req": raw.hex(), "resp": got})
            u = got[-1][1] if got else ""
            interesting = (u.startswith("67") or
                           (u.startswith("7f") and sz not in (0x11,) and
                            int(u[4:6], 16) not in (0x11,)))
            plain_unsupported = u.startswith("7f") and len(u) >= 6 and int(u[4:6], 16) == 0x11
            if not plain_unsupported:
                print("  27 %02X -> %s" % (sub, describe(got)))
            for _s, uu, _k in got:
                if uu.startswith("7f") and len(uu) >= 6 and int(uu[4:6], 16) == 0x37:
                    print("      (NRC 0x37 - sleeping 6s)")
                    time.sleep(6.0)
            time.sleep(0.03)
    S.append_jsonl("E-sec27.jsonl", rows)
    seeds = [r for r in rows if any(u.startswith("67") for _s, u, _k in r["resp"])]
    print("\n[sec27] === SEEDS FOUND: %d ===" % len(seeds))
    for r in seeds:
        print("   req=%s -> %s" % (r["req"], describe(r["resp"])))
    nonsup = sum(1 for r in rows if any(u == "7f2711" for _s, u, _k in r["resp"]))
    print("[sec27] plain serviceNotSupported(0x11) count: %d / %d" % (nonsup, len(rows)))
    return rows


def b_mem(c, a):
    """Discover which ALFID/size combination 0x23 accepts, then optionally dump."""
    print("[mem] entering extended session")
    print("  10 03 ->", describe(ask(c, a.target, bytes.fromhex("1003"))))
    rows = []
    # ALFID 0x14 = addr 1B/len 1B, 0x24 = 2B/1B, 0x34 = 3B/1B, 0x44 = 4B/1B
    # Also try addr/len both wide: 0x24 with 2B len is non-standard, so we test
    # the canonical ISO-14229 ALFID table plus a few "both 4 byte" guesses.
    addr = a.start
    length = a.length
    formats = []
    for alfid, alen in ((0x14, 1), (0x24, 2), (0x34, 3), (0x44, 4)):
        # addr alen bytes, length 1 or 2 bytes (try 1 first then 2)
        for lenlen in (1, 2):
            formats.append((alfid, alen, lenlen))
    for alfid, alen, lenlen in formats:
        raw = bytes([0x23, alfid]) + addr.to_bytes(alen, "big") + length.to_bytes(lenlen, "big")
        got = ask(c, a.target, raw)
        u = got[-1][1] if got else ""
        verdict = "?"
        if u.startswith("63"):
            verdict = "ACCEPTED"
        elif u.startswith("7f23"):
            verdict = "NRC " + NRC.get(int(u[4:6], 16), "?")
        elif not u:
            verdict = "NO REPLY"
        rows.append({"req": raw.hex(), "resp": got, "alfid": "0x%02X" % alfid,
                     "addr_len": alen, "len_len": lenlen, "verdict": verdict})
        print("  23 alfid=0x%02X addr=%dB len=%dB -> %-10s %s"
              % (alfid, alen, lenlen, verdict, u[:80]))
    S.append_jsonl("E-mem-format.jsonl", rows)
    ok = [r for r in rows if r["verdict"] == "ACCEPTED"]
    print("\n[mem] accepted formats: %s" % ([r["req"][:6] for r in ok] or "NONE"))
    return rows


def b_memdump(c, a):
    """Dump memory in 256-byte windows once a working format is known."""
    alfid = a.alfid
    alen = a.alen
    lenlen = a.lenlen
    print("[memdump] alfid=0x%02X addr=%dB len=%dB  range 0x%08X..0x%08X step 0x%X size 0x%X"
          % (alfid, alen, lenlen, a.start, a.end, a.step, a.chunk))
    rows, blob = [], bytearray()
    addr = a.start
    needle_hits = []
    while addr < a.end:
        raw = bytes([0x23, alfid]) + addr.to_bytes(alen, "big") + a.chunk.to_bytes(lenlen, "big")
        got = ask(c, a.target, raw, idle=0.5)
        u = got[-1][1] if got else ""
        if u.startswith("63"):
            data = bytes.fromhex(u[4:]) if not (len(u) > 3 and int(u[2:4], 16) == 0x23) else bytes.fromhex(u[6:])
            blob += data
            rows.append({"addr": "0x%08X" % addr, "len": len(data), "hex": data.hex()})
            low = data.lower()
            for pat in (b"cv6", b"-----begin", b"bms", b"vcu", b"rv32", b"\x30\x82", b"ecdsa", b"rsa"):
                if pat in low:
                    needle_hits.append({"addr": "0x%08X" % addr, "pattern": pat.decode("latin1")})
                    print("  *** NEEDLE %r at 0x%08X" % (pat, addr))
        elif u.startswith("7f23"):
            rows.append({"addr": "0x%08X" % addr, "nrc": u})
        else:
            rows.append({"addr": "0x%08X" % addr, "resp": "none"})
        addr += a.step
        if len(rows) % 32 == 0:
            print("  ... 0x%08X  collected %d bytes" % (addr, len(blob)))
    out = os.path.join(S.EVID, "memdump_%08x_%08x.bin" % (a.start, a.end))
    with open(out, "wb") as f:
        f.write(blob)
    S.append_jsonl("E-memdump.jsonl", rows)
    print("[memdump] wrote %s (%d bytes); needles=%s" % (out, len(blob), needle_hits))
    return rows


def b_routine(c, a):
    ids = [0xFF00, 0xFF01, 0xFF02, 0x0202, 0x0203, 0xDF01, 0xDE01, 0x0101,
           0xF001, 0xF002, 0x0001, 0x0002, 0x0003, 0xE001, 0xE002, 0xE003]
    print("[routine] 31 sub 01/02/03 over %d routine ids" % len(ids))
    print("  10 03 ->", describe(ask(c, a.target, bytes.fromhex("1003"))))
    rows = []
    for rid in ids:
        for sub in (1, 2, 3):
            raw = bytes([0x31, sub]) + struct.pack(">H", rid)
            got = ask(c, a.target, raw)
            rows.append({"req": raw.hex(), "resp": got, "rid": "0x%04X" % rid, "sub": sub})
            u = got[-1][1] if got else ""
            if not (u.startswith("7f") and len(u) >= 6 and int(u[4:6], 16) in (0x11, 0x12, 0x31)):
                print("  31 %02X %04X -> %s" % (sub, rid, describe(got)))
            elif u.startswith("71"):
                print("  31 %02X %04X -> POSITIVE %s" % (sub, rid, u))
            time.sleep(0.04)
    S.append_jsonl("E-routine.jsonl", rows)
    pos = [r for r in rows if r["resp"] and r["resp"][-1][1].startswith("71")]
    print("[routine] positive=%d  nrc kinds=%s" % (
        len(pos), sorted({(r["resp"][-1][1][4:6] if r["resp"] and r["resp"][-1][1].startswith("7f") else "none")
                          for r in rows})))
    return rows


def b_dl(c, a):
    """Support probe only: no erase, no real transfer into a live partition."""
    print("[dl] RequestDownload support probe (no flash)")
    print("  10 03 ->", describe(ask(c, a.target, bytes.fromhex("1003"))))
    print("  10 02 ->", describe(ask(c, a.target, bytes.fromhex("1002"))))
    rows = []
    for dfi in (0x00, 0x04, 0x01):
        for alfid, alen, lenlen in ((0x44, 4, 4), (0x34, 3, 3), (0x24, 2, 2)):
            raw = (bytes([0x34, dfi, alfid])
                   + a.addr.to_bytes(alen, "big") + a.size.to_bytes(lenlen, "big"))
            got = ask(c, a.target, raw)
            rows.append({"req": raw.hex(), "resp": got, "dfi": "0x%02X" % dfi})
            print("  34 dfi=0x%02X alfid=0x%02X a=%dB l=%dB -> %s"
                  % (dfi, alfid, alen, lenlen, describe(got)))
            time.sleep(0.05)
    # 36/37 with a bogus block to see whether sequence error fires (0x24)
    for raw in (bytes.fromhex("3601" + "00" * 8), bytes.fromhex("37")):
        got = ask(c, a.target, raw)
        rows.append({"req": raw.hex(), "resp": got})
        print("  %-20s -> %s" % (raw.hex(), describe(got)))
    S.append_jsonl("E-dl.jsonl", rows)
    return rows


def b_io(c, a):
    print("[io] 2E / 2F support probe (no real write)")
    print("  10 03 ->", describe(ask(c, a.target, bytes.fromhex("1003"))))
    rows = []
    for did in (0xF190, 0xF1A0, 0x0100, 0x0200):
        raw = bytes([0x2E]) + struct.pack(">H", did) + b"\x00" * 4
        got = ask(c, a.target, raw)
        rows.append({"req": raw.hex(), "resp": got})
        print("  2E %04X -> %s" % (did, describe(got)))
    for did in (0xF190, 0x0100):
        raw = bytes([0x2F]) + struct.pack(">H", did) + bytes([0x03])
        got = ask(c, a.target, raw)
        rows.append({"req": raw.hex(), "resp": got})
        print("  2F %04X -> %s" % (did, describe(got)))
    S.append_jsonl("E-io.jsonl", rows)
    return rows


def b_dtc(c, a):
    print("[dtc] 19 / 14")
    print("  10 03 ->", describe(ask(c, a.target, bytes.fromhex("1003"))))
    rows = run_seq(c, a.target, [bytes.fromhex(x) for x in
                                 ("1901", "1902", "1904", "1906", "190A", "14FFFFFF")],
                   "E-dtc")
    return rows


def b_did(c, a):
    spaces = []
    for lo, hi in (a.spaces or "F100-F1FF,0100-01FF,D100-D1FF,0001-00FF"):
        pass
    print("[did] sweeping DID spaces: %s" % a.spaces)
    print("  10 03 ->", describe(ask(c, a.target, bytes.fromhex("1003"))))
    rows, pos = [], []
    for part in a.spaces.split(","):
        lo_s, hi_s = part.split("-")
        lo, hi = int(lo_s, 0), int(hi_s, 0)
        print(" -- space 0x%04X-0x%04X (%d)" % (lo, hi, hi - lo + 1))
        for did in range(lo, hi + 1):
            raw = bytes([0x22]) + struct.pack(">H", did)
            got = ask(c, a.target, raw, idle=0.45)
            u = got[-1][1] if got else ""
            bad = (not got) or (u.startswith("7f") and len(u) >= 6 and int(u[4:6], 16) in (0x11, 0x31, 0x12))
            if not bad:
                rows.append({"did": "0x%04X" % did, "req": raw.hex(), "resp": got})
                print("  *** 22 %04X -> %s" % (did, describe(got)))
                if u.startswith("62"):
                    pos.append({"did": "0x%04X" % did, "value": u[6:]})
            time.sleep(0.02)
        S.append_jsonl("E-did.jsonl", rows[-8:] if rows else [])
    print("\n[did] positive DIDs: %d" % len(pos))
    for p in pos:
        print("   %s = %s" % (p["did"], p["value"]))
    return rows


BATTERIES = {"session": b_session, "sec27": b_sec27, "mem": b_mem, "memdump": b_memdump,
             "routine": b_routine, "dl": b_dl, "io": b_io, "dtc": b_dtc, "did": b_did}


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("battery", choices=sorted(BATTERIES))
    ap.add_argument("--target", type=lambda x: int(x, 0), default=0x1000)
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--end", type=lambda x: int(x, 0), default=0x200000)
    ap.add_argument("--addr", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--len", dest="length", type=lambda x: int(x, 0), default=0x100)
    ap.add_argument("--size", type=lambda x: int(x, 0), default=0x100)
    ap.add_argument("--step", type=lambda x: int(x, 0), default=0x1000)
    ap.add_argument("--chunk", type=lambda x: int(x, 0), default=0x100)
    ap.add_argument("--alfid", type=lambda x: int(x, 0), default=0x44)
    ap.add_argument("--alen", type=int, default=4)
    ap.add_argument("--lenlen", type=int, default=1)
    ap.add_argument("--spaces", default="F100-F1FF,0100-01FF,D100-D1FF,0001-00FF")
    a = ap.parse_args(argv)
    c = S.Conn()
    try:
        return BATTERIES[a.battery](c, a)
    finally:
        c.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

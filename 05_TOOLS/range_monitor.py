#!/usr/bin/env python3
"""Range state monitor for the CyberCar CTF workspace.

Polls the few known endpoints and records *transitions* only, so that
"the stub turned into a real GraphQL" or "a module host came up" is
detectable without babysitting.

Output: 03_EVIDENCE/monitor/state.jsonl  (one JSON line per transition,
        plus one baseline line at start).  Also prints ALERT lines to stdout.

Usage: python 05_TOOLS/range_monitor.py [--interval 40] [--iterations 90]
"""
import argparse
import hashlib
import json
import socket
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "03_EVIDENCE" / "monitor"

HTTP_TARGETS = {
    "tsp":    ("http://10.230.164.2:8080", "/graphql"),
    "tbox":   ("http://10.230.164.3:8080", "/graphql"),
    "gw164":  ("http://10.230.164.4:8080", "/graphql"),
    "cgw":    ("http://10.229.221.2:8080", "/graphql"),
}
TCP_TARGETS = [("10.224.139.5", 8080), ("10.224.139.6", 8080), ("10.224.139.7", 8080)]


def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def probe_http(base, path):
    body = json.dumps({"query": "{ __typename }"}).encode()
    req = urllib.request.Request(base + path, data=body,
                                 headers={"Content-Type": "application/json",
                                          "Connection": "close"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            raw = r.read(2048)
            return {"status": r.status,
                    "sha256_16": hashlib.sha256(raw).hexdigest()[:16],
                    "len": len(raw),
                    "head": raw[:120].decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        raw = e.read(512)
        return {"status": e.code,
                "sha256_16": hashlib.sha256(raw).hexdigest()[:16],
                "len": len(raw),
                "head": raw[:120].decode("utf-8", "replace")}
    except Exception as e:
        return {"status": "ERR", "err": type(e).__name__}


def probe_tcp(host, port, timeout=3.0):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return "OPEN"
    except socket.timeout:
        return "TIMEOUT"
    except ConnectionRefusedError:
        return "REFUSED"
    except Exception as e:
        return type(e).__name__
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=40)
    ap.add_argument("--iterations", type=int, default=90)
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    log = OUT / "state.jsonl"

    prev = {}
    for it in range(a.iterations):
        rec = {"ts": now(), "iter": it, "http": {}, "tcp": {}}
        for name, (base, path) in HTTP_TARGETS.items():
            rec["http"][name] = probe_http(base, path)
        for host, port in TCP_TARGETS:
            rec["tcp"][f"{host}:{port}"] = probe_tcp(host, port)

        # transition detection on the full fingerprint
        fp = json.dumps({"h": {k: (v.get("status"), v.get("sha256_16")) for k, v in rec["http"].items()},
                         "t": rec["tcp"]}, sort_keys=True)
        changed = prev.get("fp") != fp
        if changed:
            rec["changed"] = True
            if prev:
                print(f"[ALERT {rec['ts']}] state changed:\n  was {prev['fp']}\n  now {fp}", flush=True)
            else:
                print(f"[baseline {rec['ts']}] {fp}", flush=True)
            with log.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            prev = {"fp": fp}
        else:
            rec["changed"] = False
        time.sleep(a.interval)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_all.py -- re-run every canfd self-test and regenerate the evidence.

    python run_all.py                 # all four modules, evidence to 03_EVIDENCE/canfd
    python run_all.py --only isotp    # a single module
    python run_all.py --no-evidence   # just the pass/fail summary

Exit code is 0 only if every selected module passes every check.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
EVIDENCE = os.path.join(ROOT, "03_EVIDENCE", "canfd")

MODULES = ("isotp", "secoc", "bms_dump", "tap13401")


def run_one(name: str, evidence: bool) -> tuple:
    cmd = [sys.executable, os.path.join(HERE, f"{name}.py"), "--self-test"]
    if evidence:
        cmd += ["--evidence-dir", EVIDENCE]
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=HERE,
                          timeout=600)
    dt = time.perf_counter() - t0
    tail = ""
    for line in proc.stdout.splitlines():
        if line.startswith("RESULT:"):
            tail = line.strip()
    if not tail:
        tail = (proc.stderr.strip().splitlines() or ["no RESULT line"])[-1]
    return name, proc.returncode, tail, dt


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None,
                    help=f"one of {', '.join(MODULES)}")
    ap.add_argument("--no-evidence", action="store_true")
    args = ap.parse_args(argv)
    names = [args.only] if args.only else list(MODULES)
    for n in names:
        if n not in MODULES:
            raise SystemExit(f"unknown module {n!r}; pick from {MODULES}")
    if not args.no_evidence:
        os.makedirs(EVIDENCE, exist_ok=True)
    print("=" * 78)
    print(f"canfd self-test suite  ({time.strftime('%Y-%m-%d %H:%M:%S')})")
    print(f"evidence dir: {EVIDENCE if not args.no_evidence else '(disabled)'}")
    print("=" * 78)
    rows = []
    for name in names:
        nm, rc, tail, dt = run_one(name, not args.no_evidence)
        rows.append((nm, rc, tail, dt))
        print(f"  {nm:<10} rc={rc}  {dt:6.1f}s  {tail}")
    ok = all(rc == 0 for _, rc, _, _ in rows)
    print("-" * 78)
    print(f"SUITE: {'ALL PASS' if ok else 'FAILURES'} "
          f"({sum(1 for _, rc, _, _ in rows if rc == 0)}/{len(rows)} modules)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

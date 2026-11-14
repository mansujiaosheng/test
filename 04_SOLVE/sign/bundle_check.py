#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage K: does the bundle's VCU reference change per download, and does the
sign handler read anything outside variables?

Uses one keep-alive Session (a 16 k burst exhausted the local ephemeral port
range).
"""
import base64, hashlib, io, json, os, time, zipfile
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.abspath(os.path.join(HERE, "..", "..", "03_EVIDENCE", "sign"))
CRED = "5e7f07b4a81153ecd5868cc02557f823"
VIN = "CV622697F82A936A1"
CAMP = "CAMP-243892C376D4CB2D5F826953"
PKG = "3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0"
TB = "http://10.225.139.3:8080"
TSP = "http://10.225.139.2:8080/graphql"
GUEST = '{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'

s = requests.Session()
s.auth = ("diag", CRED)


def dump_bundles(n=3):
    out = []
    for i in range(n):
        r = s.get(TB + "/api/v1/ota/engineering-bundle", timeout=20)
        z = zipfile.ZipFile(io.BytesIO(r.content))
        vcu = z.read("vcu-reference.bin")
        man = json.loads(z.read("manifest.json"))
        ca = z.read("diagnostics/ca.pem")
        cl = z.read("diagnostics/client.pem")
        out.append({
            "i": i,
            "zip_sha": hashlib.sha256(r.content).hexdigest()[:16],
            "vcu_sha": hashlib.sha256(vcu).hexdigest(),
            "vcu_first32": vcu[:32].hex(),
            "nonce": man.get("nonce"),
            "ca_sha": hashlib.sha256(ca).hexdigest()[:16],
            "client_sha": hashlib.sha256(cl).hexdigest()[:16],
            "manifest": man,
        })
        print(f"  [{i}] vcu_sha={out[-1]['vcu_sha'][:32]} nonce={man.get('nonce')} "
              f"zip={out[-1]['zip_sha']} client={out[-1]['client_sha']}")
    return out


def gql(body, note=""):
    r = s.post(TSP, json=body, timeout=12)
    return r.status_code, r.text.strip()


def main():
    print("=== A. bundle stability (3 downloads) ===")
    b = dump_bundles(3)
    json.dump(b, open(os.path.join(EV, "K_bundle_stability.json"), "w"), indent=1)
    same = len({x["vcu_sha"] for x in b}) == 1
    print(f"[*] vcu-reference identical across downloads: {same}")
    print(f"[*] manifest identical: {len({json.dumps(x['manifest'], sort_keys=True) for x in b}) == 1}")
    print(f"[*] client cert identical: {len({x['client_sha'] for x in b}) == 1}")

    print("\n=== B. does the handler read top-level body keys? ===")
    FW = open(os.path.join(HERE, "..", "..", "work", "bundle2", "x", "vcu-reference.bin"), "rb").read()
    SHA = hashlib.sha256(FW).hexdigest()
    B64 = base64.b64encode(FW).decode()
    bodies = [
        {"query": "signFirmwareUpdate", "variables": {"vin": VIN}, "campaignId": CAMP},
        {"query": "signFirmwareUpdate", "variables": {"vin": VIN}, "campaign": CAMP},
        {"query": "signFirmwareUpdate", "variables": {"vin": VIN}, "rollback": 2},
        {"query": "signFirmwareUpdate", "variables": {"vin": VIN},
         "input": {"campaignId": CAMP, "rollback": 2}},
        {"query": "signFirmwareUpdate", "variables": {"vin": VIN},
         "campaignId": CAMP, "rollback": 2, "sha256": SHA, "size": 1024,
         "address": "0x08040000", "firmware": B64},
        {"query": "signFirmwareUpdate", "variables": {"vin": VIN}, "operationName": "signFirmwareUpdate",
         "campaignId": CAMP},
        {"query": "signFirmwareUpdate", "vin": VIN, "variables": {"vin": VIN}, "campaignId": CAMP},
    ]
    for bd in bodies:
        st, txt = gql(bd)
        mark = "SAME" if txt == '{"errors":[{"message":"update campaign validation failed"}]}' else "DIFF"
        print(f"  {mark} {st} {txt[:110]}")
        print(f"        body keys: {sorted(bd.keys())}")

    print("\n=== C. baseline sanity ===")
    print("  diag:      ", gql({"query": "vehicleDiagnostics", "variables": {"vin": VIN}})[1][:80])
    print("  sign+vin:  ", gql({"query": "signFirmwareUpdate", "variables": {"vin": VIN}})[1][:90])
    print("  sign novin:", gql({"query": "signFirmwareUpdate", "variables": {}})[1][:90])


if __name__ == "__main__":
    main()

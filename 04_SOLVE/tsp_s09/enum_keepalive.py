#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TSP 路径枚举 (keep-alive, 可靠版)
- 用 requests.Session 复用连接, 避免 Windows 本地端口耗尽 (上一个版本用裸 socket + Connection: close 导致 WinError)
- 多方法: GET / POST(空体{} json) / PUT / DELETE / OPTIONS 仅对高价值路径
- 结果按状态码分类, 404+Go 默认体 视为"不存在"
"""
import requests
import sys
import os
import json
import time
import urllib3

urllib3.disable_warnings()

BASE = "http://10.230.164.2:8080"
OUT = sys.argv[1] if len(sys.argv) > 1 else r"D:\qwb\03_EVIDENCE\tsp_s09"

WORDS = """
programming programming-session programmingsession programming_session session sessions
download downloads requestdownload request-download request_download transferdata
transfer-data transfer_data block blocklength block-length blocks maxblock
sign signature signatures sign-firmware sign_firmware signfirmware signpackage signing
verify verify-signature cosign resign countersign
campaign campaigns campaign/vcu campaign/active rollback rollbackcounter rollback-counter
vcu vcus ecu ecus firmware firmwares firmware/reference firmware/vcu firmware/latest
firmware/download firmware/package firmware/manifest reference-firmware reference
ota ota/package ota/packages ota/firmware ota/manifest ota/campaign ota/campaigns
ota/sign ota/download ota/v1 ota/v2 ota/session ota/status ota/config ota/metadata
package packages manifest manifests blob blobs artifact artifacts image images
bin binaries binary hex srec s19 srp update updates upgrade upgrades flash flashing
pki ca certs cert certificates keys key pubkey public publickey jwks jwt token tokens
auth login logout signin authorize oauth apikey api-key credential credentials
debug metrics config configuration internal system status info version health readyz
livez admin manage management dashboard console panel root index home
api api/v1 api/v2 api/v3 api/v1/ota api/v1/firmware api/v1/sign api/v1/campaign
v1 v2 v3 rest rpc graphql graphiql playground gql query mutation subscription
vehicles vehicle fleet fleets car cars device devices tbox tsp cv6 vin diagnostics
diagnostic dtc doip can bus uds boot bootloader partition provisioning provision
enroll enrollment bootstrap tenant tenants account accounts users me
report reports audit logs log events webhook webhooks notify notification queue
jobs job task tasks batch sync import export upload files file static assets media
docs doc openapi swagger redoc actuator healthcheck health-check
content contents resource resources storage store data dataset datasets
transfer transfers upload-session chunk chunks multipart resumable
""".split()

# 前缀组合 (真路由多半在 /api/v1/* 下)
PREFIXES = ["", "/api", "/api/v1", "/api/v2", "/v1", "/v2"]

VALUES = ["vcu", "VCU", "reference", "latest", "current", "active", "default",
          "CV6000000DEMO0001", "CV6FF52FEE9EDDD86", "1", "0", "demo", "test",
          "sign", "download", "manifest", "bin", "hex"]

PRE_FOR_VALUES = ["firmware", "ota", "ota/package", "ota/firmware", "vehicle", "vehicles",
                  "package", "image", "artifact", "blob", "file", "campaign", "vcu",
                  "download", "reference", "api/v1/firmware", "api/v1/ota"]

def build_paths():
    s = set()
    for w in WORDS:
        for pre in PREFIXES:
            s.add(f"{pre}/{w}")
    for p in PRE_FOR_VALUES:
        for v in VALUES:
            s.add(f"/{p}/{v}")
    return sorted(s)

METHODS_FULL = ["GET", "POST"]
EXTRA_METHODS = ["PUT", "DELETE", "PATCH", "OPTIONS"]
HIGH_VALUE = {"programming", "session", "download", "requestdownload", "transferdata",
              "sign", "signature", "campaign", "rollback", "firmware", "ota", "manifest",
              "package", "vcu", "block", "graphql"}


def judge(r):
    """返回 (code, interesting?)"""
    code = r.status_code
    body = r.text[:200]
    if code == 404 and body.strip().startswith("404 page not found"):
        return code, False
    return code, True


def main():
    os.makedirs(OUT, exist_ok=True)
    paths = build_paths()
    print(f"paths={len(paths)}  methods=GET,POST (+PUT/PATCH/DELETE/OPTIONS on {len(HIGH_VALUE)} 关键词)")
    sess = requests.Session()
    sess.headers.update({"Connection": "keep-alive"})
    hits = []
    n = 0
    t0 = time.time()
    raw = open(os.path.join(OUT, "10_path_enum_keepalive.txt"), "w", encoding="utf-8")
    raw.write(f"# TSP {BASE} 路径枚举 {time.strftime('%Y-%m-%dT%H:%M:%S')}\n")
    for p in paths:
        methods = list(METHODS_FULL)
        if any(k in p for k in HIGH_VALUE):
            methods += EXTRA_METHODS
        for m in methods:
            n += 1
            try:
                if m == "POST":
                    r = sess.post(BASE + p, json={}, timeout=6)
                else:
                    r = sess.request(m, BASE + p, timeout=6)
                code, interesting = judge(r)
            except Exception as e:
                raw.write(f"ERR {m} {p} {e!r}\n")
                continue
            if interesting:
                rec = {"method": m, "path": p, "code": code,
                       "len": len(r.content), "body": r.text[:300],
                       "allow": r.headers.get("Allow"), "ctype": r.headers.get("Content-Type")}
                hits.append(rec)
                raw.write(json.dumps(rec, ensure_ascii=False) + "\n")
                raw.flush()
                print(f"[HIT] {code} {m:7s} {p}  {r.text[:80]!r}")
    raw.close()
    print(f"\n=== done: {n} requests in {time.time()-t0:.1f}s, {len(hits)} non-404 ===")
    with open(os.path.join(OUT, "10_path_enum_summary.json"), "w", encoding="utf-8") as f:
        json.dump(hits, f, ensure_ascii=False, indent=1)
    for h in hits:
        print(f'{h["code"]} {h["method"]:7s} {h["path"]:35s} {h["body"][:70]!r}')


main()

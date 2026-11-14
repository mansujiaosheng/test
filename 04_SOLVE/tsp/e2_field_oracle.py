"""E2: 用 Go json.Unmarshal 的类型错误做「顶层字段存在性 oracle」。
原理：json.Unmarshal 到 struct 时，未知字段被忽略(200)；已知字段类型不符则 err(400)。
对每个候选 key 用 4 种值探测：
  S="zz"（字符串）  O={"k":"v"}（对象）  A=["zz"]（数组）  N=123456789（数字）
结论分类：
  S only 通过 -> string 型字段
  O only 通过 -> object/map 型字段
  A only 通过 -> 数组型字段
  N only 通过 -> 数字型字段
  全通过     -> 字段不存在（或 interface{}）
  全失败     -> 不可能（除非字段是特殊类型）
"""
import json, time, urllib.request, urllib.error

URL = "http://10.230.164.2:8080/graphql"
PROBES = {"S": "zz", "O": {"k": "v"}, "A": ["zz"], "N": 123456789}

KEYS = """
query variables operationName extensions data input args params filter where vehicle vin VIN
vehicles vehicleId vehicle_id id ids tenant tenantId tenant_id account accountId account_id
user userId user_id subject principal role roles scope scopes token accessToken access_token
apiKey api_key auth authorization session sessionId session_id cookie signature sig
campaign campaignId campaign_id ota otaCampaign ota_campaign otaCampaigns firmware package
packageId artifact artifactId artifacts release releases update updates version
diagnostic diagnostics session_key dtc dtcs ecu ecus gateway tbox device deviceId
fleet org organization region cluster namespace env home group team
traceId trace_id requestId request_id clientId client_id nonce timestamp ts
kind type action op operation name path resource resourceId target
auth_mode authMode credentials password username login
limit offset page first last after before order sort orderBy order_by
fields select projection include exclude format lang locale
sig_algo algorithm alg keyId key_id key cert certId
manifest bundle image file url downloadUrl download_url
hw hardware sw software model partNumber part_number
debug internal engineering admin root force dryRun dry_run test
"""
KEYS = sorted(set(KEYS.split()))

def probe(key, val):
    body = json.dumps({key: val})
    r = urllib.request.Request(URL, data=body.encode(), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(r, timeout=8) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)

def classify(results):
    ok = {k: (code == 200) for k, (code, _) in results.items()}
    if all(ok.values()):
        return "absent/any", ""
    if not any(ok.values()):
        return "??", ""
    good = "".join(sorted(k for k, v in ok.items() if v))
    names = {"S": "string", "O": "object", "A": "array", "N": "number"}
    return "present", "+".join(names[c] for c in good)

out = []
t0 = time.time()
for k in KEYS:
    res = {p: probe(k, v) for p, v in PROBES.items()}
    kind, note = classify(res)
    if kind != "absent/any":
        out.append((k, kind, note, {p: res[p][0] for p in PROBES}, {p: res[p][1][:80] for p in PROBES}))
        print(f"{k:16} {kind:8} {note}")
print(f"\nprobed {len(KEYS)} keys in {time.time()-t0:.1f}s ; present={len(out)}")
# 已知对照
for k in ["query", "variables", "zzznotafield"]:
    res = {p: probe(k, v) for p, v in PROBES.items()}
    print("control", k, {p: res[p][0] for p in PROBES}, classify(res))
json.dump(out, open(r"D:\qwb\03_EVIDENCE\tsp\0201_e2_field_oracle.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)

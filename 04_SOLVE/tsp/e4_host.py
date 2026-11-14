"""E4: Host 头 / vhost 路由。
线索：web/redirect_and_vhost_probe.txt 记录 Host: tsp 时 GET /graphql -> 404（默认 Host 是 405）。
   说明路由依赖 Host。lead 只测了 GET，这里测 POST + 更多 Host。
判据：响应 body != DEMO 或 status 不在 {200,405} 即命中。
"""
import json, hashlib, urllib.request, urllib.error

URL = "http://10.230.164.2:8080/graphql"
DEMO = {"data": {"vehicles": [{"label": "Guest demo vehicle", "vin": "CV6000000DEMO0001"}]}}

def call(host, body=None, method="POST", path="/graphql", extra=None):
    data = json.dumps(body or {"query": "{vehicles{vin}}"}).encode() if method == "POST" else None
    h = {"Host": host, "Content-Type": "application/json"}
    h.update(extra or {})
    r = urllib.request.Request("http://10.230.164.2:8080" + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=8) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)

HOSTS = """
tsp tsp.local tsp.internal tsp.cybercar tsp.cybercar.local tsp.cybercar.com tsp.api
api.tsp api.tsp.local api tsp-api tsp-graphql graphql
tbox tbox.local tbox.cybercar tbox.cybercar.local
cgw cgw.local gateway gateway.local gw
ota ota.local ota.cybercar firmware updates campaign diagnostics
cybercar cybercar.local cybercar.com ctf qwb
vehicle vehicles cv6ff52fee9eddd86 CV6FF52FEE9EDDD86 cv6000000demo0001
fleet fleet.local fleet.cybercar tenant1 tenant acme demo guest admin internal
localhost 127.0.0.1 10.230.164.2 10.230.164.2:8080 10.230.164.4 10.230.164.3
""".split()

rows = []
for host in HOSTS:
    st, bd = call(host)
    is_demo = (bd.strip() == json.dumps(DEMO, separators=(",", ":")))
    tag = "same" if (st == 200 and is_demo) else "DIFF"
    rows.append((host, st, bd[:200].replace("\n", " ")))
    print(f"{tag:4} POST Host={host:28} status={st:3} body={bd[:120].strip()}")
    if tag == "DIFF":
        print("      ^^^^", bd[:400])

print("\n--- GET /graphql with Host variants (vhost 探针) ---")
for host in HOSTS:
    st, bd = call(host, method="GET")
    print(f"GET  Host={host:28} status={st:3} len={len(bd)} body={bd[:80].strip()}")

json.dump(rows, open(r"D:\qwb\03_EVIDENCE\tsp\0203_e4_host_matrix.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)

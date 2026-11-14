"""E6b: 重跑 E6 中因本地 socket 耗尽/超时失败的那部分字段名，确保「0 差分」结论干净。
只重试 errors 里的名字，逐条重试最多 3 次，间隔 20ms。"""
import json, urllib.request, urllib.error, time

URL = "http://10.230.164.2:8080/graphql"
DEMO = '{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN = "CV6FF52FEE9EDDD86"

prev = json.load(open(r"D:\qwb\03_EVIDENCE\tsp\0206_e6_fieldname_brute.json", encoding="utf-8"))
failed_names = sorted({d["name"] for d in prev["diffs"]})
print(f"上轮失败的名字 {len(failed_names)} 个")

def post(q):
    body = json.dumps({"query": q}).encode()
    r = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(r, timeout=10) as resp:
        return resp.status, resp.read().decode("utf-8", "replace").strip()

real, errs, n = [], [], 0
for name in failed_names:
    for q in (f"{{{name}}}", f'{{{name}(vin:"{VIN}"){{id}}}}'):
        for attempt in range(3):
            try:
                code, bd = post(q)
                n += 1
                if bd != DEMO:
                    real.append({"name": name, "query": q, "status": code, "body": bd[:400]})
                    print("DIFF", q, code, bd[:200], flush=True)
                break
            except Exception as e:
                if attempt == 2:
                    errs.append({"name": name, "query": q, "err": str(e)})
                time.sleep(0.05)
        time.sleep(0.02)
print(f"重试完成：成功 {n} 条查询，真差分 {len(real)}，仍失败 {len(errs)}")
json.dump({"retried_names": len(failed_names), "queries_ok": n, "real_diffs": real, "still_failed": errs},
          open(r"D:\qwb\03_EVIDENCE\tsp\0206b_e6_retry.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)

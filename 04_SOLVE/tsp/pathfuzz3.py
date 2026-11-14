import concurrent.futures, requests
hosts=[("tsp","http://10.225.139.2:8080"),("tbox","http://10.225.139.3:8080"),("cgw","http://10.226.193.2:8080")]
VIN="CV622697F82A936A1"
base=["ota","ota/","ota/package","ota/packages","ota/engineering","ota/artifact","ota/artifacts",
"ota/download","ota/campaign","ota/campaigns","ota/firmware","ota/vcu","ota/sign","ota/signature",
"campaign","campaigns","campaign/1","campaigns/1","package","packages","package/vcu","packages/vcu",
"artifact","artifacts","artifact/1","artifacts/1","firmware","firmware/vcu","firmware/vcu.bin",
"download","downloads","files","file","static","static/ota","assets","data","storage","blob","s3",
"api/ota","api/v1/ota","api/ota/package","api/v1/ota/package","api/campaigns","api/vehicles",
"api/v1/vehicles","api/v1/vehicle","v1/ota","v1/vehicles","graphql/ota","graphql/vehicle",
"vehicle","vehicle/"+VIN,"vehicles/"+VIN,"vehicles/"+VIN+"/ota","vehicles/"+VIN+"/campaigns",
"vehicle/"+VIN+"/ota","vehicle/"+VIN+"/campaign","ota/"+VIN,"ota/vehicles/"+VIN,
"engineering","engineering/package","engineering/ota","eng","debug","internal","export","backup",
"pkg","pkg.tar.gz","ota/pkg.tar.gz","ota/package.tar.gz","ota/engineering.tar.gz","ota/vcu.bin",
"firmware.bin","vcu.bin","ota.bin","sign.bin","ota/sign.bin","keys","key","cert","certs","pki","ca.pem",
"ca.crt","cert.pem","client.pem","client.crt","tbox.pem","tbox.crt","root-ca.pem","manifest.json",
"signature.json","campaign.json","vehicles.json","ota.json","config.json","version","status","info",
"health","metrics","install","upgrade","update","updates","flash","flash/vcu","flash/vcu.bin",
"diagnostic","diagnostics","diag","diag/entry","diagnostic/entry","doip","canfd","bridge","secoc","bms","bcm","vcu",
"ota/1","ota/2","campaign/c1","package/p1","artifact/a1","ota/engineering/1","ota/engineering/vcu"]
paths=[]
for b in base:
    paths.append("/"+b)
    paths.append("/"+b+"/")
seen=set(); paths=[p for p in paths if not (p in seen or seen.add(p))]
def get(args):
    name,url,p=args
    try:
        r=requests.get(url+p,timeout=4,allow_redirects=False)
        if r.status_code not in (404,):
            return f"{name} {r.status_code} {len(r.content)} {p} {r.text[:100]!r}"
    except Exception: return None
jobs=[(n,u,p) for n,u in hosts for p in paths]
with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
    for res in ex.map(get,jobs):
        if res: print(res,flush=True)
print("done",len(jobs))

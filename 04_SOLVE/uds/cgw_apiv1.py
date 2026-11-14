import concurrent.futures, requests
HOSTS={"cgw_193_2":"http://10.226.193.2:8080","cgw_225_139_4":"http://10.225.139.4:8080",
       "tbox":"http://10.225.139.3:8080","tsp":"http://10.225.139.2:8080"}
# 已被证明存在的同族路径模式
known=["objectives","objectives/final","diag","diag/session","diag/bind","diag/ticket",
"ota","ota/engineering-bundle","ota/bundle","ota/sign","ota/campaign","ota/campaigns",
"vehicles","vehicle","campaign","campaigns","session","sessions","ticket","tickets",
"bridge","bridge/open","bridge/enable","bridge/status","canfd","canfd/open","can","isotp",
"uds","uds/session","uds/security","security","security/access","security/seed","security/key",
"seed","key","unlock","doip","doip/session","cgw","cgw/session","ecu","ecus",
"firmware","firmware/decrypt","crypto","keys","pki","auth","auth/session","token","tokens",
"health","healthz","status","info","version","config","state","debug","internal","admin",
"engineering","bundle","packages","package","artifacts","sign","signature","verify",
"bms","bcm","vcu","vehicle/diagnostics","vehicles/diagnostics"]
def probe(args):
    name,base,p=args
    out=[]
    for m in ("GET","POST"):
        try:
            r=requests.request(m,f"{base}/api/v1/{p}",timeout=4,allow_redirects=False,
                               json={} if m=="POST" else None)
            if r.status_code!=404:
                out.append(f"{name:14s} {m:4s} {r.status_code} {len(r.content):5d} /api/v1/{p}  {r.text[:110]!r}")
        except Exception: pass
    return out
jobs=[(n,b,p) for n,b in HOSTS.items() for p in known]
with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
    for res in ex.map(probe,jobs):
        for line in res: print(line,flush=True)
print("done")

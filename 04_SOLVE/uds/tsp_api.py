import concurrent.futures, requests
BASE="http://10.225.139.2:8080"
roots=["objectives","diag","diagnostics","uds","doip","security","seed","key","ticket","session",
"bridge","canfd","can","isotp","vehicle","vehicles","campaign","campaigns","ota","firmware",
"auth","token","admin","internal","debug","state","status","info","ecu","ecus","cgw","tbox",
"bms","bcm","vcu","fleet","update","updates","package","packages","artifact","sign","signature",
"engineering","routine","routines","unlock","control","command","cmd","relay","proxy","forward"]
leafs=["","/final","/status","/open","/enable","/start","/seed","/key","/session","/ticket",
"/unlock","/state","/info","/list","/all","/1","/current","/next","/config"]
paths=set()
for r in roots:
    for l in leafs:
        paths.add(f"/api/v1/{r}{l}")
# 已知锚点
paths.add("/api/v1/objectives/final"); paths.add("/api/v1/objectives")
def probe(p):
    out=[]
    for m in ("GET","POST"):
        try:
            r=requests.request(m,BASE+p,timeout=4,allow_redirects=False,
                               json={} if m=="POST" else None)
            if r.status_code!=404:
                out.append(f"{m:4s} {r.status_code} {len(r.content):5d} {p}  {r.text[:160]!r}")
        except Exception: pass
    return out
print(f"probing {len(paths)} paths on TSP")
with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
    for res in ex.map(probe,sorted(paths)):
        for line in res: print(line,flush=True)
print("done")

import requests, itertools
URL="http://10.230.164.2:8080/graphql"
BASE='{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
body='{"query":"{vehicles{vin}}"}'
cts=["application/json","application/json; charset=utf-8","application/graphql+json","text/json","application/x-json",None]
accepts=["*/*","application/json","application/graphql-response+json",None]
diffs=0
for ct,ac in itertools.product(cts,accepts):
    h={}
    if ct: h["Content-Type"]=ct
    if ac: h["Accept"]=ac
    try:
        r=requests.post(URL,data=body.encode(),headers=h,timeout=6)
        t=r.text.strip()
        if t!=BASE:
            print("DIFF",ct,ac,r.status_code,t[:200],flush=True); diffs+=1
    except Exception as e:
        print("ERR",ct,ac,e)
print("diffs",diffs)
# timing: small vs huge query
import time
for size in [10, 100000, 5000000]:
    q='{"query":"'+("a"*size)+'"}'
    t0=time.time()
    try:
        r=requests.post(URL,data=q,headers={"Content-Type":"application/json"},timeout=15)
        print(f"size={size} status={r.status_code} time={time.time()-t0:.3f}s len={len(r.text)}")
    except Exception as e:
        print(f"size={size} err={e} time={time.time()-t0:.3f}s")

import concurrent.futures, requests
HOSTS={"cgw":"http://10.226.193.2:8080","tbox":"http://10.225.139.3:8080","cgw_alt":"http://10.225.139.4:8080"}
paths=["/","/healthz","/api","/api/v1","/api/v1/bridge","/api/v1/bridge/open","/api/v1/bridge/enable",
"/api/v1/canfd","/api/v1/can","/api/v1/doip","/api/v1/diag","/api/v1/diag/session","/api/v1/diagnostics",
"/api/v1/uds","/api/v1/security","/api/v1/security/access","/api/v1/seed","/api/v1/key","/api/v1/ticket",
"/api/v1/auth","/api/v1/session","/api/v1/vehicle","/api/v1/vehicles","/api/v1/ecu","/api/v1/ecus",
"/api/v1/ota","/api/v1/ota/bridge","/bridge","/bridge/open","/canfd","/can","/iso15765","/isotp",
"/diag","/diag/session","/diagnostics","/uds","/doip","/security","/seed","/unlock","/open",
"/api/v1/routine","/api/v1/routines","/api/v1/routine/open_bridge","/api/v1/internal","/internal",
"/api/v1/admin","/admin","/api/v1/debug","/debug","/api/v1/config","/config","/api/v1/state","/state"]
def probe(args):
    name,base,p=args
    out=[]
    for m in ("GET","POST"):
        try:
            r=requests.request(m,base+p,timeout=4,allow_redirects=False,
                               json={} if m=="POST" else None)
            if r.status_code not in (404,):
                out.append(f"{name:8s} {m:4s} {r.status_code} {len(r.content):5d} {p}  {r.text[:90]!r}")
        except Exception: pass
    return out
jobs=[(n,b,p) for n,b in HOSTS.items() for p in paths]
with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
    for res in ex.map(probe,jobs):
        for line in res: print(line,flush=True)
print("done")

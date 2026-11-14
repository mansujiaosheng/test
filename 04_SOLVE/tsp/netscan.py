import socket, concurrent.futures, sys, time
def probe(host, port, timeout=0.4):
    s=socket.socket(); s.settimeout(timeout)
    try:
        s.connect((host,port)); return host,port
    except Exception: return None
    finally: s.close()
ports=[8080,8443,13400]
nets=[(f"10.{a}.{b}.0") for a in (229,230) for b in range(0,256)]
hosts=[f"{n.rsplit('.',1)[0]}.{i}" for n in nets for i in range(1,255)]
jobs=[(h,p) for h in hosts for p in ports]
print("targets",len(jobs),flush=True)
t0=time.time(); hits=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=800) as ex:
    for r in ex.map(lambda hp: probe(*hp), jobs):
        if r:
            hits.append(r); print("OPEN",r,flush=True)
print("done",len(hits),"elapsed",round(time.time()-t0,1),flush=True)

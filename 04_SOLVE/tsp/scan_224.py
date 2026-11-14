import socket, concurrent.futures, time
def probe(host, port, timeout=0.35):
    s=socket.socket(); s.settimeout(timeout)
    try:
        s.connect((host,port)); return host,port
    except Exception: return None
    finally: s.close()
ports=[8080,8443,13400,80,443,8000,3000,5000,9090]
hosts=[f"10.224.{b}.{i}" for b in range(0,256) for i in range(1,255)]
jobs=[(h,p) for h in hosts for p in ports]
t0=time.time(); hits=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=800) as ex:
    for r in ex.map(lambda hp: probe(*hp), jobs):
        if r: hits.append(r); print("OPEN",r,flush=True)
print("done",len(hits),round(time.time()-t0,1),flush=True)

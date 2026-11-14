import socket, concurrent.futures
PORTS=[22,80,443,8080,8443,13400,13401,1883,5000,8000,9000,10000,3000,8888,9090]
def chk(a):
    out=[]
    for p in PORTS:
        s=socket.socket(); s.settimeout(0.35)
        try:
            s.connect((a,p)); out.append(p)
        except Exception: pass
        finally: s.close()
    return a,out
res={}
with concurrent.futures.ThreadPoolExecutor(max_workers=120) as ex:
    for a,o in ex.map(chk,[f"10.230.164.{i}" for i in range(1,255)]):
        if o: res[a]=o
for a in sorted(res): print(a, res[a])
print("live:", len(res))

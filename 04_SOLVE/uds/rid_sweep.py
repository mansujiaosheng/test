import sys, struct; sys.path.insert(0,"04_SOLVE/uds")
from doip import DoIP, explain
d=DoIP(); d.connect(); d.routing_activation()
d.uds(0xE442, bytes.fromhex("1003"), wait=0.6)
found=[]; stats={}
tried=0
for rid in range(0x0000,0x10000):
    uds=bytes([0x31,0x01])+struct.pack(">H",rid)
    x=d.parse_uds(d.uds(0xE442, uds, wait=0.30))
    tried+=1
    if not x: stats["EMPTY"]=stats.get("EMPTY",0)+1; continue
    u=x[0]['uds']
    if u.startswith("7f31"):
        nrc=u[4:6]; stats[nrc]=stats.get(nrc,0)+1
    else:
        found.append((rid,u)); print(f"  *** RID {rid:#06x} -> {x[0]['src']} {explain(u)}",flush=True)
    if tried%20000==0: print(f"  ...{tried} done, found={len(found)}",flush=True)
d.close()
print("tried",tried,"stats",stats,"found",len(found))

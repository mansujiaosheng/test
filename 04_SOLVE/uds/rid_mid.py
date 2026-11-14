import sys, json, hashlib, struct, socket, time
sys.path.insert(0,"04_SOLVE/uds")
from u import open_link
from solve_task04 import _pkt,_recv
H=lambda t,p: bytes([0x02,0xFD])+struct.pack(">H",t)+struct.pack(">I",len(p))+p
SA=0x0E00; TA=0xE442
link,t=open_link("CV622697F82A936A1", verbose=True)
s=link.s
def rp():
    old=s.gettimeout(); s.settimeout(1.2)
    try: r=_recv(s)
    except socket.timeout: r=None
    finally: s.settimeout(old)
    return r

lo,hi,step=0x0201,0xDFFF,32
hits=[]; t0=time.time(); la=lo
while la<=hi:
    chunk=list(range(la,min(la+step,hi+1)))
    s.sendall(b"".join(H(0x8001,struct.pack(">H",SA)+struct.pack(">H",TA)+
                        bytes([0x31,0x01])+struct.pack(">H",r)) for r in chunk))
    got=0
    while got<len(chunk):
        r=rp()
        if r is None: break
        if r[0]!=0x8001 or len(r[1])<5: continue
        uds=r[1][4:].hex()
        if not uds.startswith("7f3131"):
            hits.append((chunk[got],uds)); print(f"  *** RID {chunk[got]:#06x} -> {uds}",flush=True)
        got+=1
    if got!=len(chunk):
        # 不对齐：退回严格单发这一段
        for r in chunk:
            s.sendall(H(0x8001,struct.pack(">H",SA)+struct.pack(">H",TA)+bytes([0x31,0x01])+struct.pack(">H",r)))
            rr=rp()
            if rr and rr[0]==0x8001 and len(rr[1])>=5:
                u=rr[1][4:].hex()
                if not u.startswith("7f3131"):
                    hits.append((r,u)); print(f"  *** RID {r:#06x} -> {u} (strict)",flush=True)
    la+=step
    if la%0x2000<step: print(f"  ...{la:#06x} ({time.time()-t0:.0f}s) hits={len(hits)}",flush=True)
link.close()
print(f"DONE 0x0201-0xDFFF hits={len(hits)} elapsed={time.time()-t0:.0f}s")
print(hits)

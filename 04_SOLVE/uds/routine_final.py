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
diag(bytes.fromhex("1003")); diag(bytes.fromhex("2EF1A1")+T.encode())
sd=diag(bytes.fromhex("2701")); k=hash8(bytes.fromhex(sd[4:]), hashlib.sha256(VIN).digest()[:8], C_DEV)
print("unlock:",diag(bytes.fromhex("2702")+k))
fr=bytes.fromhex(diag(bytes.fromhex("22F1A3"))[6:]); print("fresh:",fr.hex())

print("\n=== 4-byte RID forms ===")
for rid4 in [0x00000001,0x0000FF00,0x0000F1A3,0x00000000,0x00010000]:
    p=bytes([0x31,0x01])+struct.pack(">I",rid4)
    print(f"  31 01 {rid4:#010x} -> {diag(p)}")
print("\n=== RID from freshness ===")
for rid in [int.from_bytes(fr[:2],'big'), int.from_bytes(fr[2:4],'big'),
            int.from_bytes(fr[4:6],'big'), int.from_bytes(fr[6:8],'big'),
            int.from_bytes(fr[:4],'big')&0xFFFF, int.from_bytes(fr[4:],'big')&0xFFFF]:
    print(f"  31 01 {rid:#06x} -> {diag(bytes([0x31,0x01])+struct.pack('>H',rid))}")
print("\n=== 31 on other TAs while unlocked ===")
for ta in [0x1000,0x1220,0x07E0,0x07E1,0x07E8,0x07E9,0xE400,0xE442]:
    print(f"  TA={ta:#06x} 31 01 FF00 -> {diag(bytes.fromhex('3101FF00'),ta=ta)}")
print("\n=== 10 02 (programming) retry unlocked ===")
print("  10 02 ->", diag(bytes.fromhex("1002")))
print("  10 01 ->", diag(bytes.fromhex("1001")))
s.close()

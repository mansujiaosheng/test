import socket,struct,binascii,time,json
HOST=("10.229.221.2",13400); SA=0x0E00; TA=0xE442
def pkt(pt,payload=b""):
    return bytes([0x02,0xFD])+struct.pack(">H",pt)+struct.pack(">I",len(payload))+payload
class C:
    def __init__(s,t=3.0):
        s.s=socket.socket(); s.s.settimeout(t); s.s.connect(HOST); s.last=0
        s.s.sendall(pkt(0x0005, bytes.fromhex("0E000000000000"))); s.recv()
    def recv(s):
        hdr=b""
        while len(hdr)<8:
            c=s.s.recv(8-len(hdr))
            if not c: return None
            hdr+=c
        v,iv,pt,pl=struct.unpack(">BBHI",hdr); d=b""
        while len(d)<pl:
            c=s.s.recv(pl-len(d))
            if not c: break
            d+=c
        return pt,d
    def uds(s,data):
        s.s.sendall(pkt(0x8001,struct.pack(">HH",SA,TA)+data))
        r=s.recv()
        return None if r is None else r[1][4:]
    def ensure(s):
        if time.time()-s.last>2.0:
            s.uds(bytes.fromhex("1003")); s.last=time.time()
    def reinit(s):
        try: s.s.close()
        except: pass
        s.__init__()
c=C(); out=[]
rids=[]
for lo,hi in [(0xFF00,0xFFFF),(0x0000,0x00FF),(0x0200,0x02FF),(0x0100,0x01FF)]:
    rids+=list(range(lo,hi+1))
for rid in rids:
    c.ensure()
    try: r=c.uds(bytes([0x31,0x01,rid>>8,rid&0xFF]))
    except Exception: c.reinit(); r=None
    h=None if r is None else binascii.hexlify(r).decode()
    out.append({"rid":f"0x{rid:04X}","resp":h})
    if h and not h.startswith("7f3131") and not h.startswith("7f31"):
        print(f"[+] RID 0x{rid:04X} -> {h}", flush=True)
    elif h and h.startswith("7f31") and h not in ("7f3131",):
        print(f"[?] RID 0x{rid:04X} -> {h}", flush=True)
with open("03_EVIDENCE/lead_s09/0006_routinescan_e442.jsonl","w") as f:
    for o in out: f.write(json.dumps(o)+"\n")
import collections
cc=collections.Counter(str(o["resp"]) for o in out)
print("SUMMARY:",dict(cc.most_common(10)))

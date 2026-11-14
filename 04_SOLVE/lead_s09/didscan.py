import socket,struct,binascii,sys,time,json
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
        v,iv,pt,pl=struct.unpack(">BBHI",hdr)
        d=b""
        while len(d)<pl:
            c=s.s.recv(pl-len(d))
            if not c: break
            d+=c
        return pt,d
    def uds(s,data):
        s.s.sendall(pkt(0x8001,struct.pack(">HH",SA,TA)+data))
        r=s.recv()
        if r is None: return None
        d=r[1][4:]
        return d
    def ensure_session(s):
        if time.time()-s.last>2.0:
            s.uds(bytes.fromhex("1003")); s.last=time.time()
    def reconnect(s):
        try: s.s.close()
        except: pass
        s.__init__()
def main():
    dids=[]
    for lo,hi in [(0xF180,0xF1FF),(0xF100,0xF17F),(0xF000,0xF0FF)]:
        dids+= list(range(lo,hi+1))
    c=C()
    out=[]
    for i,did in enumerate(dids):
        c.ensure_session()
        try:
            r=c.uds(bytes([0x22,did>>8,did&0xFF]))
        except Exception as e:
            c.reconnect(); r=None
        if r is None:
            out.append({"did":f"0x{did:04X}","resp":None}); continue
        h=binascii.hexlify(r).decode()
        out.append({"did":f"0x{did:04X}","resp":h})
        if not h.startswith("7f"):
            print(f"[+] DID 0x{did:04X} -> {h}", flush=True)
    with open("03_EVIDENCE/lead_s09/0005_didscan_e442.jsonl","w") as f:
        for o in out: f.write(json.dumps(o)+"\n")
    pos=[o for o in out if not str(o["resp"]).startswith("7f")]
    print(f"total={len(out)} positive={len(pos)}")
if __name__=="__main__": main()

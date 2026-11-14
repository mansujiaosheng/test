import socket,struct,binascii,json
HOST=("10.229.221.2",13400); SA=0x0E00; TA=0xE442
def pkt(pt,payload=b""):
    return bytes([0x02,0xFD])+struct.pack(">H",pt)+struct.pack(">I",len(payload))+payload
def recv(s):
    hdr=b""
    while len(hdr)<8:
        c=s.recv(8-len(hdr))
        if not c: return None
        hdr+=c
    v,iv,pt,pl=struct.unpack(">BBHI",hdr); d=b""
    while len(d)<pl:
        c=s.recv(pl-len(d))
        if not c: break
        d+=c
    return pt,d
s=socket.socket(); s.settimeout(3); s.connect(HOST)
s.sendall(pkt(0x0005, bytes.fromhex("0E000000000000"))); recv(s)
def uds(data):
    s.sendall(pkt(0x8001,struct.pack(">HH",SA,TA)+data))
    r=recv(s)
    return None if r is None else r[1][4:]
out=[]
for sub in range(0x100):
    try: r=uds(bytes([0x10,sub]))
    except Exception as e:
        r=None
    h=None if r is None else binascii.hexlify(r).decode()
    out.append([sub,h])
    if h and not h.startswith("7f"):
        print(f"[+] 10 {sub:02X} -> {h}",flush=True)
    elif h and h not in ("7f1012","7f1011","7f1031"):
        print(f"[?] 10 {sub:02X} -> {h}",flush=True)
import collections
print("SUMMARY:",collections.Counter(str(x[1]) for x in out).most_common(8))
open("03_EVIDENCE/lead_s09/0007_sessionscan_e442.json","w").write(json.dumps(out,indent=0))

import socket,struct,binascii,time
HOST=("10.229.221.2",13400); SA=0x0E00
def pkt(pt,payload=b""):
    return bytes([0x02,0xFD])+struct.pack(">H",pt)+struct.pack(">I",len(payload))+payload
def recv(s):
    hdr=b""
    while len(hdr)<8:
        c=s.recv(8-len(hdr))
        if not c: return None
        hdr+=c
    v,iv,pt,pl=struct.unpack(">BBHI",hdr)
    d=b""
    while len(d)<pl:
        c=s.recv(pl-len(d))
        if not c: break
        d+=c
    return pt,d
s=socket.socket(); s.settimeout(3); s.connect(HOST)
print("connected")
s.sendall(pkt(0x0001))
try:
    r=recv(s); print("ident ->", f"pt=0x{r[0]:04X}", binascii.hexlify(r[1]).decode())
except Exception as e: print("ident exc",type(e).__name__)
t=time.time()
s.sendall(pkt(0x0005, bytes.fromhex("0E000000000000")))
try:
    r=recv(s); print("RA ->", f"pt=0x{r[0]:04X}", binascii.hexlify(r[1]).decode(), f"{(time.time()-t)*1000:.0f}ms")
except Exception as e: print("RA exc",type(e).__name__)
t=time.time()
s.sendall(pkt(0x8001, bytes.fromhex("0E0010001002")))
try:
    r=recv(s); print("10 02 ->", f"pt=0x{r[0]:04X}", binascii.hexlify(r[1]).decode(), f"{(time.time()-t)*1000:.0f}ms")
except Exception as e: print("1002 exc",type(e).__name__)
s.close()

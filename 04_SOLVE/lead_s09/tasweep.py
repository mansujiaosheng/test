import socket,struct,binascii,sys,time
HOST=("10.229.221.2",13400); SA=0x0E00
def pkt(pt,payload=b"",ver=0x02):
    return bytes([ver,0xFF-ver])+struct.pack(">H",pt)+struct.pack(">I",len(payload))+payload
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
def conn(t=2.0):
    s=socket.socket(); s.settimeout(t); s.connect(HOST); return s
def ra(s,sa=SA,act=0x00,oem=b""):
    s.sendall(pkt(0x0005,struct.pack(">HB",sa,act)+b"\x00\x00\x00\x00"+oem))
    return recv(s)
def diag(s,ta,uds):
    s.sendall(pkt(0x8001,struct.pack(">HH",SA,ta)+uds))
    return recv(s)
if __name__=="__main__":
    s=conn(); r=ra(s)
    print("RA ->", "None" if r is None else (f"pt=0x{r[0]:04X}", binascii.hexlify(r[1]).decode()))
    tests=[0x0001,0x0010,0x0100,0x0700,0x07E0,0x07E1,0x07E2,0x07E3,0x07E8,0x07E9,0x0710,0x0714,0x0720,0x0730,0x0740,0x0760,0x07A0,0x1000,0x1001,0x0E00,0x0E80,0xE000,0xE400,0xEFFF]
    for ta in tests:
        try:
            r=diag(s,ta,bytes.fromhex("1002"))
            if r is None: print(f"TA 0x{ta:04X} 1002 -> TIMEOUT"); continue
            pt,d=r
            print(f"TA 0x{ta:04X} 1002 -> pt=0x{pt:04X} {binascii.hexlify(d).decode()}")
        except Exception as e:
            print(f"TA 0x{ta:04X} EXC {type(e).__name__}"); 
            try: s.close()
            except: pass
            s=conn(); ra(s)
    s.close()

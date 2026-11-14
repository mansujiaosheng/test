import socket, struct, binascii, time, sys
H=lambda t,p: bytes([0x02,0xFD])+struct.pack('>H',t)+struct.pack('>I',len(p))+p
def frame(s,to):
    s.settimeout(to); hdr=b''
    try:
        while len(hdr)<8:
            c=s.recv(8-len(hdr))
            if not c: return None,None
            hdr+=c
        v,i,t,l=struct.unpack('>BBHI',hdr); pl=b''
        while len(pl)<l:
            c=s.recv(l-len(pl))
            if not c: break
            pl+=c
        return t,pl
    except socket.timeout: return 'TIMEOUT',b''
def run(dids, to=12):
    s=socket.socket(); s.settimeout(5); s.connect(('10.230.164.4',13400))
    s.sendall(H(0x0005, struct.pack('>H',0x0E00)+b'\x00'+b'\x00'*4))
    print("RA:", frame(s,5))
    for did in dids:
        t0=time.time()
        s.sendall(H(0x8001, struct.pack('>H',0x0E00)+struct.pack('>H',0x1000)+b'\x22'+bytes.fromhex(did)))
        out=[]
        while True:
            t,pl=frame(s,to)
            if t is None or t=='TIMEOUT': break
            out.append((hex(t),pl.hex()))
            if t==0x8001: break
        print(f"{did}: {time.time()-t0:.2f}s -> {out}")
    s.close()
if __name__=="__main__":
    run(sys.argv[1:] or ["3CE0","8DA0","A7E0","F1A8","A7F7"])

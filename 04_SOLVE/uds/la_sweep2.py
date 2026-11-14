import socket, struct, sys, time
H=lambda t,p: bytes([0x02,0xFD])+struct.pack(">H",t)+struct.pack(">I",len(p))+p
HOST,PORT="10.226.193.2",13400; SA=0x0E00
def recv_pkt(s):
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

def coarse(lo,hi,svc,batch=32):
    """返回所有非0x1000的(src)出现，不做LA对齐（仅作粗筛）"""
    found=set(); la=lo
    while la<=hi:
        chunk=list(range(la,min(la+batch,hi+1)))
        s=socket.socket(); s.settimeout(3)
        try:
            s.connect((HOST,PORT))
            s.sendall(H(0x0005,struct.pack(">H",SA)+b"\x00"+b"\x00"*4)); recv_pkt(s)
            blob=b"".join(H(0x8001,struct.pack(">H",SA)+struct.pack(">H",t)+svc) for t in chunk)
            s.sendall(blob); s.settimeout(1.0)
            n=0
            while n<len(chunk):
                r=recv_pkt(s)
                if r is None: break
                pt,pl=r
                if pt!=0x8001 or len(pl)<5: continue
                n+=1
                src=struct.unpack(">H",pl[:2])[0]
                found.add((src,pl[4:].hex()))
        except Exception: pass
        finally: s.close()
        la+=batch
    return found

def strict(la,svc):
    s=socket.socket(); s.settimeout(3)
    try:
        s.connect((HOST,PORT))
        s.sendall(H(0x0005,struct.pack(">H",SA)+b"\x00"+b"\x00"*4)); recv_pkt(s)
        s.sendall(H(0x8001,struct.pack(">H",SA)+struct.pack(">H",la)+svc))
        r=recv_pkt(s)
        if r and r[0]==0x8001 and len(r[1])>=5:
            return struct.unpack(">H",r[1][:2])[0], r[1][4:].hex()
    except Exception: pass
    finally: s.close()
    return None,None

if __name__=="__main__":
    lo,hi=int(sys.argv[1],16),int(sys.argv[2],16); svc=bytes.fromhex(sys.argv[3])
    t0=time.time()
    f=coarse(lo,hi,svc)
    print(f"coarse done, distinct (src,resp) pairs: {len(f)}  elapsed={time.time()-t0:.0f}s")
    for sr,rs in sorted(f): print(f"   src={sr:#06x} resp={rs}")

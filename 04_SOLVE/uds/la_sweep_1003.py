import socket, struct, sys, time
H=lambda t,p: bytes([0x02,0xFD])+struct.pack(">H",t)+struct.pack(">I",len(p))+p
HOST,PORT="10.226.193.2",13400
SA=0x0E00

def recv_pkt(s):
    hdr=b""
    while len(hdr)<8:
        c=s.recv(8-len(hdr))
        if not c: return None
        hdr+=c
    v,i,pt,ln=struct.unpack(">BBHI",hdr)
    pl=b""
    while len(pl)<ln:
        c=s.recv(ln-len(pl))
        if not c: break
        pl+=c
    return pt,pl

def sweep(lo,hi,svc,sa=SA,batch=64,timeout=1.2):
    """pipelined: send `batch` diag msgs then collect"""
    hits=[]
    la=lo
    while la<=hi:
        chunk=list(range(la,min(la+batch,hi+1)))
        s=socket.socket(); s.settimeout(4)
        try:
            s.connect((HOST,PORT))
            s.sendall(H(0x0005, struct.pack(">H",sa)+b"\x00"+b"\x00"*4))
            ra=recv_pkt(s)
            blob=b""
            for t in chunk:
                blob+=H(0x8001, struct.pack(">H",sa)+struct.pack(">H",t)+svc)
            s.sendall(blob)
            s.settimeout(timeout)
            seen=0
            while seen<len(chunk):
                r=recv_pkt(s)
                if r is None: break
                pt,pl=r
                if pt!=0x8001 or len(pl)<5: continue
                seen+=1
                src=struct.unpack(">H",pl[:2])[0]
                uds=pl[4:]
                if src!=0x1000:
                    hits.append((t,src,uds.hex()))
                    print(f"  *** LA={t:#06x} src={src:#06x} {uds.hex()}",flush=True)
        except Exception:
            pass
        finally:
            s.close()
        la+=batch
        if la % 4096 < batch:
            print(f"  ...{la:#06x}",flush=True)
    return hits

if __name__=="__main__":
    lo,hi=int(sys.argv[1],16),int(sys.argv[2],16)
    svc=bytes.fromhex(sys.argv[3])
    t0=time.time()
    h=sweep(lo,hi,svc)
    print(f"DONE {lo:#06x}-{hi:#06x} svc={sys.argv[3]} hits={len(h)} elapsed={time.time()-t0:.1f}s")
    for x in h: print("  ",x)

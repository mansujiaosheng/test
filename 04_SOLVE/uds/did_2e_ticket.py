import socket, struct, sys, json, base64, time
H=lambda t,p: bytes([0x02,0xFD])+struct.pack(">H",t)+struct.pack(">I",len(p))+p
HOST,PORT="10.226.193.2",13400; SA=0x0E00; TA=0xE442
tick=json.load(open("work/ticket_fresh.json"))
T=base64.urlsafe_b64decode(tick["diagnosticTicket"]+"="*(-len(tick["diagnosticTicket"])%4))

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

def sweep(lo,hi,batch=48):
    hits=[]; la=lo; t0=time.time()
    while la<=hi:
        chunk=list(range(la,min(la+batch,hi+1)))
        s=socket.socket(); s.settimeout(3)
        try:
            s.connect((HOST,PORT))
            s.sendall(H(0x0005,struct.pack(">H",SA)+b"\x00"+b"\x00"*4)); recv_pkt(s)
            s.sendall(H(0x8001,struct.pack(">H",SA)+struct.pack(">H",TA)+bytes.fromhex("1003"))); recv_pkt(s)
            blob=b"".join(H(0x8001,struct.pack(">H",SA)+struct.pack(">H",TA)+
                            bytes([0x2E])+struct.pack(">H",did)+T) for did in chunk)
            s.sendall(blob); s.settimeout(1.2)
            n=0
            while n<len(chunk):
                r=recv_pkt(s)
                if r is None: break
                pt,pl=r
                if pt!=0x8001 or len(pl)!=7: continue
                n+=1
                uds=pl[4:].hex()
                if uds!="7f2e31":
                    hits.append((chunk[n-1],uds)); print(f"  *** DID={chunk[n-1]:#06x} -> {uds}",flush=True)
        except Exception: pass
        finally: s.close()
        la+=batch
        if la%8192<batch: print(f"  ...{la:#06x} ({time.time()-t0:.0f}s)",flush=True)
    return hits

if __name__=="__main__":
    lo,hi=int(sys.argv[1],16),int(sys.argv[2],16)
    t0=time.time(); h=sweep(lo,hi)
    print(f"DONE {lo:#06x}-{hi:#06x} hits={len(h)} elapsed={time.time()-t0:.0f}s")

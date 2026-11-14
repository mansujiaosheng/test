"""Enumerate DoIP payload types on 13400 to find un-enumerated interfaces."""
import sys, struct, socket
def pkt(pt,p=b""): return bytes([0x02,0xFD])+struct.pack(">H",pt)+struct.pack(">I",len(p))+p
def probe(pt, payload=b"", host="10.226.193.2", port=13400, wait=1.0):
    s=socket.socket(); s.settimeout(wait)
    try:
        s.connect((host,port)); s.sendall(pkt(pt,payload))
        hdr=b""
        while len(hdr)<8:
            c=s.recv(8-len(hdr))
            if not c: return None
            hdr+=c
        _,_,rt,ln=struct.unpack(">BBHI",hdr); pl=b""
        while len(pl)<ln:
            c=s.recv(ln-len(pl))
            if not c: break
            pl+=c
        return rt,pl
    except Exception:
        return None
    finally: s.close()

if __name__=="__main__":
    ranges=[(0x0000,0x0800),(0x4000,0x4100),(0x8000,0x8100),(0xE000,0xE100),(0xF000,0xF100)]
    seen={}
    for lo,hi in ranges:
        for pt in range(lo,hi):
            r=probe(pt)
            if r is None: continue
            rt,pl=r
            key=(rt,pl.hex()[:20])
            seen.setdefault(key,[]).append(pt)
    for (rt,plh),pts in sorted(seen.items(), key=lambda x:-len(x[1])):
        print(f"resp ptype={rt:#06x} body={plh:22s} n={len(pts):4d}  e.g. {[hex(p) for p in pts[:6]]}")

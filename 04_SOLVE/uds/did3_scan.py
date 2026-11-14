"""UDS allows 2- or 3-byte DIDs. We only ever scanned 2-byte. Try 3-byte."""
import sys, json, struct, socket, time
sys.path.insert(0,"04_SOLVE/uds")
from u import open_link
from solve_task04 import _recv
H=lambda t,p: bytes([0x02,0xFD])+struct.pack(">H",t)+struct.pack(">I",len(p))+p
SA=0x0E00; TA=0xE442
link,t=open_link("CV622697F82A936A1", verbose=True)
s=link.s
def diag(p,wait=0.4):
    s.sendall(H(0x8001,struct.pack(">H",SA)+struct.pack(">H",TA)+p))
    old=s.gettimeout(); s.settimeout(wait)
    try: r=_recv(s)
    except socket.timeout: r=None
    finally: s.settimeout(old)
    return r[1][4:].hex() if r and r[0]==0x8001 and len(r[1])>=5 else ""

print("=== 3-byte DID (22 F1A0 xx style) ===")
for hi in [0xF1A0,0xF1A1,0xF1A2,0xF1A3,0xF1A4,0xF000,0xF100,0x0000,0x0100]:
    for lo in range(0x00,0x100,1):
        did=struct.pack(">H",hi&0xFFFF)
        # 3-byte DID: hi16 + lo8 -> total 3 bytes
        d3=struct.pack(">H",hi)+bytes([lo])
        r=diag(bytes([0x22])+d3, wait=0.25)
        if r and not r.startswith("7f2231"):
            print(f"  *** 22 {d3.hex()} -> {r}",flush=True)
print("  (3-byte DID scan done)")

print("\n=== also try 22 with 3-byte F1A3xx only ===")
for lo in range(0x00,0x100):
    d3=b"\xf1\xa3"+bytes([lo])
    r=diag(bytes([0x22])+d3, wait=0.25)
    if r and not r.startswith("7f2231"):
        print(f"  *** 22 {d3.hex()} -> {r}",flush=True)
link.close()
print("done")

"""Helpers: fresh ticket + unlock (reusable by task05)."""
import sys, os, json, hashlib, struct, socket, zipfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from solve_task04 import hash8, C_DEV, diag_query, fetch_bundle, issue_ticket, DoIP, _pkt, _recv

TA=0xE442; SA=0x0E00; CGW=("10.226.193.2",13400)
_CACHE={}

def fresh_ticket(vin, workdir="work/t5"):
    os.makedirs(workdir, exist_ok=True)
    node=diag_query(vin)
    blob=fetch_bundle(node["firmwareCredential"])
    zp=os.path.join(workdir,"b.zip"); open(zp,"wb").write(blob)
    ex=os.path.join(workdir,"x")
    zipfile.ZipFile(zp).extractall(ex)
    j=issue_ticket(os.path.join(ex,"diagnostics"))
    j["issued_at"]=int(time.time())
    json.dump(j, open(os.path.join(workdir,"ticket.json"),"w"))
    return j["diagnosticTicket"]

class Link:
    """One DoIP connection with helpers."""
    def __init__(self, host=CGW[0], port=CGW[1], sa=SA):
        self.s=socket.socket(); self.s.settimeout(4); self.s.connect((host,port))
        self.s.sendall(_pkt(0x0005, struct.pack(">H",sa)+b"\x00"+b"\x00"*4)); _recv(self.s)
    def diag(self, payload, ta=TA, wait=1.5):
        self.s.sendall(_pkt(0x8001, struct.pack(">H",SA)+struct.pack(">H",ta)+payload))
        old=self.s.gettimeout(); self.s.settimeout(wait)
        try:
            r=_recv(self.s)
        except socket.timeout:
            r=None
        finally:
            self.s.settimeout(old)
        return r[1][4:].hex() if r and r[0]==0x8001 and len(r[1])>=5 else ""
    def close(self):
        try: self.s.close()
        except: pass

def unlock(vin, ticket, link=None, verbose=False):
    """1003 -> 2E F1A1(ticket) -> 27 01 -> 27 02(key). Returns (link, seed, key)."""
    own = link is None
    d = link or Link()
    d.diag(bytes.fromhex("1003"))
    r=d.diag(bytes.fromhex("2EF1A1")+ticket.encode())
    if not r.startswith("6ef1a1"): raise RuntimeError(f"ticket bind failed: {r} (ticket expired? TTL=600s)")
    sd=d.diag(bytes.fromhex("2701"))
    if not sd.startswith("6701"): raise RuntimeError(f"no seed: {sd}")
    seed=bytes.fromhex(sd[4:])
    key=hash8(seed[:8], hashlib.sha256(vin.encode()).digest()[:8], C_DEV)
    r2=d.diag(bytes.fromhex("2702")+key)
    if not r2.startswith("6702"): raise RuntimeError(f"sendKey failed: {r2}")
    if verbose: print(f"    seed={seed.hex()} key={key.hex()} unlock=6702")
    return d, seed, key

def open_link(vin, workdir="work/t5", verbose=False):
    """Fresh ticket + unlock on ONE connection. Returns link."""
    t=fresh_ticket(vin, workdir)
    if verbose: print(f"    ticket={t[:20]}... ({len(t)} chars)")
    d,_,_=unlock(vin, t, verbose=verbose)
    return d, t

"""Brute-force SecOC MAC construction against 13401 accept/reject oracle."""
import sys, socket, itertools, struct
sys.path.insert(0,"04_SOLVE/uds")
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
import hmac, hashlib

HOST,PORT="10.226.193.2",13401
KEY32=bytes.fromhex("693d2ab06a2fe1a6e1ada23ac8bbb08ec3a8ffbbc90015ddeff28e721c9f693d")
FRESH=bytes.fromhex("0000002daac9f4e3")
DATAID=struct.pack(">H",0x0200)
PAYLOAD=bytes(6)

def cmac(k,m):
    c=CMAC(algorithms.AES(k)); c.update(m); return c.finalize()

def send(frame, wait=0.8):
    s=socket.socket(); s.settimeout(wait)
    try:
        s.connect((HOST,PORT)); s.sendall(frame)
        try:
            d=s.recv(128)
            return ("RESP",d) if d else ("CLOSED",b"")
        except socket.timeout: return ("ALIVE",b"")
    except Exception as e: return ("ERR",str(e).encode())
    finally: s.close()

keys={"k32":KEY32,"k32[:16]":KEY32[:16],"k32[16:]":KEY32[16:],"k32[:24]":KEY32[:24]}
parts={"D":DATAID,"P":PAYLOAD,"F":FRESH}
results={}
tested=0
for kn,key in keys.items():
    if len(key) not in (16,24,32): continue
    for perm in itertools.permutations("DPF"):
        msg=b"".join(parts[c] for c in perm)
        for maclen in (8,):
            for alg in ("cmac","hmac"):
                if alg=="cmac": mac=cmac(key,msg)[:maclen]
                else: mac=hmac.new(key,msg,hashlib.sha256).digest()[:maclen]
                frame=DATAID+PAYLOAD+mac
                st,data=send(frame)
                tested+=1
                if st!="CLOSED":
                    print(f"  *** {kn} {''.join(perm)} {alg} -> {st} {data[:32].hex()}",flush=True)
                    results[(kn,''.join(perm),alg)]=st
print(f"tested {tested}; non-closed: {len(results)}")

#!/usr/bin/env python3
"""New-env, correct sequence: activation on same socket -> UDS on 0xE442 -> check 13401 gate."""
import socket, struct, time, json
H="10.226.193.2"
def pkt(pt,pl=b"",ver=2): return bytes([ver,0xFF-ver])+struct.pack(">H",pt)+struct.pack(">I",len(pl))+pl
def rx(s,t=3.0):
    s.settimeout(t); h=b""
    while len(h)<8:
        c=s.recv(8-len(h))
        if not c: return None
        h+=c
    v,i,pt,n=struct.unpack(">BBHI",h); d=b""
    while len(d)<n:
        c=s.recv(n-len(d))
        if not c: break
        d+=c
    return pt,d
def gate(tag,n=1):
    outs=[]
    for _ in range(n):
        s=socket.socket(); s.settimeout(3); s.connect((H,13401)); tc=time.time(); s.settimeout(1.2)
        try:
            c=s.recv(64); outs.append("FIN" if c==b"" else "DATA:"+c.hex())
        except socket.timeout: outs.append("OPEN")
        except ConnectionResetError: outs.append("RST")
        finally: s.close()
    print(json.dumps({"tag":tag,"gate":outs}),flush=True)
s=socket.socket(); s.settimeout(4); s.connect((H,13400))
s.sendall(pkt(0x0005, bytes.fromhex("0E000000000000"))); print(json.dumps({"act":rx(s)[1].hex()}),flush=True)
gate("baseline_after_act")
for name,uds in (("e442_10_03","1003"),("e442_31_01_ff00","3101FF00"),("e442_27_01","2701"),("e442_22_f1a3","22F1A3")):
    s.sendall(pkt(0x8001, bytes.fromhex("0E00E442")+bytes.fromhex("0E00E442")[:0]+bytes.fromhex(uds)))
    r=rx(s); print(json.dumps({name: None if r is None else [hex(r[0]), r[1].hex()]}),flush=True)
    gate("after_"+name,2)
s.close()

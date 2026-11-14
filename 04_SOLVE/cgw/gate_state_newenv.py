#!/usr/bin/env python3
"""New-env: does any DoIP activation type / 0x1220 session change the 13401 gate state?"""
import socket, struct, time, json, binascii
H="10.226.193.2"
def pkt(pt,pl=b"",ver=2): return bytes([ver,0xFF-ver])+struct.pack(">H",pt)+struct.pack(">I",len(pl))+pl
def rx(s,t=2.0):
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
def doip(pl):
    s=socket.socket(); s.settimeout(3); s.connect((H,13400)); s.sendall(pl)
    r=rx(s); s.close(); return None if r is None else [hex(r[0]), r[1].hex()]
def gate(tag,n=1):
    outs=[]
    for _ in range(n):
        s=socket.socket(); s.settimeout(3); s.connect((H,13401)); tc=time.time(); s.settimeout(1.2)
        try:
            c=s.recv(64); outs.append("FIN" if c==b"" else "DATA:"+c.hex())
        except socket.timeout: outs.append("OPEN")
        except ConnectionResetError: outs.append("RST")
        finally: s.close()
    print(json.dumps({"tag":tag,"gate":outs,"ts":time.strftime("%H:%M:%S")}),flush=True)
    return outs
gate("baseline")
for t in (0x00,0x01,0xE0,0xE1):
    r=doip(pkt(0x0005, bytes([0x0E,0x00,t])+bytes.fromhex("43575731")))  # OEM "CGW1"
    print(json.dumps({"act_type":hex(t),"resp":r}),flush=True)
    gate("after_act_%02x"%t)
# 0x1220 via functional 0xE442
r=doip(pkt(0x8001, bytes.fromhex("0E00E442")+bytes.fromhex("1003"))); print(json.dumps({"e442_1003":r}),flush=True)
gate("after_1220_1003",2)
r=doip(pkt(0x8001, bytes.fromhex("0E00E442")+bytes.fromhex("3101FF00"))); print(json.dumps({"e442_3101_ff00":r}),flush=True)
gate("after_1220_3101",2)

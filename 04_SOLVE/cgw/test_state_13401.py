#!/usr/bin/env python3
"""Round-3: is 13401 gated on DoIP routing activation state? (with retries)"""
import socket, struct, time, json, binascii, sys
sys.path.insert(0,"04_SOLVE/cgw")
from retry import connect_retry

HOST="10.229.221.2"; D=13400; C=13401
def pkt(pt,pl=b"",ver=2): return bytes([ver,0xFF-ver])+struct.pack(">H",pt)+struct.pack(">I",len(pl))+pl
def rx(s,timeout=3):
    s.settimeout(timeout); h=b""
    while len(h)<8:
        c=s.recv(8-len(h))
        if not c: return None
        h+=c
    v,i,pt,n=struct.unpack(">BBHI",h); d=b""
    while len(d)<n:
        c=s.recv(n-len(d))
        if not c: break
        d+=c
    return v,pt,d

def conn13401(tag, linger=2.0):
    try:
        s=connect_retry(HOST,C); tc=time.time(); s.settimeout(linger)
        try:
            c=s.recv(4096); te=time.time()
            r=dict(tag=tag, outcome=("FIN" if c==b"" else "DATA:"+binascii.hexlify(c).decode()),
                   close_after_connect_ms=round((te-tc)*1000,2))
        except socket.timeout:
            r=dict(tag=tag,outcome="STILL_OPEN",waited_ms=round((time.time()-tc)*1000,1))
        except ConnectionResetError:
            r=dict(tag=tag,outcome="RST",close_after_connect_ms=round((time.time()-tc)*1000,2))
        s.close()
    except Exception as e:
        r=dict(tag=tag,outcome="ERR",err=str(e))
    print(json.dumps(r),flush=True); return r

print("### A: baseline"); conn13401("baseline_before")

print("### B: DoIP activation then 13401")
try:
    d=connect_retry(HOST,D); d.sendall(pkt(0x0005, bytes.fromhex("0E000000000000")))
    r=rx(d); print(json.dumps(dict(step="routing_activation", resp=None if r is None else [hex(r[1]),binascii.hexlify(r[2]).decode()])),flush=True)
    time.sleep(0.2); conn13401("after_activation_socket_open")
    d.sendall(pkt(0x8001, bytes.fromhex("0E00100002"+"22F190")))
    r=rx(d); print(json.dumps(dict(step="uds22f190", resp=None if r is None else [hex(r[1]),binascii.hexlify(r[2]).decode()])),flush=True)
    conn13401("after_uds")
    d.close()
except Exception as e:
    print(json.dumps(dict(step="doip",err=str(e))),flush=True)

print("### C: source port 13400")
try:
    s=connect_retry(HOST,C,bind=("0.0.0.0",13400)); tc=time.time(); s.settimeout(2)
    try:
        c=s.recv(4096); print(json.dumps(dict(tag="srcport13400",outcome=("FIN" if c==b"" else "DATA:"+binascii.hexlify(c).decode()),close_ms=round((time.time()-tc)*1000,2))))
    except socket.timeout: print(json.dumps(dict(tag="srcport13400",outcome="STILL_OPEN")))
    except ConnectionResetError: print(json.dumps(dict(tag="srcport13400",outcome="RST",close_ms=round((time.time()-tc)*1000,2))))
    s.close()
except Exception as e: print(json.dumps(dict(tag="srcport13400",err=str(e))))

print("### D: 8 x connect-only latency")
lat=[]
for i in range(8):
    r=conn13401("sample_%d"%i, linger=1.5)
    if "close_after_connect_ms" in r: lat.append(r["close_after_connect_ms"])
    time.sleep(0.3)
print("### summary:", json.dumps(dict(n=len(lat),vals=lat)))

#!/usr/bin/env python3
"""Round-4: cross-host + TFO + DoIP session-state + timeline on 13401"""
import socket, struct, time, json, binascii, sys
sys.path.insert(0,"04_SOLVE/cgw")
from retry import connect_retry
D=13400; C=13401
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
def probe(host, tag, payload=b"", wait=1.5, tfo=False):
    try:
        s=socket.socket(); s.settimeout(4)
        if tfo:
            try:
                s.setsockopt(socket.IPPROTO_TCP, 30, 1)   # TCP_FASTOPEN_CONNECT
            except Exception as e:
                print(json.dumps(dict(tag=tag,note="TFO_opt_fail:%s"%e)),flush=True)
        s.connect((host,C)); tc=time.time()
        if payload: s.sendall(payload)
        s.settimeout(wait)
        try:
            c=s.recv(4096); te=time.time()
            r=dict(tag=tag,host=host,payload=payload[:24].hex(),outcome=("FIN" if c==b"" else "DATA:"+binascii.hexlify(c).decode()),close_ms=round((te-tc)*1000,2))
        except socket.timeout:
            r=dict(tag=tag,host=host,payload=payload[:24].hex(),outcome="STILL_OPEN",waited_ms=round((time.time()-tc)*1000,1))
        except ConnectionResetError:
            r=dict(tag=tag,host=host,payload=payload[:24].hex(),outcome="RST",close_ms=round((time.time()-tc)*1000,2))
        s.close()
    except Exception as e: r=dict(tag=tag,host=host,outcome="ERR",err=type(e).__name__+":"+str(e))
    print(json.dumps(r),flush=True); return r

print("### A: 10.230.164.4 (same service, other IP)")
for i in range(3): probe("10.230.164.4","164.4_connect_%d"%i); time.sleep(0.3)
probe("10.230.164.4","164.4_send16",b"\x00"*16); time.sleep(0.3)

print("### B: TFO connect+data on 10.229.221.2")
probe("10.229.221.2","tfo_connect_only",b"",tfo=True); time.sleep(0.3)
probe("10.229.221.2","tfo_send16",b"\x00"*16,tfo=True); time.sleep(0.3)

print("### C: DoIP 0x10 03 extended session then 13401")
try:
    d=connect_retry("10.229.221.2",D)
    d.sendall(pkt(0x0005, bytes.fromhex("0E000000000000"))); r=rx(d)
    print(json.dumps(dict(step="act",resp=[hex(r[1]),binascii.hexlify(r[2]).decode()])),flush=True)
    d.sendall(pkt(0x8001, bytes.fromhex("0E0010001003"))); r=rx(d)
    print(json.dumps(dict(step="10_03",resp=[hex(r[1]),binascii.hexlify(r[2]).decode()])),flush=True)
    time.sleep(0.2); probe("10.229.221.2","after_10_03")
    d.close()
except Exception as e: print(json.dumps(dict(step="doip_err",err=str(e))),flush=True)

print("### D: 13401 first bytes = DoIP routing activation frame")
probe("10.229.221.2","doip_act_on_13401",pkt(0x0005, bytes.fromhex("0E000000000000"))); time.sleep(0.3)

print("### E: timeline 20 samples @3s (is it time-gated?)")
outcomes=[]
for i in range(20):
    r=probe("10.229.221.2","tl_%02d"%i,wait=1.2)
    outcomes.append(r.get("outcome"))
    time.sleep(1.8)
print(json.dumps(dict(step="timeline_summary",outcomes=outcomes)),flush=True)

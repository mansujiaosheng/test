#!/usr/bin/env python3
"""Poll range endpoints every N sec, log state changes to 03_EVIDENCE/monitor/."""
import socket, time, os, json, datetime
OUT="03_EVIDENCE/monitor"
os.makedirs(OUT,exist_ok=True)
TARGETS=[("10.224.139.5",8080),("10.224.139.6",8080),("10.224.139.7",8080),
         ("10.229.221.2",13401),("10.230.164.3",8443),("10.230.164.2",8080)]
state={}
def probe(h,p,timeout=1.0):
    s=socket.socket(); s.settimeout(timeout)
    try:
        t0=time.time(); s.connect((h,p)); dt=(time.time()-t0)*1000
        try:
            s.settimeout(0.4); d=s.recv(64)
            return f"open:{dt:.0f}ms:recv{len(d)}"
        except socket.timeout:
            return f"open:{dt:.0f}ms"
    except Exception as e:
        return "closed"
    finally: s.close()
log=open(f"{OUT}/monitor.log","a",encoding="utf-8")
while True:
    ts=datetime.datetime.now().strftime("%H:%M:%S")
    for h,p in TARGETS:
        st=probe(h,p)
        k=f"{h}:{p}"
        if state.get(k)!=st:
            state[k]=st
            line=f"{ts} CHANGE {k} -> {st}"
            print(line,flush=True); log.write(line+"\n"); log.flush()

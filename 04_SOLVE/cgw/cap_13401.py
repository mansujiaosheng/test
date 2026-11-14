#!/usr/bin/env python3
"""Capture 13401 TCP session at packet level (scapy/Npcap on the OpenVPN TAP)."""
import socket, time, threading, json
from scapy.all import conf, sniff, wrpcap, TCP, IP
IFACE=r"\Device\NPF_{42C6004D-50E7-43F6-BA07-8F0CA0F5171F}"
HOST="10.229.221.2"; PORT=13401
pkts=[]
def worker(label, payload, hold):
    time.sleep(0.6)
    s=socket.socket(); s.settimeout(3); s.connect((HOST,PORT)); t0=time.time()
    if payload: s.sendall(payload)
    time.sleep(hold)
    try: s.recv(100)
    except Exception: pass
    s.close()
    print("done", label, round(time.time()-t0,3), flush=True)

th=[threading.Thread(target=worker,args=("connect_only",b"",1.0)),
    threading.Thread(target=worker,args=("send16",b"\x00"*16,1.0))]
for t in th: t.start(); time.sleep(1.2)
for t in th: t.join()
# capture around them
sn=sniff(iface=IFACE, filter="host %s and tcp port %d"%(HOST,PORT), timeout=6, store=True)
wrpcap("03_EVIDENCE/cgw/0508_13401_session.pcap", sn)
print("captured", len(sn))
for p in sn:
    if IP in p and TCP in p:
        t=p[TCP]; ip=p[IP]
        fa=p.time
        print(json.dumps(dict(t=round(fa,6), src=ip.src, sport=t.sport, dst=ip.dst, dport=t.dport,
                              flags=str(t.flags), seq=t.seq, ack=t.ack, len=len(bytes(t.payload)),
                              win=t.window, ttl=ip.ttl, payload=bytes(t.payload)[:24].hex())))

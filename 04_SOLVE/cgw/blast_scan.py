#!/usr/bin/env python3
"""Async-sniffer SYN blast scan: send all SYNs, collect SYN-ACKs. No per-chunk waits."""
import sys, json, time, random
from scapy.all import conf, AsyncSniffer, send, IP, TCP
conf.verb=0
IF=r"\Device\NPF_{42C6004D-50E7-43F6-BA07-8F0CA0F5171F}"
def scan(host, ports, rounds=2, listen=6.0):
    iface_sn=AsyncSniffer(iface=IF, filter="tcp and src host %s"%host, store=True)
    iface_sn.start(); time.sleep(0.8)
    t0=time.time()
    for r in range(rounds):
        pkts=[IP(dst=host)/TCP(sport=random.randint(20000,60000), dport=p, flags="S") for p in ports]
        send(pkts, verbose=0, inter=0)
        print("round",r,"sent",len(pkts),"in",round(time.time()-t0,1),"s", flush=True)
        time.sleep(1.5)
    time.sleep(listen)
    iface_sn.stop()
    open_ports=set()
    for p in iface_sn.results:
        if IP in p and TCP in p and (p[TCP].flags & 0x12)==0x12:
            open_ports.add(p[TCP].sport)
    return sorted(open_ports)

if __name__=="__main__":
    host=sys.argv[1]
    ports=list(range(1,65536))
    t=time.time()
    res=scan(host, ports)
    print(json.dumps(dict(host=host, open=res, elapsed=round(time.time()-t,1))), flush=True)

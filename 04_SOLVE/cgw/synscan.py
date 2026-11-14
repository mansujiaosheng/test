#!/usr/bin/env python3
"""Robust scapy SYN scanner (retransmits unanswered) - nmap crashes in this env."""
import sys, json, time, random
from scapy.all import conf, sr, IP, TCP, RandShort
conf.verb=0

def scan(host, ports, chunk=3000, timeout=1.2, retry_timeout=2.5, rescan=True):
    opened=set(); closed=set(); unknown=set()
    def one_round(plist, to, ch):
        unans_all=[]
        for i in range(0,len(plist),ch):
            c=plist[i:i+ch]
            pkts=[IP(dst=host)/TCP(sport=random.randint(20000,60000), dport=p, flags="S") for p in c]
            ans,unans=sr(pkts, timeout=to, verbose=0, multi=False)
            for s,r in ans:
                if r[TCP].flags & 0x12 == 0x12: opened.add(r[TCP].sport)
                elif r[TCP].flags & 0x04: closed.add(r[TCP].sport)
            unans_all += [p[TCP].dport for p in unans]
        return unans_all
    t0=time.time()
    u1=one_round(ports, timeout, chunk)
    u2=one_round(u1, retry_timeout, chunk) if rescan and u1 else u1
    unknown=set(u2)
    return dict(host=host, elapsed=round(time.time()-t0,1), open=sorted(opened),
                closed_n=len(closed), unknown=sorted(unknown))

if __name__=="__main__":
    mode=sys.argv[1]
    if mode=="full":
        hosts=sys.argv[2:]
        for h in hosts:
            r=scan(h, list(range(1,65536)))
            print(json.dumps(r), flush=True)
    elif mode=="sweep":
        ports=list(map(int,sys.argv[2].split(",")))
        nets=["10.229.221.%d"%i for i in range(1,255)]+["10.230.164.%d"%i for i in range(1,255)]
        res=[]
        for i in range(0,len(nets),40):
            batch=nets[i:i+40]
            pk=[IP(dst=h)/TCP(sport=random.randint(20000,60000), dport=p, flags="S") for h in batch for p in ports]
            ans,unans=sr(pk, timeout=1.5, verbose=0, multi=False)
            for s,r in ans:
                if r[TCP].flags & 0x12 == 0x12:
                    res.append((r[IP].src, r[TCP].sport))
        print(json.dumps(dict(ports=ports, open=sorted(set(res)))), flush=True)

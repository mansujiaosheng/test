"""E5: 契约收尾 + 协议层 + headers 全量对比。
目标：确认 (a) 响应头是否随输入变化；(b) 是否存在中间代理（TE+CL / pipelining / 1.0）；
(c) variables 里放 op 名是否会切换分支。
"""
import json, socket, hashlib, urllib.request, urllib.error

HOST, PORT = "10.230.164.2", 8080
DEMO = '{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN = "CV6FF52FEE9EDDD86"

def full(label, body, headers=None):
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    r = urllib.request.Request(f"http://{HOST}:{PORT}/graphql", data=body.encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(r, timeout=8) as resp:
            rb, code, hdrs = resp.read(), resp.status, list(resp.headers.items())
    except urllib.error.HTTPError as e:
        rb, code, hdrs = e.read(), e.code, list(e.headers.items())
    print(f"--- {label} status={code} len={len(rb)}")
    for k, v in hdrs:
        print(f"    {k}: {v}")
    print(f"    body={rb[:150]!r}")
    return code, rb, hdrs

# 1. 响应头对比：正常 vs 400
full("baseline", '{"query":"{vehicles{vin}}"}')
full("invalid", 'notjson')
full("realvin_query", '{"query":"{vehicle(vin:\\"%s\\"){vin}}"}' % VIN)
full("realvin_vars", json.dumps({"query": "query($vin:String){vehicles(vin:$vin){vin}}", "variables": {"vin": VIN}}))

# 2. variables 里放 op 名
for op in ["ota", "Ota", "campaign", "diagnostics", "vehicle", "vehicles", "admin", "fleet"]:
    for k in ["op", "operation", "operationName", "action", "kind", "type", "name", "field"]:
        code, rb, _ = 0, b"", None
        h = {"Content-Type": "application/json"}
        body = json.dumps({"query": "{vehicles{vin}}", "variables": {k: op}})
        r = urllib.request.Request(f"http://{HOST}:{PORT}/graphql", data=body.encode(), headers=h, method="POST")
        try:
            with urllib.request.urlopen(r, timeout=8) as resp:
                rb, code = resp.read(), resp.status
        except urllib.error.HTTPError as e:
            rb, code = e.read(), e.code
        if rb.decode().strip() != DEMO:
            print(f"DIFF vars[{k}]={op} -> {code} {rb[:200]}")
print("variables-op 扫描完成")

# 3. 协议层：TE+CL、chunked、HTTP/1.0、pipelining
def raw(data, label, wait=3.0):
    s = socket.socket(); s.settimeout(wait); s.connect((HOST, PORT))
    s.sendall(data)
    out = b""
    try:
        while len(out) < 4000:
            c = s.recv(4096)
            if not c: break
            out += c
    except socket.timeout:
        pass
    s.close()
    print(f"--- RAW {label} ---\n{out[:600]!r}")
    return out

body = b'{"query":"{vehicles{vin}}"}'
raw(b"POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n" % (len(body), len(body), body), "TE+CL")
raw(b"POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n" % (len(body), body), "chunked")
raw(b"POST /graphql HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body), "HTTP/1.0")
raw(b"POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%sPOST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body, len(body), body), "pipeline x2")
raw(b"POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n{\"que", "truncated body")

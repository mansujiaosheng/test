"""DoIP (ISO 13400) 最小客户端：车辆识别 + 路由激活 + UDS 只读请求。
只读写操作：0x0001 车辆识别、0x0005 路由激活、0x8001 诊断消息（只读 DID / 只读 UDS）。
"""
import socket, struct, sys, time, json

HOST, PORT = "10.230.164.4", 13400
PROTO = b"\x02\xfd"

def doip(typ, payload, timeout=6.0, sock=None):
    own = sock is None
    if own:
        sock = socket.create_connection((HOST, PORT), timeout=timeout)
        sock.settimeout(timeout)
    msg = PROTO + struct.pack(">H", typ) + struct.pack(">I", len(payload)) + payload
    sock.sendall(msg)
    hdr = b""
    while len(hdr) < 8:
        c = sock.recv(8 - len(hdr))
        if not c: raise RuntimeError("closed")
        hdr += c
    ver, inv, rtyp, rlen = hdr[0], hdr[1], struct.unpack(">H", hdr[2:4])[0], struct.unpack(">I", hdr[4:8])[0]
    body = b""
    while len(body) < rlen:
        c = sock.recv(rlen - len(body))
        if not c: break
        body += c
    if own:
        sock.close()
    return rtyp, body, msg.hex()

def parse_vehicle_ident(body):
    vin = body[0:17].decode("ascii", "replace")
    la = struct.unpack(">H", body[17:19])[0]
    eid = body[19:25].hex()
    gid = body[25:31].hex()
    fa = body[31] if len(body) > 31 else None
    return {"vin": vin, "logical_address": hex(la), "eid": eid, "gid": gid, "further_action": fa, "raw": body.hex()}

ev = {"target": f"{HOST}:{PORT}", "steps": []}

# 1) 车辆识别请求 0x0001（无 EID）
typ, body, sent = doip(0x0001, b"")
info = parse_vehicle_ident(body)
ev["steps"].append({"step": "vehicle_identification_request", "sent": sent, "resp_type": hex(typ), "resp": body.hex(), "parsed": info})
print("[1] VehicleIdentificationResponse:", json.dumps(info, ensure_ascii=False))

# 2) 路由激活 0x0005
sock = socket.create_connection((HOST, PORT), timeout=6)
sock.settimeout(6)
for sa in [0x0E00, 0x0E80, 0x0F01, 0x1000]:
    payload = struct.pack(">H", sa) + b"\x00" + b"\x00\x00\x00\x00"
    try:
        typ, body, sent = doip(0x0005, payload, sock=sock)
        code = body[4] if len(body) > 4 else None
        ev["steps"].append({"step": "routing_activation", "sa": hex(sa), "sent": sent,
                            "resp_type": hex(typ), "resp": body.hex(), "code": hex(code) if code is not None else None})
        print(f"[2] routing activation SA={hex(sa)} code={hex(code) if code is not None else None} resp={body.hex()}")
        if code == 0x10:
            break
    except Exception as e:
        print(f"[2] routing activation SA={hex(sa)} err={e}")
        ev["steps"].append({"step": "routing_activation", "sa": hex(sa), "err": str(e)})
        sock.close(); sock = socket.create_connection((HOST, PORT), timeout=6); sock.settimeout(6)

# 3) 诊断消息：读 VIN (0x22 F190)，目标 LA 用识别到的地址
TA = int(info["logical_address"], 16)
tests = [
    ("read_vin", bytes.fromhex("22F190")),
    ("read_partnumber", bytes.fromhex("22F187")),
    ("read_sw_version", bytes.fromhex("22F195")),
    ("session_default_ext", bytes.fromhex("1003")),
    ("read_vin_again", bytes.fromhex("22F190")),
    ("read_active_dtc", bytes.fromhex("1902FF")),
]
for name, uds in tests:
    payload = struct.pack(">H", 0x0E00) + struct.pack(">H", TA) + uds
    try:
        typ, body, sent = doip(0x8001, payload, sock=sock)
        if typ == 0x8001:
            sa, ta = struct.unpack(">H", body[0:2])[0], struct.unpack(">H", body[2:4])[0]
            uds_resp = body[4:].hex()
            print(f"[3] {name}: SA={hex(sa)} TA={hex(ta)} uds={uds_resp}")
            ev["steps"].append({"step": name, "sent": sent, "resp_type": hex(typ), "resp": body.hex(), "uds": uds_resp})
        else:
            print(f"[3] {name}: non-diag resp type={hex(typ)} body={body.hex()}")
            ev["steps"].append({"step": name, "sent": sent, "resp_type": hex(typ), "resp": body.hex()})
    except Exception as e:
        print(f"[3] {name}: err={e}")
        ev["steps"].append({"step": name, "sent": payload.hex(), "err": str(e)})
        break
sock.close()
json.dump(ev, open(r"D:\qwb\03_EVIDENCE\tsp\0205_doip_ident.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)

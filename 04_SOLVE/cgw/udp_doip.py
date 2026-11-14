#!/usr/bin/env python3
"""DoIP over UDP probe (13400 and 13401).

ISO 13400-2 uses UDP for: vehicle identification request (0x0001),
vehicle identification request with EID (0x0002), with VIN (0x0003),
and receives announcements (0x0004). Also probes entity status (0x4001) and
power-mode info (0x4003) over UDP, plus a raw ptype sweep, since some
gateways answer more over UDP than TCP.
"""
import socket, struct, binascii, time, json, os, sys

HOSTS = ["10.229.221.2", "10.230.164.4"]
PORTS = [13400, 13401]


def pkt(ptype, payload=b"", ver=0x02):
    return bytes([ver, 0xFF - ver]) + struct.pack(">H", ptype) + struct.pack(">I", len(payload)) + payload


def udp(host, port, payload, wait=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(wait)
    t0 = time.time()
    try:
        s.sendto(payload, (host, port))
    except OSError as e:
        return {"error": repr(e)}
    out = []
    while True:
        try:
            d, addr = s.recvfrom(65535)
        except socket.timeout:
            break
        except OSError as e:
            out.append({"error": repr(e)})
            break
        out.append({"from": "%s:%d" % addr, "hex": binascii.hexlify(d).decode(),
                    "len": len(d)})
        if len(out) > 8:
            break
    s.close()
    return {"sent": binascii.hexlify(payload).decode(), "rx": out,
            "ms": round((time.time() - t0) * 1000, 1)}


def main():
    rows = []
    names = {0x0001: "vehicle_ident_request",
             0x0002: "vehicle_ident_request_with_EID",
             0x0003: "vehicle_ident_request_with_VIN",
             0x4001: "entity_status_request",
             0x4003: "power_mode_info_request",
             0x0005: "routing_activation(udp)",
             0x0007: "alive_check_request",
             0x0008: "alive_check_response(odd)"}
    for host in HOSTS:
        for port in PORTS:
            for pt, name in names.items():
                payload = b""
                if pt == 0x0002:
                    payload = bytes.fromhex("060000001000")
                elif pt == 0x0003:
                    payload = b"CV6FF52FEE9EDDD86"
                elif pt == 0x0005:
                    payload = bytes.fromhex("0E000000000000")
                r = udp(host, port, pkt(pt, payload))
                key = "%s:%d 0x%04X %s" % (host, port, pt, name)
                hit = bool(r.get("rx"))
                rows.append({"host": host, "port": port, "ptype": "0x%04X" % pt,
                             "name": name, **r})
                print("%-58s %s %s" % (key, "REPLY" if hit else "no-reply",
                                       json.dumps(r.get("rx"))[:160]), flush=True)
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "udp_doip.json"), "w") as f:
        json.dump(rows, f, indent=2)
    print("=== replies:", sum(1 for r in rows if r.get("rx")), "/", len(rows))


if __name__ == "__main__":
    main()

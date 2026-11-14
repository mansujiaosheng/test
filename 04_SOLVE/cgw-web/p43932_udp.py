#!/usr/bin/env python3
"""Characterise TCP/43932 (the only DROPped port on the CGW) and sweep UDP.

For 43932 we distinguish three outcomes that a plain nmap "filtered" conflates:
  refused  -> RST            (closed, no service)
  dropped  -> timeout        (silent DROP rule, or heavily rate-limited)
  accepted -> SYN-ACK        (service present)

We use a plain connect() with an explicit 8 s budget, three times, and also try
from the sibling IP 10.230.164.4 so we can tell whether the DROP is per-source.
"""
import socket, time, json, os, struct

OUT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "..", "..", "03_EVIDENCE", "cgw-web",
                                   "0605_port43932_and_udp.txt"))


def tcp_probe(host, port, budget=8.0):
    t0 = time.perf_counter()
    s = socket.socket()
    s.settimeout(budget)
    try:
        s.connect((host, port))
        dt = (time.perf_counter() - t0) * 1000
        s.close()
        return {"host": host, "port": port, "outcome": "OPEN", "ms": round(dt, 1)}
    except ConnectionRefusedError:
        return {"host": host, "port": port, "outcome": "REFUSED",
                "ms": round((time.perf_counter() - t0) * 1000, 1)}
    except socket.timeout:
        return {"host": host, "port": port, "outcome": "DROPPED",
                "ms": round((time.perf_counter() - t0) * 1000, 1)}
    except OSError as e:
        return {"host": host, "port": port, "outcome": "ERR:%s" % e,
                "ms": round((time.perf_counter() - t0) * 1000, 1)}
    finally:
        try:
            s.close()
        except Exception:
            pass


def udp_probe(host, port, payload=b"\x00", budget=2.0):
    """ICMP port-unreachable surfaces as ECONNRESET on the *next* recv on Windows."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(budget)
    try:
        s.sendto(payload, (host, port))
    except OSError as e:
        return {"host": host, "port": port, "outcome": "SEND_ERR:%s" % e}
    try:
        data, addr = s.recvfrom(4096)
        return {"host": host, "port": port, "outcome": "RESPONSE",
                "rx_hex": data[:64].hex(), "rx_len": len(data), "addr": str(addr)}
    except socket.timeout:
        return {"host": host, "port": port, "outcome": "NO_REPLY"}
    except ConnectionResetError:
        return {"host": host, "port": port, "outcome": "ICMP_UNREACH"}
    except OSError as e:
        return {"host": host, "port": port, "outcome": "ERR:%s" % e}
    finally:
        s.close()


def main():
    lines = []
    print("=== TCP 43932 characterisation ===")
    for host in ("10.229.221.2", "10.230.164.4"):
        for i in range(3):
            r = tcp_probe(host, 43932, budget=6.0)
            print(json.dumps(r), flush=True)
            lines.append(json.dumps(r))
    # control: a known-closed and a known-open port on the same run
    for port in (13400, 9999):
        r = tcp_probe("10.229.221.2", port, budget=6.0)
        print("control", json.dumps(r), flush=True)
        lines.append("control " + json.dumps(r))

    print("\n=== UDP sweep ===")
    udp_ports = [53, 67, 68, 69, 123, 137, 161, 500, 520, 623, 1900, 3702,
                 5353, 13400, 43932, 47808]
    for host in ("10.229.221.2", "10.230.164.4"):
        for p in udp_ports:
            r = udp_probe(host, p)
            if r["outcome"] not in ("ICMP_UNREACH", "NO_REPLY") or p == 13400:
                print(json.dumps(r), flush=True)
            lines.append(json.dumps(r))

    # DoIP UDP vehicle-announcement / identification semantics on 13400
    print("\n=== DoIP over UDP 13400 ===")
    # 0x0001 VehicleIdentificationRequest, no payload; 0x0003 with VIN
    cases = {
        "udp_ident_nopayload": bytes.fromhex("02fd000100000000"),
        "udp_ident_with_vin_eid": bytes.fromhex("02fd000300000011") + b"CV6FF52FEE9EDDD86",
        "udp_entity_status": bytes.fromhex("02fd000400000000"),
        "udp_alive_check": bytes.fromhex("02fd000700000000"),
    }
    for label, payload in cases.items():
        r = udp_probe("10.229.221.2", 13400, payload, budget=3.0)
        r["label"] = label
        print(label, json.dumps(r), flush=True)
        lines.append(json.dumps(r))

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("# TCP/43932 characterisation + UDP sweep\n")
        f.write("# time: %s\n\n" % time.strftime("%Y-%m-%d %H:%M:%S%z"))
        f.write("\n".join(lines))
    print("\nevidence:", OUT)


if __name__ == "__main__":
    main()

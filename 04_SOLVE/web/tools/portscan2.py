#!/usr/bin/env python3
"""Wave-2 port recon for the CV6 range.

Modes
  tcp    full 1-65535 connect scan against a host, rate limited (default 300 pps)
  tcpq   quick connect scan of an explicit interest list (fast sanity check)
  udp    UDP service probes (DNS/NTP/mDNS/CoAP/DoIP-announce/MQTT/3702)

Read-only: TCP connect + a single well-formed UDP datagram per probe.
No payloads that could mutate state; CoAP probes only issue GET discovery.
"""
import argparse, json, os, random, socket, struct, sys, threading, time
from queue import Queue, Empty

OUT = os.path.join(os.path.dirname(__file__), "..", "..", "..", "03_EVIDENCE", "web")

INTEREST = [21, 22, 23, 25, 53, 80, 111, 443, 445, 993, 1024, 1080, 1883, 1884,
            2049, 2375, 2376, 3000, 3306, 3389, 4000, 4242, 4443, 4840, 5000,
            5060, 5432, 5555, 5601, 5683, 5684, 5900, 5984, 6379, 6443, 7001,
            8000, 8008, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
            8089, 8090, 8091, 8099, 8161, 8181, 8222, 8300, 8400, 8443, 8444,
            8500, 8501, 8600, 8642, 8686, 8761, 8843, 8880, 8883, 8888, 8899,
            8983, 9000, 9001, 9042, 9090, 9091, 9092, 9093, 9100, 9200, 9300,
            9418, 9443, 9600, 9843, 9999, 10000, 10250, 10255, 11211, 13306,
            13400, 13401, 13402, 13403, 14000, 15000, 15672, 16000, 16379,
            17000, 18080, 18800, 19000, 19100, 20000, 21000, 23333, 23791,
            25000, 27017, 27018, 28017, 30000, 31337, 32000, 32768, 33333,
            40000, 44300, 47001, 48080, 50000, 50051, 50070, 54321, 55000,
            55555, 56000, 58080, 60000, 61616, 62078, 6380]

lock = threading.Lock()
hits = []
tried = 0

def tcp_probe(host, port, timeout):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True, None
    except socket.timeout:
        return False, "timeout"
    except ConnectionRefusedError:
        return False, "closed"
    except OSError as e:
        return False, type(e).__name__
    finally:
        try:
            s.close()
        except Exception:
            pass

def worker(host, q, timeout, rate_state):
    global tried
    while True:
        try:
            port = q.get_nowait()
        except Empty:
            return
        # token bucket: keep aggregate <= pps
        with lock:
            now = time.time()
            if now < rate_state["next"]:
                wait = rate_state["next"] - now
                rate_state["next"] += 1.0 / rate_state["pps"]
            else:
                wait = 0
                rate_state["next"] = now + 1.0 / rate_state["pps"]
        if wait > 0:
            time.sleep(wait)
        ok, why = tcp_probe(host, port, timeout)
        with lock:
            tried += 1
            if ok:
                hits.append(port)
                print(f"[+] {host}:{port}/tcp OPEN", flush=True)
        q.task_done()

def scan_tcp(host, ports, pps, timeout, threads):
    q = Queue()
    for p in ports:
        q.put(p)
    state = {"next": time.time(), "pps": float(pps)}
    ts = [threading.Thread(target=worker, args=(host, q, timeout, state), daemon=True)
          for _ in range(threads)]
    t0 = time.time()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    dt = time.time() - t0
    return sorted(hits), dt

# ---------------------------------------------------------------- UDP probes
def dns_query(txid=0x1337):
    # A query for cv6-fleet.local
    q = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for label in b"cv6-fleet".split(b"."):
        q += bytes([len(label)]) + label
    q += b"\x05local\x00" + struct.pack(">HH", 1, 1)
    return q, txid

def mdns_query():
    q = struct.pack(">HHHHHH", 0, 0x0000, 1, 0, 0, 0)
    for label in b"_services._dns-sd._udp.local".split(b"."):
        q += bytes([len(label)]) + label
    q += b"\x00" + struct.pack(">HH", 12, 1)
    return q

def ntp_query():
    return b"\x1b" + b"\x00" * 47

def coap_get(path=".well-known/core"):
    # CoAP v1, CON, GET, no token, Uri-Path options
    pkt = bytearray([0x40, 0x01, 0x00, 0x01])
    for seg in path.split("/"):
        pkt += bytes([0xB0 | len(seg)]) + seg.encode()
    return bytes(pkt)

def doip_announce():
    # DoIP vehicle announcement / identification request, generic header
    payload = b""
    hdr = struct.pack(">BBHI", 0x02, 0xFD, 0x0004, len(payload))
    return hdr + payload

def doip_routing_activation():
    # 0x0005 routing activation request, source address 0x0E00, activation type 0x00
    body = struct.pack(">HBBI", 0x0E00, 0x00, 0x00, 0x00000000)
    return struct.pack(">BBHI", 0x02, 0xFD, 0x0005, len(body)) + body

def mqtt_connect():
    # MQTT 3.1.1 CONNECT, client id "cv6probe", clean session
    cid = b"cv6probe"
    var = b"\x00\x04MQTT\x04\x02\x00\x3c"
    payload = struct.pack(">H", len(cid)) + cid
    body = var + payload
    return b"\x10" + bytes([len(body)]) + body

def wsdiscovery():
    return (b'<?xml version="1.0" encoding="utf-8"?><soap:Envelope '
            b'xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
            b'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            b'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
            b'<soap:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
            b'<wsa:MessageID>uuid:11111111-2222-3333-4444-555555555555</wsa:MessageID>'
            b'<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To></soap:Header>'
            b'<soap:Body><wsd:Probe/></soap:Body></soap:Envelope>')

def udp_probe(host, port, payload, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (host, port))
        data, addr = s.recvfrom(4096)
        return True, data, addr
    except socket.timeout:
        return False, b"", None
    except ConnectionResetError:
        return False, b"ICMP_PORT_UNREACH", None
    except OSError as e:
        return False, str(e).encode(), None
    finally:
        s.close()

def hexdump(b, n=128):
    b = b[:n]
    return b.hex()

def run_udp(hosts):
    lines = []
    probes = [
        ("dns-53", 53, dns_query()[0]),
        ("ntp-123", 123, ntp_query()),
        ("mdns-5353", 5353, mdns_query()),
        ("coap-5683", 5683, coap_get()),
        ("coaps-5684", 5684, coap_get()),
        ("doip-13400-announce", 13400, doip_announce()),
        ("doip-13400-routingact", 13400, doip_routing_activation()),
        ("mqtt-1883", 1883, mqtt_connect()),
        ("mqtt-8883", 8883, mqtt_connect()),
        ("wsd-3702", 3702, wsdiscovery()),
        ("ssdp-1900", 1900, b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                             b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'),
    ]
    for host in hosts:
        for name, port, payload in probes:
            ok, data, addr = udp_probe(host, port, payload)
            tag = "REPLY" if ok else "none "
            line = f"{host:14s} udp/{port:<6d} {name:22s} {tag} {len(data):4d}B  {hexdump(data)}"
            print(line, flush=True)
            lines.append(line)
    return lines

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["tcp", "tcpq", "udp"])
    ap.add_argument("--host", action="append", default=[])
    ap.add_argument("--pps", type=int, default=300)
    ap.add_argument("--timeout", type=float, default=0.9)
    ap.add_argument("--threads", type=int, default=120)
    ap.add_argument("--tag", default="w2")
    a = ap.parse_args()

    hosts = a.host or ["10.230.164.2", "10.230.164.3"]
    os.makedirs(OUT, exist_ok=True)

    if a.mode == "udp":
        lines = run_udp(hosts)
        p = os.path.join(OUT, f"udp_probe_{a.tag}.txt")
        open(p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        print("wrote", p)
        return

    ports = range(1, 65536) if a.mode == "tcp" else INTEREST
    allout = []
    for h in hosts:
        global hits, tried
        hits, tried = [], 0
        print(f"=== {h} scanning {len(list(ports))} ports @ {a.pps}pps ===", flush=True)
        got, dt = scan_tcp(h, list(ports), a.pps, a.timeout, a.threads)
        line = (f"{h}: open={got} tried={tried} elapsed={dt:.1f}s "
                f"effective_pps={tried/max(dt,1e-9):.0f}")
        print(line, flush=True)
        allout.append(line)
    p = os.path.join(OUT, f"scan_{a.mode}_{a.tag}.txt")
    open(p, "w", encoding="utf-8").write("\n".join(allout) + "\n")
    print("wrote", p)

if __name__ == "__main__":
    main()

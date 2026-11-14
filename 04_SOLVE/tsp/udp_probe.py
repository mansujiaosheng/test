#!/usr/bin/env python3
"""UDP surface probe + DoIP discovery probe for 10.230.164.2 / .3

Two questions:
  Q1  Is there any UDP service on the TSP / T-BOX host?
      Windows reports WSAECONNRESET when an ICMP port-unreachable comes back,
      so we can distinguish CLOSED (reset) from OPEN-OR-FILTERED (silence).
  Q2  Does DoIP (ISO 13400-2) answer on UDP 13400?
      Payloads: 0x02 generic vehicle identification request,
                0x01 VIN request with VIN,
                0x03 entity status request,
      also raw garbage to see if anything echoes.

Output: one line per (host, port, payload) with verdict + elapsed + first bytes.
"""
import socket
import struct
import sys
import time

TARGETS = ["10.230.164.2", "10.230.164.3"]
UDP_PORTS = [53, 67, 123, 137, 161, 500, 1900, 3702, 5353, 5355, 4789, 13400, 30490]


def udp_probe(host, port, payload, label, wait=2.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(wait)
    t0 = time.time()
    try:
        s.connect((host, port))
        s.send(payload)
        data = s.recv(2048)
        return "REPLY", (time.time() - t0) * 1000, data
    except ConnectionResetError:
        return "CLOSED(icmp-unreach)", (time.time() - t0) * 1000, b""
    except socket.timeout:
        return "SILENT", (time.time() - t0) * 1000, b""
    except OSError as e:
        # Windows: WinError 10054 == connection reset by peer (ICMP)
        if getattr(e, "winerror", None) == 10054:
            return "CLOSED(icmp-unreach)", (time.time() - t0) * 1000, b""
        return "ERR:%s" % e.__class__.__name__, (time.time() - t0) * 1000, b""
    finally:
        s.close()


def main():
    print("# udp_probe.py  %s" % time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    print()

    print("=" * 78)
    print("A. UDP port sweep (payload = b'\\x00' * 8, generic)")
    print("=" * 78)
    for host in TARGETS:
        for port in UDP_PORTS:
            st, ms, data = udp_probe(host, port, b"\x00" * 8, "generic")
            print("  %-14s:%-6d %-22s %7.1f ms  %s" % (host, port, st, ms, data[:24].hex()))

    print()
    print("=" * 78)
    print("B. DoIP discovery on UDP 13400 (ISO 13400-2 payload types)")
    print("=" * 78)
    vin = b"CV6FF52FEE9EDDD86"
    payloads = [
        ("0x0002 generic vehicle id request (no VIN)", b"\x02\x00\x00\x00\x00\x00\x00\x00"),
        ("0x0001 VIN request + VIN",                   b"\x01" + struct.pack(">H", 17) + b"\x00\x00\x00\x00" + vin),
        ("0x0003 entity status request",               b"\x03\x00\x00\x00\x00\x00\x00\x00"),
        ("0x0004 power mode information request",      b"\x04\x00\x00\x00\x00\x00\x00\x00"),
        ("raw garbage 16B",                            bytes(range(16))),
    ]
    for host in TARGETS:
        for label, pl in payloads:
            st, ms, data = udp_probe(host, 13400, pl, label, wait=3.0)
            print("  %-14s 13400/udp %-38s -> %-22s %7.1f ms  %s"
                  % (host, label, st, ms, data[:40].hex()))

    print()
    print("=" * 78)
    print("C. control: UDP 13400 to CGW 10.229.221.2 (known DoIP host, should answer)")
    print("=" * 78)
    for label, pl in payloads[:3]:
        st, ms, data = udp_probe("10.229.221.2", 13400, pl, label, wait=3.0)
        print("  %-14s 13400/udp %-38s -> %-22s %7.1f ms  %s"
              % ("10.229.221.2", label, st, ms, data[:40].hex()))
    print("done")


if __name__ == "__main__":
    main()

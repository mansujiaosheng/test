#!/usr/bin/env python3
"""Minimal DoIP (ISO 13400-2) client: vehicle identification + routing activation + UDS."""
import socket, struct, sys, binascii

CGW = ("10.230.164.4", 13400)

def pkt(ptype, payload=b"", ver=0x02):
    return bytes([ver, 0xFF - ver]) + struct.pack(">H", ptype) + struct.pack(">I", len(payload)) + payload

def recv_pkt(s):
    hdr = b""
    while len(hdr) < 8:
        c = s.recv(8 - len(hdr))
        if not c: return None
        hdr += c
    ver, inv, ptype, plen = struct.unpack(">BBHI", hdr)
    data = b""
    while len(data) < plen:
        c = s.recv(plen - len(data))
        if not c: break
        data += c
    return ver, ptype, data

def show(ver, ptype, data):
    print(f"  ver=0x{ver:02x} ptype=0x{ptype:04x} len={len(data)}")
    print(f"  hex={binascii.hexlify(data).decode()}")
    return data

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "ident"
    s = socket.socket(); s.settimeout(5); s.connect(CGW)
    if cmd == "ident":
        print("[*] Vehicle identification request (0x0001)")
        s.sendall(pkt(0x0001, b""))
        r = recv_pkt(s); d = show(*r)
        if r[1] == 0x0002 and len(d) >= 17:
            vin = d[:17].decode("ascii", "replace")
            la = struct.unpack(">H", d[17:19])[0]
            eid = binascii.hexlify(d[19:25]).decode()
            gid = binascii.hexlify(d[25:31]).decode()
            fa = d[31] if len(d) > 31 else None
            print(f"[+] VIN = {vin}")
            print(f"[+] LogicalAddress = 0x{la:04x}  EID={eid}  GID={gid}  furtherAction={fa}")

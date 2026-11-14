#!/usr/bin/env python3
"""CGW DoIP (ISO 13400-2) client library + CLI.

Reusable by any agent. Handles:
  - vehicle identification (0x0001)
  - routing activation (0x0005) with tester SA
  - diagnostic message (0x8001) SA/TA + UDS, with timing
  - raw ptype send
  - service-surface scan (NRC 0x11 == serviceNotSupported)
  - DID scan

Usage:
  python cgw_doip.py ident
  python cgw_doip.py ra
  python cgw_doip.py uds 22F190
  python cgw_doip.py uds 22F1A0 --ta 1000
  python cgw_doip.py svcs              # scan service bytes 0x10..0xFE
  python cgw_doip.py dids 0xF180 0xF200
  python cgw_doip.py raw 0005 0E000000000000
"""
import socket, struct, sys, binascii, time, json

DEFAULT_HOST = "10.229.221.2"
DEFAULT_PORT = 13400
TESTER_SA = 0x0E00
GW_TA = 0x1000


def pkt(ptype, payload=b"", ver=0x02):
    return bytes([ver, 0xFF - ver]) + struct.pack(">H", ptype) + struct.pack(">I", len(payload)) + payload


class DoIP:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, timeout=4.0, sa=TESTER_SA):
        self.host, self.port, self.timeout, self.sa = host, port, timeout, sa
        self.s = None

    def connect(self):
        self.s = socket.socket()
        self.s.settimeout(self.timeout)
        self.s.connect((self.host, self.port))
        return self

    def close(self):
        if self.s:
            try:
                self.s.close()
            except Exception:
                pass
            self.s = None

    def recv_pkt(self):
        hdr = b""
        while len(hdr) < 8:
            try:
                c = self.s.recv(8 - len(hdr))
            except socket.timeout:
                return None
            if not c:
                return None
            hdr += c
        ver, inv, ptype, plen = struct.unpack(">BBHI", hdr)
        data = b""
        while len(data) < plen:
            try:
                c = self.s.recv(plen - len(data))
            except socket.timeout:
                return None
            if not c:
                break
            data += c
        return ver, ptype, data

    def send(self, ptype, payload=b""):
        self.s.sendall(pkt(ptype, payload))

    def ident(self):
        self.send(0x0001)
        return self.recv_pkt()

    def ra(self, sa=None, act_type=0x00, oem=b"\x00\x00\x00\x00"):
        sa = self.sa if sa is None else sa
        self.send(0x0005, struct.pack(">H", sa) + bytes([act_type]) + oem)
        r = self.recv_pkt()
        return r

    def uds(self, uds: bytes, ta=None, sa=None, extra_timeout=None):
        """Return (raw_resp_bytes_or_None, elapsed_ms)."""
        ta = GW_TA if ta is None else ta
        sa = self.sa if sa is None else sa
        old = self.s.gettimeout()
        if extra_timeout:
            self.s.settimeout(extra_timeout)
        t0 = time.time()
        self.send(0x8001, struct.pack(">HH", sa, ta) + uds)
        r = self.recv_pkt()
        el = (time.time() - t0) * 1000
        self.s.settimeout(old)
        if r is None:
            return None, el
        ver, ptype, data = r
        if ptype == 0x8001 and len(data) >= 4:
            # SA(2) TA(2) + UDS
            return data[4:], el
        return data, el


def parse_uds(resp):
    if resp is None:
        return "NO RESPONSE"
    if len(resp) >= 3 and resp[0] == 0x7F:
        return "NEGATIVE service=0x%02X NRC=0x%02X" % (resp[1], resp[2])
    return "POSITIVE " + (binascii.hexlify(resp).decode() if resp else "")


def open_session(host=DEFAULT_HOST, port=DEFAULT_PORT, timeout=4.0):
    d = DoIP(host, port, timeout).connect()
    d.ident()
    r = d.ra()
    return d


if __name__ == "__main__":
    args = sys.argv[1:]
    cmd = args[0] if args else "ident"
    host = DEFAULT_HOST
    ta = GW_TA
    rest = args[1:]
    if "--host" in rest:
        i = rest.index("--host")
        host = rest[i + 1]
        rest = rest[:i] + rest[i + 2:]
    if "--ta" in rest:
        i = rest.index("--ta")
        ta = int(rest[i + 1], 16)
        rest = rest[:i] + rest[i + 2:]

    if cmd == "ident":
        d = DoIP(host).connect()
        ver, pt, data = d.ident()
        print("ptype=0x%04x hex=%s" % (pt, binascii.hexlify(data).decode()))
        print("VIN=%s LA=0x%04x" % (data[:17].decode("ascii", "replace"),
                                    struct.unpack(">H", data[17:19])[0]))

    elif cmd == "ra":
        d = DoIP(host).connect()
        d.ident()
        r = d.ra()
        print("ptype=0x%04x hex=%s" % (r[1], binascii.hexlify(r[2]).decode()))

    elif cmd == "uds":
        d = open_session(host)
        uds = bytes.fromhex(rest[0])
        resp, ms = d.uds(uds, ta=ta)
        print("TX %s -> %s (%.0fms)" % (binascii.hexlify(uds).decode().upper(),
                                        binascii.hexlify(resp).decode().upper() if resp else "None", ms))
        print(parse_uds(resp))

    elif cmd == "svcs":
        d = open_session(host)
        out = []
        for svc in range(0x10, 0xFF):
            resp, ms = d.uds(bytes([svc, 0x00]), ta=ta, extra_timeout=1.5)
            if resp is None:
                st = "silent"
            elif resp[0] == 0x7F and len(resp) >= 3:
                nrc = resp[2]
                st = "NRC%02X" % nrc
                if nrc == 0x11:
                    st += " (serviceNotSupported)"
            else:
                st = "POS-" + binascii.hexlify(resp).decode().upper()
            out.append((svc, st, ms))
            if not st.startswith("NRC11"):
                print("  svc 0x%02X -> %s  %.0fms" % (svc, st, ms), flush=True)
        print("--- summary: %d services, %d not-NRC11 ---" %
              (len(out), sum(1 for _, s, _ in out if not s.startswith("NRC11"))))

    elif cmd == "dids":
        lo = int(rest[0], 16)
        hi = int(rest[1], 16) if len(rest) > 1 else lo + 0x100
        d = open_session(host)
        hits = []
        for did in range(lo, hi):
            resp, ms = d.uds(bytes([0x22, did >> 8, did & 0xFF]), ta=ta, extra_timeout=1.2)
            if resp is None:
                continue
            if resp[0] == 0x7F:
                if len(resp) >= 3 and resp[2] == 0x31:
                    continue
                st = "NRC%02X" % resp[2] if len(resp) >= 3 else "NEG"
            else:
                st = "POS " + binascii.hexlify(resp).decode().upper()
                hits.append((did, st))
            print("  DID 0x%04X -> %s" % (did, st), flush=True)
        print("--- hits: %d" % len(hits))

    elif cmd == "raw":
        d = DoIP(host).connect()
        d.ident()
        d.ra()
        pt = int(rest[0], 16)
        payload = bytes.fromhex(rest[1]) if len(rest) > 1 else b""
        d.send(pt, payload)
        r = d.recv_pkt()
        print(r if r is None else "ptype=0x%04x hex=%s" % (r[1], binascii.hexlify(r[2]).decode()))
    else:
        print(__doc__)

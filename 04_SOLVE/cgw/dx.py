#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dx.py - strict DoIP/UDS client for CyberCar CGW (agent: cgw-doip)

Design goals
------------
* one request -> exactly one logical answer (retry on timeout, no silent NRC11/31 confusion)
* full wire transparency: every request/response hex is kept and can be persisted
* evidence writer continues the global sequence in 03_EVIDENCE/cgw/ (append-only)
* read-first guard: WRITE_SIDS is refused unless allow_write=True

Usage: import dx; d = dx.link(); print(d.uds(b'\x22\xf1\x90', ta=0x1000))
"""
import socket, struct, time, json, os, glob, binascii, sys

HOST = os.environ.get("DOIP_HOST", "10.229.221.2")
PORT = int(os.environ.get("DOIP_PORT", "13400"))
EV_DIR = r"D:\qwb\03_EVIDENCE\cgw"

# SIDs that modify ECU state. Guarded: never sent unless allow_write=True.
WRITE_SIDS = {0x11, 0x14, 0x2E, 0x2F, 0x31, 0x34, 0x35, 0x36, 0x37, 0x3D, 0x27, 0x28, 0x85, 0x29, 0x83}


def now():
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)) + ".%03d+08:00" % int((t % 1) * 1000)


def hx(b):
    return binascii.hexlify(b).decode().upper() if isinstance(b, (bytes, bytearray)) else str(b)


class Link:
    def __init__(self, host=HOST, port=PORT, timeout=4.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.s = None
        self.trace = []          # list of dict(type, ptype, hex, ts)
        self.sa = 0x0E00
        self.activated = False

    # ---------------- transport ----------------
    def connect(self, sa=0x0E00):
        self.s = socket.socket()
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.s.settimeout(self.timeout)
        self.s.connect((self.host, self.port))
        self.sa = sa
        self.activated = False
        return self

    def close(self):
        try:
            self.s and self.s.close()
        except Exception:
            pass
        self.s = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *a):
        self.close()

    def _send(self, ptype, payload=b"", ver=0x02):
        pkt = bytes([ver, 0xFF - ver]) + struct.pack(">H", ptype) + struct.pack(">I", len(payload)) + payload
        self.s.sendall(pkt)
        self.trace.append({"dir": "TX", "ptype": "0x%04x" % ptype, "hex": hx(payload), "ts": now()})

    def _read(self, timeout=None):
        self.s.settimeout(timeout or self.timeout)
        hdr = b""
        while len(hdr) < 8:
            c = self.s.recv(8 - len(hdr))
            if not c:
                return None
            hdr += c
        ver, inv, ptype, plen = struct.unpack(">BBHI", hdr)
        data = b""
        while len(data) < plen:
            c = self.s.recv(plen - len(data))
            if not c:
                break
            data += c
        self.trace.append({"dir": "RX", "ptype": "0x%04x" % ptype, "hex": hx(data), "ts": now()})
        return ver, ptype, data

    # ---------------- DoIP core ----------------
    def ident(self):
        self._send(0x0001)
        return self._collect(expect=(0x0004,))

    def ra(self, sa=None, act=0x00, oem=b"\x00\x00\x00\x00"):
        sa = self.sa if sa is None else sa
        self._send(0x0005, struct.pack(">H", sa) + bytes([act]) + oem)
        pk = self._collect(expect=(0x0006,))
        for _, pt, d in pk:
            if pt == 0x0006 and len(d) >= 4 and d[2] == 0x10:
                self.activated = True
        return pk

    def _collect(self, expect=(), drain=0.30):
        """Read packets until one of `expect` seen, then drain briefly. Returns list."""
        out = []
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                pk = self._read(timeout=max(0.2, min(self.timeout, deadline - time.time())))
            except socket.timeout:
                break
            except ConnectionResetError:
                out.append((None, -1, b""))
                break
            if pk is None:
                break
            out.append(pk)
            if pk[1] in expect:
                # short drain for trailing packets
                try:
                    while True:
                        more = self._read(timeout=drain)
                        if more is None:
                            break
                        out.append(more)
                        drain = 0.08
                except socket.timeout:
                    pass
                break
        return out

    def uds_raw(self, uds, ta=0x1000, sa=None, allow_write=False, timeout=None):
        """Send one diagnostic message; return dict with frames/acks/uds/ms."""
        sid = uds[0]
        if sid in WRITE_SIDS and not allow_write:
            raise PermissionError("SID 0x%02X is a write/service-state service; pass allow_write=True" % sid)
        sa = self.sa if sa is None else sa
        t0 = time.time()
        self._send(0x8001, struct.pack(">HH", sa, ta) + bytes(uds))
        pk = self._collect(expect=(0x8001, 0x8003), drain=0.20)
        ms = (time.time() - t0) * 1000
        frames, acks, nack = [], [], None
        for _, pt, d in pk:
            if pt == 0x8001 and len(d) >= 4:
                frames.append({"sa": struct.unpack(">H", d[0:2])[0],
                               "ta": struct.unpack(">H", d[2:4])[0],
                               "uds": d[4:]})
            elif pt == 0x8002:
                acks.append({"ptype": 0x8002, "hex": hx(d)})
            elif pt == 0x8003:
                acks.append({"ptype": 0x8003, "hex": hx(d)})
                if len(d) >= 5:
                    nack = d[4]
        uds_bytes = None
        if frames:
            uds_bytes = _assemble([f["uds"] for f in frames])
        return {"req": bytes(uds), "ta": ta, "sa": sa, "frames": frames,
                "uds": uds_bytes, "acks": acks, "nack": nack, "ms": round(ms, 1),
                "raw_pkts": [{"ptype": "0x%04x" % pt, "hex": hx(d)} for _, pt, d in pk if pt > 0]}

    def uds(self, uds, ta=0x1000, sa=None, allow_write=False, retries=1, timeout=None):
        last = None
        for i in range(retries + 1):
            r = self.uds_raw(uds, ta=ta, sa=sa, allow_write=allow_write, timeout=timeout)
            last = r
            if r["uds"] is not None or r["acks"] and r["nack"] is not None:
                return r
            time.sleep(0.15)
        return last


def _assemble(frames):
    """ISO-TP: 0x1N = first frame (len in 12 bits), 0x2N = consecutive, 0x0N = single."""
    if not frames:
        return None
    if len(frames) == 1:
        f = frames[0]
        if f and (f[0] & 0xF0) == 0x00:
            return f[1:1 + (f[0] & 0x0F)]
        return f
    f0 = frames[0]
    if f0 and (f0[0] & 0xF0) == 0x10:
        total = ((f0[0] & 0x0F) << 8) | f0[1]
        buf = f0[2:]
        for f in frames[1:]:
            if f and (f[0] & 0xF0) == 0x20:
                buf += f[1:]
        return buf[:total]
    return b"".join(frames)


def verdict(r):
    """Human one-liner for a uds_raw result."""
    if r is None:
        return "NONE"
    if r["acks"] and r["nack"] is not None and r["uds"] is None:
        return "NACK-code=0x%02X" % r["nack"]
    u = r["uds"]
    if u is None:
        return "NO-RESPONSE"
    if len(u) >= 3 and u[0] == 0x7F:
        return "NRC 0x%02X (srv 0x%02X)" % (u[2], u[1])
    return "POS " + hx(u)


# ---------------- evidence ----------------
def next_seq():
    nums = []
    for f in glob.glob(os.path.join(EV_DIR, "*.json")):
        b = os.path.basename(f)[:4]
        if b.isdigit():
            nums.append(int(b))
    return (max(nums) + 1) if nums else 1


def save(label, purpose, link, result, extra=None):
    seq = next_seq()
    rec = {
        "seq": seq,
        "ts": now(),
        "label": label,
        "purpose": purpose,
        "host": link.host if link else HOST,
        "port": link.port if link else PORT,
        "request": {"ta": "0x%04X" % result["ta"], "sa": "0x%04X" % result["sa"],
                    "uds": hx(result["req"])},
        "responses": result["raw_pkts"],
        "verdict": verdict(result),
        "elapsed_ms": result["ms"],
    }
    if extra:
        rec.update(extra)
    path = os.path.join(EV_DIR, "%04d_%s.json" % (seq, label))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, ensure_ascii=False)
    # append one-line wire summary
    wl = os.path.join(EV_DIR, "wire.log")
    resp = result["raw_pkts"][0]["hex"] if result["raw_pkts"] else "-"
    with open(wl, "a", encoding="utf-8") as f:
        f.write("%s  [%04d %s] TX 8001 %s -> RX %s | %s\n" % (
            time.strftime("%H:%M:%S"), seq, label,
            rec["request"]["uds"], resp, rec["verdict"]))
    return path, seq


def link(host=HOST, port=PORT, sa=0x0E00):
    d = Link(host, port).connect(sa)
    d.ra(sa)
    return d


if __name__ == "__main__":
    d = link()
    print("IDENT:", d.ident())
    for t in ("3E00", "22F190", "22F1A0", "10 01".replace(" ", ""), "10 03", "22F187"):
        r = d.uds(bytes.fromhex(t), allow_write=True)
        print("%-8s -> %-28s ms=%-7.1f frames=%s" % (t, verdict(r), r["ms"],
              [(hex(f["sa"]), hex(f["ta"]), hx(f["uds"])) for f in r["frames"]]))

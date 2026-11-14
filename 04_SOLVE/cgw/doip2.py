#!/usr/bin/env python3
"""CGW DoIP client v2 (cgw-doip agent).

Improvements over 05_TOOLS/cgw_doip.py:
  - collects ALL packets in a short drain window (handles 0x8002 ack + 0x8001 resp,
    and multiple frames)
  - ISO-TP reassembly if the ECU emits UDS 0x2x framing (first frame 0x1x / 0x2x)
  - strict one-request-one-answer mode with request/response edge logging
  - auto-numbered evidence writer (03_EVIDENCE/cgw/2NNN_*.json), append-only
"""
import socket, struct, sys, binascii, time, json, os, glob

HOST = "10.229.221.2"
PORT = 13400
EV_DIR = r"D:\qwb\03_EVIDENCE\cgw"

PT = {
    0x0000: "generic nack",
    0x0001: "vehicle identification request",
    0x0004: "vehicle announcement/identification response",
    0x0005: "routing activation request",
    0x0006: "routing activation response",
    0x0007: "alive check request",
    0x0008: "alive check response",
    0x8001: "diagnostic message",
    0x8002: "diag message positive ack",
    0x8003: "diag message negative ack",
    0x4001: "entity status request",
    0x4002: "entity status response",
    0x4003: "power mode info request",
    0x4003 + 1: "power mode info response",
}


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()) + ".%03d+08:00" % (int(time.time() * 1000) % 1000)


class DoIP:
    def __init__(self, host=HOST, port=PORT, timeout=3.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.s = None
        self.wire = []

    def connect(self):
        self.s = socket.socket()
        self.s.settimeout(self.timeout)
        self.s.connect((self.host, self.port))
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

    # ---------- raw ----------
    def send(self, ptype, payload=b"", ver=0x02):
        pkt = bytes([ver, 0xFF - ver]) + struct.pack(">H", ptype) + struct.pack(">I", len(payload)) + payload
        self.wire.append(("TX", ptype, payload))
        self.s.sendall(pkt)

    def _read_one(self):
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
        return ver, ptype, data

    def recv_all(self, drain=0.45, first_timeout=None):
        """Read first packet (blocking up to first_timeout), then drain `drain` s."""
        out = []
        t_first = first_timeout or self.timeout
        old = self.s.gettimeout()
        self.s.settimeout(t_first)
        t0 = time.time()
        try:
            r = self._read_one()
        except socket.timeout:
            r = None
        ms = (time.time() - t0) * 1000
        if r is not None:
            out.append(r)
            self.s.settimeout(drain)
            while True:
                try:
                    r2 = self._read_one()
                except socket.timeout:
                    break
                if r2 is None:
                    break
                out.append(r2)
                self.s.settimeout(drain)
        self.s.settimeout(old)
        for _, pt, d in out:
            self.wire.append(("RX", pt, d))
        return out, ms

    # ---------- DoIP ----------
    def ident(self):
        self.send(0x0001)
        pk, ms = self.recv_all()
        return pk, ms

    def ra(self, sa=0x0E00, act=0x00, oem=b"\x00\x00\x00\x00"):
        self.send(0x0005, struct.pack(">H", sa) + bytes([act]) + oem)
        pk, ms = self.recv_all()
        return pk, ms

    def uds(self, uds_bytes, ta=0x1000, sa=0x0E00, timeout=None):
        """Send diagnostic message, return (list_of_(ptype,hex), uds_bytes_or_None, ms)."""
        old = self.s.gettimeout()
        if timeout:
            self.s.settimeout(timeout)
        self.send(0x8001, struct.pack(">HH", sa, ta) + uds_bytes)
        pk, ms = self.recv_all(first_timeout=timeout or self.timeout)
        if timeout:
            self.s.settimeout(old)
        uds_frames = []
        acks = []
        for ver, pt, d in pk:
            if pt == 0x8001 and len(d) >= 4:
                uds_frames.append((struct.unpack(">H", d[0:2])[0], struct.unpack(">H", d[2:4])[0], d[4:]))
            elif pt in (0x8002, 0x8003):
                acks.append((pt, d))
        uds = None
        if uds_frames:
            # single frame
            if len(uds_frames) == 1:
                uds = uds_frames[0][2]
            else:
                uds = _assemble([f[2] for f in uds_frames])
        return pk, uds, ms, acks


def _assemble(frames):
    """ISO-TP-ish reassembly: first frame 0x1N (len 12bit), consecutive 0x2N."""
    if not frames:
        return None
    b0 = frames[0]
    if b0 and (b0[0] & 0xF0) == 0x10 and len(frames) > 1:
        total = ((b0[0] & 0x0F) << 8) | b0[1]
        buf = b0[2:]
        for f in frames[1:]:
            if f and (f[0] & 0xF0) == 0x20:
                buf += f[1:]
        return buf[:total]
    return b"".join(frames)


def parse(resp):
    if resp is None:
        return "NO RESPONSE"
    if len(resp) >= 3 and resp[0] == 0x7F:
        return "NEG srv=0x%02X NRC=0x%02X" % (resp[1], resp[2])
    return "POS " + binascii.hexlify(resp).decode().upper()


# ---------- evidence ----------
def next_seq(prefix=2):
    nums = [int(os.path.basename(f)[:4]) for f in glob.glob(os.path.join(EV_DIR, "*.json"))
            if os.path.basename(f)[:4].isdigit()]
    base = prefix * 1000
    nums = [n for n in nums if n >= base]
    return (max(nums) + 1) if nums else base + 1


def save(label, purpose, req, resp_pkts, extra=None, seq=None):
    seq = seq or next_seq()
    rec = {
        "label": label,
        "purpose": purpose,
        "request": req,
        "responses": [{"ptype": "0x%04x" % pt, "hex": binascii.hexlify(d).decode(), "len": len(d)}
                      for _, pt, d in resp_pkts],
        "seq": seq,
        "ts": now(),
    }
    if extra:
        rec.update(extra)
    path = os.path.join(EV_DIR, "%04d_%s.json" % (seq, label))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, ensure_ascii=False)
    return path, seq


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "base"
    if cmd == "base":
        d = DoIP().connect()
        pk, ms = d.ident()
        print("IDENT", ["0x%04x:%s" % (p, binascii.hexlify(x).decode()) for _, p, x in pk], "%.0fms" % ms)
        save("base_ident", "vehicle identification", {"ptype": "0x0001"}, pk, {"elapsed_ms": round(ms, 2)})
        pk, ms = d.ra(0x0E00)
        print("RA", ["0x%04x:%s" % (p, binascii.hexlify(x).decode()) for _, p, x in pk], "%.0fms" % ms)
        save("base_ra_sa0e00", "routing activation SA 0x0E00 act 0x00", {"ptype": "0x0005", "hex": "0E000000000000"},
             pk, {"elapsed_ms": round(ms, 2)})
        for t in ("3E00", "22F190", "10 03".replace(" ", ""), "22F1A0"):
            pk, uds, ms, acks = d.uds(bytes.fromhex(t))
            print("UDS %-8s -> %s  (%.0fms) acks=%s" % (t, parse(uds), ms, [("0x%04x" % a) for a, _ in acks]))
        d.close()

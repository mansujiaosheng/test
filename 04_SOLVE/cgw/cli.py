#!/usr/bin/env python3
"""Strict, self-synchronising DoIP/UDS client for the CGW target.

Why this exists: the ECU's answers are NOT aligned 1:1 with requests under load
(observed: a 0x3E00 answer surfaced while reading for 22F190). Every request is
therefore matched by echoed SID, and stale frames are recorded as `stale`, never
silently attributed to the current request.

Evidence is append-only, numbered from 2000 in 03_EVIDENCE/cgw/.
"""
import socket, struct, binascii, time, json, os, glob

HOST = "10.229.221.2"
PORT = 13400
EV = r"D:\qwb\03_EVIDENCE\cgw"
SEQ_FLOOR = 2000


def ts():
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)) + ".%03d+08:00" % int((t % 1) * 1000)


class Cli:
    def __init__(self, host=HOST, port=PORT, sock_timeout=1.0):
        self.host, self.port, self.st = host, port, sock_timeout
        self.s = socket.socket()
        self.s.settimeout(sock_timeout)
        self.s.connect((host, port))
        self.sa = 0x0E00
        self.ta = 0x1000
        self.stale = []

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # --- framing ---
    def _tx(self, ptype, payload=b""):
        self.s.sendall(bytes([0x02, 0xFD]) + struct.pack(">H", ptype) + struct.pack(">I", len(payload)) + payload)

    def _rx(self):
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
        return ptype, data

    def flush(self, quiet=0.20):
        """Discard anything already queued (bounded)."""
        self.s.settimeout(quiet)
        n = 0
        while True:
            try:
                r = self._rx()
            except socket.timeout:
                break
            except OSError:
                break
            if r is None:
                break
            n += 1
            if n > 40:
                break
        self.s.settimeout(self.st)
        return n

    # --- DoIP ---
    def ident(self, wait=3.0):
        self.flush()
        self._tx(0x0001)
        return self._wait_for(lambda pt, d: pt == 0x0004, wait)

    def ra(self, sa=None, act=0x00, oem=b"\x00\x00\x00\x00", wait=3.0):
        sa = self.sa if sa is None else sa
        self.flush()
        self._tx(0x0005, struct.pack(">H", sa) + bytes([act]) + oem)
        return self._wait_for(lambda pt, d: pt == 0x0006, wait)

    def _wait_for(self, pred, wait):
        """Collect packets until pred matches or `wait` seconds pass.

        Returns (matched_packet_or_None, all_packets, elapsed_ms).
        """
        t0 = time.time()
        got = []
        matched = None
        self.s.settimeout(0.3)
        while (time.time() - t0) < wait:
            try:
                r = self._rx()
            except socket.timeout:
                continue
            except OSError:
                break
            if r is None:
                break
            got.append(r)
            if matched is None and pred(*r):
                matched = r
        self.s.settimeout(self.st)
        return matched, got, (time.time() - t0) * 1000

    def uds(self, data: bytes, ta=None, sa=None, wait=6.0):
        """Send a diagnostic message and return the answer that ECHOES its SID.

        Returns dict(uds=bytes|None, ms=float, stale=[hex...], acks=[...], all=[...])
        """
        ta = self.ta if ta is None else ta
        sa = self.sa if sa is None else sa
        want_sid = data[0]
        self.flush()
        t0 = time.time()
        self._tx(0x8001, struct.pack(">HH", sa, ta) + data)

        stale = []
        acks = []
        allp = []
        answer = None
        deadline = t0 + wait
        self.s.settimeout(0.25)
        while time.time() < deadline:
            try:
                r = self._rx()
            except socket.timeout:
                # also bail early once we have an answer and 0.35s of quiet
                if answer is not None and (time.time() - t_last) > 0.35:
                    break
                continue
            except OSError:
                break
            if r is None:
                break
            t_last = time.time()
            pt, d = r
            allp.append((pt, d))
            if pt in (0x8002, 0x8003):
                acks.append((pt, binascii.hexlify(d).decode()))
                continue
            if pt != 0x8001 or len(d) < 4:
                stale.append("pt0x%04x:%s" % (pt, binascii.hexlify(d).decode()))
                continue
            body = d[4:]
            ok = (len(body) >= 2 and body[0] == 0x7F and body[1] == want_sid) or \
                 (body and body[0] == (want_sid + 0x40) & 0xFF)
            if ok and answer is None:
                answer = body
            else:
                stale.append(binascii.hexlify(body).decode().upper())
        self.s.settimeout(self.st)
        for st in stale:
            self.stale.append(st)
        return {"uds": answer, "ms": (time.time() - t0) * 1000, "stale": stale,
                "acks": acks, "all": [(p, binascii.hexlify(d).decode()) for p, d in allp]}

    # --- convenience ---
    def ensure_ra(self, sa=None, retries=3):
        for _ in range(retries):
            m, got, ms = self.ra(sa=sa)
            if m:
                return m[1], ms
            time.sleep(0.4)
        return None, 0.0


def pfmt(uds):
    if uds is None:
        return "NO-RESP"
    if len(uds) >= 3 and uds[0] == 0x7F:
        return "NEG srv=%02X NRC=%02X" % (uds[1], uds[2])
    return "POS " + binascii.hexlify(uds).decode().upper()


def next_seq():
    nums = []
    for f in glob.glob(os.path.join(EV, "*.json")):
        b = os.path.basename(f)[:4]
        if b.isdigit() and int(b) >= SEQ_FLOOR:
            nums.append(int(b))
    return (max(nums) + 1) if nums else SEQ_FLOOR + 1


def save(label, purpose, req, result, extra=None):
    """Append-only evidence record. `result` is a uds() dict or raw packet list."""
    seq = next_seq()
    rec = {"label": label, "purpose": purpose, "request": req, "ts": ts(), "seq": seq}
    if isinstance(result, dict) and "uds" in result:
        rec["responses"] = [{"ptype": "0x%04x" % p, "hex": h} for p, h in result["all"]]
        rec["uds_answer"] = binascii.hexlify(result["uds"]).decode().upper() if result["uds"] else None
        rec["parsed"] = pfmt(result["uds"])
        rec["elapsed_ms"] = round(result["ms"], 2)
        if result["stale"]:
            rec["stale_frames_discarded"] = result["stale"]
    else:
        rec["responses"] = [{"ptype": "0x%04x" % p, "hex": binascii.hexlify(d).decode()} for p, d in result]
    if extra:
        rec.update(extra)
    path = os.path.join(EV, "%04d_%s.json" % (seq, label))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, ensure_ascii=False)
    return seq, path

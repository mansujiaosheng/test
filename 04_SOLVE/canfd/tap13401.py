#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tap13401.py -- discover and speak whatever framing the CAN FD bridge uses.

State of knowledge
------------------
13401 sits next to the DoIP port 13400 on the central gateway.  Before the
bridge is opened it accepts TCP and then closes without sending a byte (the
earlier round measured accept-then-close, 13 payload shapes, 0 responses).  So
the framing is *unknown*, and guessing wrong is indistinguishable from "bridge
still closed".  This module exists to make that distinction in one shot the
moment the bridge opens.

What it does
------------
1. `detect()` probes the port with protocol-specific, bus-neutral handshakes
   (a version query, a socketcand greeting -- never a vehicle command) and
   records every byte in and out.
2. `FramingTransport` implements the isotp.Transport duck type for each
   framing family, so `bms_dump.py` can ride on top of whichever one wins.
3. `--self-test` stands up **local fake bridges** for sLCAN, socketcand and a
   raw-frame server, then asserts that `detect()` identifies each one and that
   a frame survives encode -> wire -> decode unmodified.  No target needed.

Framing families covered
------------------------
    slcan        ASCII  t<id><dlc><data>\\r        (LAWICEL; CAN FD via d/b)
    socketcand   ASCII  < send 0x7E1 8 02 10 03 > (Becker)
    candump      ASCII  (ts) can0 7E1#0210...
    raw8/16/64   bare frame data, size implied by the codec
    id+data      CAN ID (2/4 B) followed by the frame data
    len+frame    1/2/4-byte length prefix, then the frame data
    isotp        the bridge does ISO-TP itself (2-byte length + UDS bytes)

Read-only discipline
--------------------
Detection sends only: an sLCAN version request (`V\\r`), a socketcand greeting
(`< hi >`), and a bare CR.  None of them touch the bus or change ECU state.  No
CAN frame is transmitted by `detect()`.

CLI
---
    python tap13401.py --probe --host 10.226.193.2 --port 13401
    python tap13401.py --self-test
    python tap13401.py --monitor --host ... --port ... --framing slcan
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import isotp

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

FD_LEN_TO_DLC = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8,
                 12: 9, 16: 0xA, 20: 0xB, 24: 0xC, 32: 0xD, 48: 0xE, 64: 0xF}
DLC_TO_FD_LEN = {v: k for k, v in FD_LEN_TO_DLC.items()}


def _hx(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


# --------------------------------------------------------------------------- #
# codecs
# --------------------------------------------------------------------------- #

class Codec:
    name = "abstract"
    is_ascii = False
    frame_dl = 16
    #: True when one wire unit carries exactly one CAN frame with known size
    fixed_size = True

    def encode(self, frame: isotp.Frame) -> bytes:
        raise NotImplementedError

    def decode(self, buf: bytearray) -> Optional[tuple]:
        """Consume one frame from `buf`; return (Frame, consumed) or None."""
        raise NotImplementedError

    def describe(self) -> dict:
        return {"codec": self.name, "frame_dl": self.frame_dl,
                "ascii": self.is_ascii, "fixed_size": self.fixed_size}


class RawCodec(Codec):
    """Bare frame data; the frame size is implied by the codec."""

    def __init__(self, dl: int = 16, can_id: int = 0x7E9):
        self.frame_dl = dl
        self.name = f"raw{dl}"
        self.rx_id = can_id

    def encode(self, frame: isotp.Frame) -> bytes:
        data = frame.data
        if len(data) != self.frame_dl:
            data = data + bytes([0xCC]) * (self.frame_dl - len(data))
            data = data[:self.frame_dl]
        return bytes(data)

    def decode(self, buf: bytearray):
        if len(buf) < self.frame_dl:
            return None
        data = bytes(buf[:self.frame_dl])
        del buf[:self.frame_dl]
        return (isotp.Frame(can_id=self.rx_id, data=data, brs=True,
                            fd=self.frame_dl > 8, ts=time.perf_counter()),
                self.frame_dl)


class IdDataCodec(Codec):
    """CAN ID (2 or 4 bytes, big endian) + frame data."""

    def __init__(self, dl: int = 16, id_bytes: int = 4, endian: str = "big"):
        self.frame_dl = dl
        self.id_bytes = id_bytes
        self.endian = endian
        self.name = f"id{id_bytes}+{dl}"

    def encode(self, frame: isotp.Frame) -> bytes:
        data = frame.data + bytes([0xCC]) * (self.frame_dl - len(frame.data))
        return (frame.can_id.to_bytes(self.id_bytes, self.endian)
                + data[:self.frame_dl])

    def decode(self, buf: bytearray):
        need = self.id_bytes + self.frame_dl
        if len(buf) < need:
            return None
        can_id = int.from_bytes(bytes(buf[:self.id_bytes]), self.endian)
        data = bytes(buf[self.id_bytes:need])
        del buf[:need]
        return (isotp.Frame(can_id=can_id, data=data, brs=True,
                            fd=self.frame_dl > 8, ts=time.perf_counter()), need)


class LenPrefixCodec(Codec):
    """Length prefix (1/2/4 bytes) + frame data."""

    def __init__(self, dl: int = 16, len_bytes: int = 2, endian: str = "big",
                 can_id: int = 0x7E9):
        self.frame_dl = dl
        self.len_bytes = len_bytes
        self.endian = endian
        self.rx_id = can_id
        self.name = f"len{len_bytes}{endian[0]}+{dl}"
        self.fixed_size = False

    def encode(self, frame: isotp.Frame) -> bytes:
        data = frame.data
        return len(data).to_bytes(self.len_bytes, self.endian) + bytes(data)

    def decode(self, buf: bytearray):
        if len(buf) < self.len_bytes:
            return None
        n = int.from_bytes(bytes(buf[:self.len_bytes]), self.endian)
        if n > 64 or n == 0:
            return None  # not this codec
        if len(buf) < self.len_bytes + n:
            return None
        data = bytes(buf[self.len_bytes:self.len_bytes + n])
        del buf[:self.len_bytes + n]
        return (isotp.Frame(can_id=self.rx_id, data=data, brs=True,
                            fd=len(data) > 8, ts=time.perf_counter()),
                self.len_bytes + n)


class SlcanCodec(Codec):
    """LAWICEL ASCII: t/T classic, d/D/b/B CAN FD, \\r terminated."""

    name = "slcan"
    is_ascii = True
    fixed_size = False

    def __init__(self):
        self.frame_dl = 64  # sLCAN FD can carry up to 64

    def encode(self, frame: isotp.Frame) -> bytes:
        data = bytes(frame.data)
        n = len(data)
        if n <= 8:
            prefix = "t" if frame.can_id <= 0x7FF else "T"
            idtxt = (f"{frame.can_id:03X}" if prefix == "t"
                     else f"{frame.can_id:08X}")
            return f"{prefix}{idtxt}{n:X}{data.hex()}\r".encode()
        dlc = FD_LEN_TO_DLC.get(n)
        if dlc is None:
            raise ValueError(f"sLCAN FD cannot carry {n} B")
        brs = getattr(frame, "brs", True)
        prefix = ("b" if brs else "d") if frame.can_id <= 0x7FF else \
                 ("B" if brs else "D")
        idtxt = (f"{frame.can_id:03X}" if frame.can_id <= 0x7FF
                 else f"{frame.can_id:08X}")
        return f"{prefix}{idtxt}{dlc:X}{data.hex()}\r".encode()

    def decode(self, buf: bytearray):
        end = buf.find(b"\r")
        if end < 0:
            return None
        line = bytes(buf[:end]).decode("ascii", "replace")
        del buf[:end + 1]
        if len(line) < 5:
            return None
        kind = line[0]
        if kind in "tT":
            idlen = 3 if kind == "t" else 8
            can_id = int(line[1:1 + idlen], 16)
            dlc = int(line[1 + idlen], 16)
            data = bytes.fromhex(line[2 + idlen:2 + idlen + dlc * 2])
        elif kind in "dDbB":
            idlen = 3 if kind in "db" else 8
            can_id = int(line[1:1 + idlen], 16)
            dlc = int(line[1 + idlen], 16)
            n = DLC_TO_FD_LEN.get(dlc, dlc)
            data = bytes.fromhex(line[2 + idlen:2 + idlen + n * 2])
        else:
            return None
        return (isotp.Frame(can_id=can_id, data=data,
                            brs=kind in "bB", fd=len(data) > 8 or kind in "dDbB",
                            ts=time.perf_counter()), len(line))


class SocketcandCodec(Codec):
    """Becker socketcand ASCII protocol: < send 0x7E1 8 02 10 >."""

    name = "socketcand"
    is_ascii = True
    fixed_size = False

    def __init__(self, bus: str = "can0"):
        self.bus = bus
        self.frame_dl = 64

    def encode(self, frame: isotp.Frame) -> bytes:
        data = " ".join(f"{b:02X}" for b in frame.data)
        inner = f"send 0x{frame.can_id:03X} {len(frame.data)} {data}"
        return f"< {inner} >".encode()

    def encode_frame(self, frame: isotp.Frame) -> bytes:
        """Server->client direction uses `frame`, client->server uses `send`."""
        data = " ".join(f"{b:02X}" for b in frame.data)
        inner = f"frame 0x{frame.can_id:03X} {len(frame.data)} {data}"
        return f"< {inner} >".encode()

    def decode(self, buf: bytearray):
        start = buf.find(b"<")
        if start < 0:
            return None
        end = buf.find(b">", start)
        if end < 0:
            return None
        inner = bytes(buf[start + 1:end]).decode("ascii", "replace").strip()
        del buf[:end + 1]
        parts = inner.split()
        if not parts or parts[0] not in ("frame", "send") or len(parts) < 3:
            return None
        can_id = int(parts[1], 0)
        n = int(parts[2], 0)
        data = bytes(int(x, 16) for x in parts[3:3 + n])
        return (isotp.Frame(can_id=can_id, data=data, brs=True,
                            fd=len(data) > 8, ts=time.perf_counter()), end + 1)


class CandumpCodec(Codec):
    """candump -L text: (1234.567890) can0 7E1#0210030000000000."""

    name = "candump"
    is_ascii = True
    fixed_size = False

    def __init__(self, iface: str = "can0"):
        self.iface = iface
        self.frame_dl = 64

    def encode(self, frame: isotp.Frame) -> bytes:
        return (f"({time.time():.6f}) {self.iface} "
                f"{frame.can_id:03X}#{frame.data.hex()}\n").encode()

    def decode(self, buf: bytearray):
        end = buf.find(b"\n")
        if end < 0:
            return None
        line = bytes(buf[:end]).decode("ascii", "replace")
        del buf[:end + 1]
        if "#" not in line:
            return None
        head, data_hex = line.split("#", 1)
        tokens = head.split()
        if not tokens:
            return None
        idtxt = tokens[-1]
        try:
            can_id = int(idtxt, 16)
            data = bytes.fromhex(data_hex.strip())
        except ValueError:
            return None
        return (isotp.Frame(can_id=can_id, data=data, brs=True,
                            fd=len(data) > 8, ts=time.perf_counter()), end + 1)


class IsotpDirectCodec(Codec):
    """The bridge terminates ISO-TP itself: 2-byte length + UDS payload."""

    name = "isotp-direct"
    fixed_size = False

    def __init__(self, len_bytes: int = 2, endian: str = "big"):
        self.len_bytes = len_bytes
        self.endian = endian
        self.frame_dl = 64

    def encode(self, frame: isotp.Frame) -> bytes:
        return len(frame.data).to_bytes(self.len_bytes, self.endian) + bytes(frame.data)

    def decode(self, buf: bytearray):
        if len(buf) < self.len_bytes:
            return None
        n = int.from_bytes(bytes(buf[:self.len_bytes]), self.endian)
        if len(buf) < self.len_bytes + n:
            return None
        data = bytes(buf[self.len_bytes:self.len_bytes + n])
        del buf[:self.len_bytes + n]
        return (isotp.Frame(can_id=0, data=data, brs=True, fd=True,
                            ts=time.perf_counter()), self.len_bytes + n)


CODEC_BUILDERS = {
    "raw8": lambda **kw: RawCodec(8, kw.get("can_id", 0x7E9)),
    "raw16": lambda **kw: RawCodec(16, kw.get("can_id", 0x7E9)),
    "raw64": lambda **kw: RawCodec(64, kw.get("can_id", 0x7E9)),
    "id2+16": lambda **kw: IdDataCodec(16, 2),
    "id4+16": lambda **kw: IdDataCodec(16, 4),
    "id4+64": lambda **kw: IdDataCodec(64, 4),
    "len1+16": lambda **kw: LenPrefixCodec(16, 1, "big", kw.get("can_id", 0x7E9)),
    "len2big+16": lambda **kw: LenPrefixCodec(16, 2, "big", kw.get("can_id", 0x7E9)),
    "len2little+16": lambda **kw: LenPrefixCodec(16, 2, "little", kw.get("can_id", 0x7E9)),
    "len4big+16": lambda **kw: LenPrefixCodec(16, 4, "big", kw.get("can_id", 0x7E9)),
    "slcan": lambda **kw: SlcanCodec(),
    "socketcand": lambda **kw: SocketcandCodec(),
    "candump": lambda **kw: CandumpCodec(),
    "isotp-direct": lambda **kw: IsotpDirectCodec(),
}

#: order matters: cheapest/most likely probes first
PROBE_TARGETS = ("slcan", "socketcand", "raw16", "len2big+16", "id4+16")


def make_codec(name: str, **kw) -> Codec:
    if name not in CODEC_BUILDERS:
        raise SystemExit(f"unknown framing {name!r}; known: "
                         f"{sorted(CODEC_BUILDERS)}")
    return CODEC_BUILDERS[name](**kw)


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #

class FramingTransport(isotp.Transport):
    """isotp.Transport over a TCP bridge speaking `codec`."""

    def __init__(self, sock, codec: Codec, can_id: int = 0x7E1,
                 timeout: float = 2.0, trace: Optional[list] = None):
        self.sock = sock
        self.codec = codec
        self.can_id = can_id
        self.timeout = timeout
        self.buf = bytearray()
        self.trace = trace if trace is not None else []
        self.tx_frames = 0
        self.rx_frames = 0

    # -- isotp.Transport ------------------------------------------------ #
    def send(self, frame: isotp.Frame) -> None:
        if frame.can_id is None or frame.can_id == 0:
            frame.can_id = self.can_id
        raw = self.codec.encode(frame)
        self.trace.append({"dir": "tx", "wire": raw.hex()})
        self.sock.sendall(raw)
        self.tx_frames += 1

    def recv(self, timeout: float) -> Optional[isotp.Frame]:
        end = time.perf_counter() + max(0.0, timeout)
        while True:
            got = self.codec.decode(self.buf)
            if got is not None:
                frame, _consumed = got
                self.rx_frames += 1
                if frame.ts == 0.0:
                    frame.ts = time.perf_counter()
                self.trace.append({"dir": "rx", "wire": frame.data.hex()})
                return frame
            left = end - time.perf_counter()
            if left <= 0:
                return None
            self.sock.settimeout(max(0.01, left))
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                return None
            if not chunk:
                return None
            self.buf += chunk

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# detection
# --------------------------------------------------------------------------- #

@dataclass
class ProbeRecord:
    label: str
    sent: str = ""
    received: str = ""
    elapsed_ms: float = 0.0
    note: str = ""

    def as_dict(self) -> dict:
        return {"label": self.label, "sent": self.sent,
                "received": self.received, "elapsed_ms": round(self.elapsed_ms, 1),
                "note": self.note}


def _one_exchange(host: str, port: int, payload: bytes, wait: float,
                  connect_timeout: float = 3.0) -> ProbeRecord:
    rec = ProbeRecord(label="")
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((host, port), timeout=connect_timeout)
    except OSError as exc:
        rec.note = f"connect failed: {exc}"
        return rec
    try:
        s.settimeout(wait)
        if payload:
            s.sendall(payload)
        data = b""
        while len(data) < 4096:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            except ConnectionResetError:
                rec.note = "peer reset (RST)"
                break
            except OSError as exc:
                rec.note = f"socket error: {exc}"
                break
            if not chunk:
                rec.note = "peer closed"
                break
            data += chunk
        rec.received = data.hex()
    finally:
        s.close()
    rec.elapsed_ms = (time.perf_counter() - t0) * 1000
    return rec


def detect(host: str, port: int = 13401, passive_wait: float = 1.0,
           probe_wait: float = 0.8) -> dict:
    """Figure out how the bridge frames CAN frames, without touching the bus."""
    evidence = []
    verdict = {"framing": None, "confidence": "none", "evidence": evidence,
               "banner": "", "peer_closes": False}

    # 0) passive: does the server speak first?
    pas = _one_exchange(host, port, b"", passive_wait)
    pas.label = "passive"
    evidence.append(pas.as_dict())
    if pas.received:
        verdict["banner"] = pas.received
    if pas.note == "peer closed":
        verdict["peer_closes"] = True

    banner_bytes = bytes.fromhex(pas.received) if pas.received else b""
    if b"< hi >" in banner_bytes or b"< ok" in banner_bytes:
        verdict["framing"] = "socketcand"
        verdict["confidence"] = "high"
        verdict["note"] = "server greeted with socketcand banner"
        return verdict
    if banner_bytes and all(32 <= b < 127 or b in (10, 13) for b in banner_bytes):
        text = banner_bytes.decode("ascii", "replace")
        if any(ch.isdigit() for ch in text) and len(text) <= 32:
            verdict["framing"] = "slcan"
            verdict["confidence"] = "medium"
            verdict["note"] = f"sLCAN-style banner {text!r}"
            return verdict

    # 1) sLCAN version query: harmless, returns "V1013\r" or similar
    v = _one_exchange(host, port, b"V\r", probe_wait)
    v.label = "slcan:V"
    evidence.append(v.as_dict())
    if v.received:
        try:
            text = bytes.fromhex(v.received).decode("ascii", "replace")
        except ValueError:
            text = ""
        if text.startswith("V") or any(ch.isdigit() for ch in text):
            verdict["framing"] = "slcan"
            verdict["confidence"] = "high"
            verdict["note"] = f"V answered {text!r}"
            return verdict

    # 2) socketcand greeting
    sc = _one_exchange(host, port, b"< hi >", probe_wait)
    sc.label = "socketcand:hi"
    evidence.append(sc.as_dict())
    if sc.received:
        try:
            text = bytes.fromhex(sc.received).decode("ascii", "replace")
        except ValueError:
            text = ""
        if "< ok" in text or "< hi >" in text:
            verdict["framing"] = "socketcand"
            verdict["confidence"] = "high"
            verdict["note"] = f"greeting answered {text!r}"
            return verdict

    # 3) bare CR: some ASCII bridges answer "?\r"
    cr = _one_exchange(host, port, b"\r", probe_wait)
    cr.label = "bare-cr"
    evidence.append(cr.as_dict())
    if cr.received:
        verdict["framing"] = "slcan"
        verdict["confidence"] = "low"
        verdict["note"] = "bare CR produced output"
        return verdict

    # 4) nothing at all: either closed bridge, or a silent raw-frame sink
    if not any(e["received"] for e in evidence):
        verdict["framing"] = "raw16"
        verdict["confidence"] = "guess"
        verdict["note"] = ("no handshake answered; if the bridge is open this "
                           "points at bare fixed-size frames, otherwise the "
                           "bridge is still closed")
    return verdict


def open_transport(host: str, port: int = 13401, framing: str = "auto",
                   timeout: float = 2.0, can_id: int = 0x7E1,
                   **codec_kw):
    """Return (FramingTransport, info) for the bridge at host:port."""
    info = {"host": host, "port": port, "framing_requested": framing}
    if framing in ("auto", "", None):
        det = detect(host, port)
        info["detection"] = det
        framing = det["framing"] or "raw16"
    codec = make_codec(framing, can_id=can_id, **codec_kw)
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    info.update({"framing": codec.name, "codec": codec.describe(),
                 "can_id": f"0x{can_id:03X}"})
    return FramingTransport(sock, codec, can_id=can_id, timeout=timeout), info


# --------------------------------------------------------------------------- #
# self-test: local fake bridges
# --------------------------------------------------------------------------- #

class FakeBridge(threading.Thread):
    """A TCP server that speaks one codec; echoes frames back reversed."""

    def __init__(self, codec: Codec, greeter: Optional[bytes] = None,
                 reply_to_version: Optional[bytes] = None, port: int = 0):
        super().__init__(daemon=True)
        self.codec = codec
        self.greeter = greeter
        self.reply_to_version = reply_to_version
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop_flag = threading.Event()
        self.seen: list = []
        self.conns = 0

    def run(self) -> None:
        self.sock.settimeout(0.3)
        while not self.stop_flag.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            self.conns += 1
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()

    def _serve(self, conn) -> None:
        conn.settimeout(0.3)
        buf = bytearray()
        try:
            if self.greeter:
                try:
                    conn.sendall(self.greeter)
                except OSError:
                    return
            while not self.stop_flag.is_set():
                got = self.codec.decode(buf)
                if got is None:
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        return
                    if not chunk:
                        return
                    # ASCII bridges answer a version query before any frame
                    if (self.reply_to_version and not self.seen
                            and chunk.startswith(b"V")):
                        conn.sendall(self.reply_to_version)
                        continue
                    buf += chunk
                    continue
                frame, _ = got
                self.seen.append(frame)
                echo = isotp.Frame(can_id=frame.can_id + 8, data=frame.data,
                                   brs=True, fd=frame.fd)
                enc = getattr(self.codec, "encode_frame", self.codec.encode)
                try:
                    conn.sendall(enc(echo))
                except OSError:
                    return
        finally:
            conn.close()

    def stop(self) -> None:
        self.stop_flag.set()
        try:
            self.sock.close()
        except OSError:
            pass


def _roundtrip(codec_name: str, port_hint: int = 0, **codec_kw) -> dict:
    codec = make_codec(codec_name, **codec_kw)
    srv = FakeBridge(codec)
    srv.start()
    tr = FramingTransport(socket.create_connection(("127.0.0.1", srv.port),
                                                   timeout=2.0),
                          codec, can_id=0x7E1, timeout=1.0)
    full = bytes.fromhex("0322f190") + bytes([0xCC]) * 12  # 16 bytes
    payload = full[:min(len(full), codec.frame_dl)]
    tr.send(isotp.Frame(can_id=0x7E1, data=payload, brs=True, fd=True))
    back = tr.recv(1.5)
    tr.close()
    srv.stop()
    return {"codec": codec_name, "echo": back.data.hex() if back else None,
            "ok": (back is not None and back.can_id == 0x7E9
                   and back.data[:len(payload)] == payload)}


class _Res:
    def __init__(self):
        self.rows = []

    def check(self, name, cond, detail=""):
        detail = detail if isinstance(detail, str) else str(detail)
        self.rows.append({"name": name, "ok": bool(cond), "detail": detail})
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}" +
              (f"  -- {detail}" if detail else ""))
        return bool(cond)

    @property
    def ok(self):
        return all(r["ok"] for r in self.rows)


def _t_codecs(res: _Res) -> None:
    print("\n[1] codec round trips through a local fake bridge")
    for name in ("raw8", "raw16", "raw64", "id2+16", "id4+16", "len1+16",
                 "len2big+16", "len2little+16", "len4big+16", "slcan",
                 "socketcand", "candump"):
        r = _roundtrip(name)
        res.check(f"{name} encode->wire->decode", r["ok"],
                  f"echo={r['echo']}")


def _t_slcan_vectors(res: _Res) -> None:
    print("\n[2] sLCAN wire format vectors")
    c = SlcanCodec()
    f8 = isotp.Frame(0x7E1, bytes.fromhex("0210030000000000"), brs=False, fd=False)
    res.check("classic t-frame", c.encode(f8) == b"t7E180210030000000000\r",
              c.encode(f8))
    f16 = isotp.Frame(0x7E1, bytes(16), brs=True, fd=True)
    enc = c.encode(f16)
    res.check("CAN FD b-frame uses DLC code 0xA for 16 B",
              enc.startswith(b"b7E1A"), enc[:12])
    buf = bytearray(enc)
    got, _ = c.decode(buf)
    res.check("FD round trip", got.data == bytes(16) and got.can_id == 0x7E1
              and got.brs, f"{len(got.data)} B brs={got.brs}")
    f64 = isotp.Frame(0x7E1, bytes(range(64)), brs=True, fd=True)
    buf = bytearray(c.encode(f64))
    got, _ = c.decode(buf)
    res.check("64 B FD round trip", got.data == bytes(range(64)), "64 B")


def _t_detect(res: _Res) -> None:
    print("\n[3] detect() against local fake bridges")
    # sLCAN
    srv = FakeBridge(SlcanCodec(), reply_to_version=b"V1013\r")
    srv.start()
    d = detect("127.0.0.1", srv.port, passive_wait=0.3, probe_wait=0.4)
    srv.stop()
    res.check("sLCAN detected", d["framing"] == "slcan",
              f"{d['framing']}/{d['confidence']} -- {d.get('note', '')}")

    # socketcand
    srv = FakeBridge(SocketcandCodec(), greeter=b"< hi >\n")
    srv.start()
    d = detect("127.0.0.1", srv.port, passive_wait=0.3, probe_wait=0.4)
    srv.stop()
    res.check("socketcand detected", d["framing"] == "socketcand",
              f"{d['framing']}/{d['confidence']} -- {d.get('note', '')}")

    # silent raw server: no handshake answered -> guessed raw16
    srv = FakeBridge(RawCodec(16))
    srv.start()
    d = detect("127.0.0.1", srv.port, passive_wait=0.3, probe_wait=0.3)
    srv.stop()
    res.check("silent server falls back to raw16 guess",
              d["framing"] == "raw16" and d["confidence"] == "guess",
              f"{d['framing']}/{d['confidence']}")

    # closed port
    d = detect("127.0.0.1", 1, passive_wait=0.1, probe_wait=0.1)
    res.check("closed port reported clearly",
              d["evidence"][0]["note"].startswith("connect failed"),
              d["evidence"][0]["note"][:60])


def _t_open_transport(res: _Res) -> None:
    print("\n[4] open_transport() against a fake sLCAN bridge")
    srv = FakeBridge(SlcanCodec(), reply_to_version=b"V1013\r")
    srv.start()
    tr, info = open_transport("127.0.0.1", srv.port, framing="slcan")
    tr.send(isotp.Frame(0x7E1, bytes.fromhex("0221000000000000"), brs=False, fd=False))
    back = tr.recv(1.0)
    tr.close()
    srv.stop()
    res.check("transport sends and receives", back is not None
              and back.can_id == 0x7E9, repr(back))
    res.check("info documents the codec", info["framing"] == "slcan",
              json.dumps(info["codec"]))


def _t_isotp_over_framing(res: _Res) -> None:
    print("\n[5] full ISO-TP exchange over a fake sLCAN bridge")
    # a bridge that speaks sLCAN and answers a UDS 0x23 with 512 bytes
    image = bytes((i * 5 + 1) & 0xFF for i in range(512))

    class UdsBridge(FakeBridge):
        def _serve(self, conn):
            conn.settimeout(0.3)
            buf = bytearray()
            link_in = None
            try:
                while not self.stop_flag.is_set():
                    got = self.codec.decode(buf)
                    if got is None:
                        try:
                            chunk = conn.recv(4096)
                        except socket.timeout:
                            continue
                        except OSError:
                            return
                        if not chunk:
                            return
                        buf += chunk
                        continue
                    frame, _ = got
                    self.seen.append(frame)
                    # naive: answer the 0x23 request with a 512-byte 0x63 PDU
                    payload = bytes([0x63, 0x24, 0x00, 0x00, 0x00, 0x00,
                                     0x02, 0x00]) + image
                    for f in _segment(payload, 0x7E9, 16):
                        conn.sendall(self.codec.encode(f))
            finally:
                conn.close()

    def _segment(payload: bytes, can_id: int, dl: int):
        if len(payload) <= dl - 2:
            body = bytes([len(payload)]) + payload
            return [isotp.Frame(can_id, body + bytes([0xCC]) * (dl - len(body)),
                                brs=True, fd=True)]
        out = []
        ff, carried = isotp.build_ff(len(payload), payload, dl=dl)
        out.append(isotp.Frame(can_id, ff, brs=True, fd=True))
        off, sn = carried, 1
        while off < len(payload):
            chunk = payload[off:off + dl - 1]
            out.append(isotp.Frame(can_id, isotp.build_cf(sn, chunk, dl=dl),
                                   brs=True, fd=True))
            off += len(chunk)
            sn = (sn + 1) & 0x0F
        return out

    srv = UdsBridge(SlcanCodec(), reply_to_version=b"V1013\r")
    srv.start()
    tr, info = open_transport("127.0.0.1", srv.port, framing="slcan")
    link = isotp.IsoTpLink(tr, tx_id=0x7E1, rx_id=0x7E9, dl=16, label="tap")
    resp = link.request(bytes.fromhex("2324000000000200"), timeout=2.0)
    tr.close()
    srv.stop()
    res.check("0x63 response reassembled over sLCAN",
              resp[0] == 0x63 and len(resp) == 520, f"{len(resp)} B")
    res.check("payload byte-exact", resp[8:] == image, "512 B")


def self_test(evidence_dir: Optional[str] = None) -> int:
    print("=" * 78)
    print("tap13401.py self-test -- framing codecs + detection on local fakes")
    print("=" * 78)
    t0 = time.time()
    res = _Res()
    _t_codecs(res)
    _t_slcan_vectors(res)
    _t_detect(res)
    _t_open_transport(res)
    _t_isotp_over_framing(res)
    passed = sum(1 for r in res.rows if r["ok"])
    total = len(res.rows)
    print("\n" + "=" * 78)
    print(f"RESULT: {passed}/{total} checks passed "
          f"({'OK' if res.ok else 'FAILURES'}) in {time.time() - t0:.1f}s")
    print("=" * 78)
    if evidence_dir:
        os.makedirs(evidence_dir, exist_ok=True)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        base = os.path.join(evidence_dir, "03_selftest_tap13401")
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump({"tool": "tap13401.py", "ts": stamp, "passed": passed,
                       "total": total, "ok": res.ok, "checks": res.rows},
                      f, indent=2, ensure_ascii=False)
        with open(base + ".log", "w", encoding="utf-8") as f:
            f.write(f"# tap13401.py self-test {stamp}\n")
            for r in res.rows:
                f.write(f"[{'PASS' if r['ok'] else 'FAIL'}] {r['name']}")
                if r["detail"]:
                    f.write(f"  -- {r['detail']}")
                f.write("\n")
            f.write(f"\nRESULT {passed}/{total} {'OK' if res.ok else 'FAIL'}\n")
        print(f"evidence written: {base}.json / .log")
    return 0 if res.ok else 1


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def cmd_probe(args) -> int:
    t0 = time.perf_counter()
    det = detect(args.host, args.port, passive_wait=args.passive,
                 probe_wait=args.probe)
    det["elapsed_s"] = round(time.perf_counter() - t0, 2)
    print(json.dumps(det, indent=2, ensure_ascii=False))
    if args.evidence_dir:
        os.makedirs(args.evidence_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = os.path.join(args.evidence_dir, f"20_tap13401_probe_{stamp}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(det, f, indent=2, ensure_ascii=False)
        print(f"evidence written: {path}")
    return 0 if det["framing"] else 1


def cmd_monitor(args) -> int:
    tr, info = open_transport(args.host, args.port, framing=args.framing,
                             timeout=args.timeout, can_id=args.can_id)
    print(json.dumps(info, indent=2, ensure_ascii=False))
    print("monitoring (Ctrl-C to stop) ...")
    rec_path = args.record
    rec_fh = None
    if rec_path:
        os.makedirs(os.path.dirname(os.path.abspath(rec_path)), exist_ok=True)
        rec_fh = open(rec_path, "a", encoding="utf-8")
        print(f"recording frames to {rec_path}")
    t_end = time.time() + args.duration
    n = 0
    try:
        while time.time() < t_end:
            fr = tr.recv(0.5)
            if fr is None:
                continue
            n += 1
            print(f"{time.strftime('%H:%M:%S')} 0x{fr.can_id:03X} "
                  f"[{len(fr.data):02d}] {_hx(fr.data)}  brs={fr.brs}")
            if rec_fh:
                rec_fh.write(json.dumps({
                    "t": round(fr.ts, 6), "can_id": f"0x{fr.can_id:03X}",
                    "dl": len(fr.data), "hex": fr.data.hex(),
                    "brs": fr.brs, "fd": fr.fd}) + "\n")
                rec_fh.flush()
    except KeyboardInterrupt:
        pass
    finally:
        tr.close()
        if rec_fh:
            rec_fh.close()
            print(f"recorded {n} frame(s) to {rec_path}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="13401 CAN FD bridge framing")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--evidence-dir", default=None)
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--monitor", action="store_true")
    ap.add_argument("--host", default="10.226.193.2")
    ap.add_argument("--port", type=int, default=13401)
    ap.add_argument("--framing", default="auto")
    ap.add_argument("--can-id", default="0x7E1")
    ap.add_argument("--passive", type=float, default=1.0)
    ap.add_argument("--probe-wait", dest="probe", type=float, default=0.8)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--record", default=None,
                    help="append received frames as JSONL (SecOC captures)")
    args = ap.parse_args(argv)
    args.can_id = int(str(args.can_id), 0)
    if args.self_test:
        return self_test(args.evidence_dir)
    if args.probe:
        return cmd_probe(args)
    if args.monitor:
        return cmd_monitor(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

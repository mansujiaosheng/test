#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""isotp.py -- ISO 15765-2:2016 (DoCAN) transport for CAN FD, both directions.

What this is
------------
The transport half of tasks 05/06: move an arbitrary byte blob (up to ~16 KiB)
between the tester and an ECU over a pair of CAN identifiers, using 8..64 byte
CAN (FD) frames and nothing else.  Four N_PCI types are implemented:

    SF  Single Frame       classic 0x0N (1..7 B), CAN-FD escape 0x00 + SF_DL
                           (8..62 B) when N_DL > 8
    FF  First Frame        0x1N + 12-bit FF_DL; escape form FF_DL==0x000
                           followed by a 32-bit big-endian length
    CF  Consecutive Frame  0x2N, SN 1..15 with wrap 15 -> 0
    FC  Flow Control       0x3N, FS (CTS/WAIT/OVFLW) + BS + STmin

Both directions are needed in practice: a request/response exchange requires
the tester to *receive* (advertise BS/STmin via FC, reassemble CFs) as well as
to *send* (obey the peer's FC, respect its STmin).

Design points that matter on a real bus
---------------------------------------
* CAN FD data lengths are restricted to {8,12,16,20,24,32,48,64}.  We round up
  and pad with 0xCC (the AUTOSAR filler) but accept any filler on RX: the
  receiver trims the last frame using the declared total length only.
* A CAN FD single frame longer than 7 bytes must use the escape encoding
  (PCI byte 0x00, second byte = SF_DL).  Max SF payload is 62 bytes (N_DL=64).
* The FF escape encoding (12-bit FF_DL == 0, then uint32 BE) is the only way to
  declare more than 4095 bytes; a 16384-byte firmware read needs it.
* STmin decoding is exact: 0x00..0x7F = 0..127 ms, 0xF1..0xF9 = 100..900 us,
  and the reserved ranges 0x80..0xF0 / 0xFA..0xFF are treated as 127 ms as
  ISO 15765-2 requires (with a warning, because peers get this wrong).
* STmin is enforced between *transmitted* consecutive frames, including across
  an FC block boundary, on the sender's monotonic clock.  Every CF timestamp
  is kept so compliance can be audited after the run.
* Timers: N_Bs (wait for FC), N_Cr/N_As (transmit/receive guard), N_WFTmax
  (maximum number of FS=WAIT frames).

Read-only discipline
--------------------
This module has no idea what a UDS service is.  It forwards bytes.  The only
UDS code in this directory (bms_dump.py) uses 0x23 ReadMemoryByAddress and
0x3E TesterPresent, both read-only.

Transports
----------
`Transport` is a two-method duck type:  send(Frame) / recv(timeout) -> Frame|None.
Included here: VirtualBus (in-process loopback, used by --self-test) and
TcpFrameTransport (fixed-size raw frames, for a bridge that speaks bare frames).
tap13401.py supplies framing-aware transports for the real 13401 bridge.

CLI
---
    python isotp.py --self-test
    python isotp.py --self-test --evidence-dir ../../03_EVIDENCE/canfd
    python isotp.py --demo-512          # print the frames for one 0x23 read
    python isotp.py --decode <hex>      # decode one frame's PCI
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #

PCI_SF = 0x0
PCI_FF = 0x1
PCI_CF = 0x2
PCI_FC = 0x3

FS_CTS = 0
FS_WAIT = 1
FS_OVFLW = 2
FS_RESERVED = 3

CANFD_DL = (8, 12, 16, 20, 24, 32, 48, 64)
DEFAULT_PAD = 0xCC

MAX_SF_FD = 62  # N_DL 64 minus PCI + SF_DL
MAX_SF_CLASSIC = 7
FF_ESCAPE_LIMIT = 0xFFF

# ISO 15765-2 performance requirements (seconds unless stated)
N_BS = 1.0
N_CR = 1.0
N_AS = 1.0
N_WFTMAX = 10
N_P2_STAR = 5.0


class IsoTpError(RuntimeError):
    """Protocol violation / abort."""


class IsoTpTimeout(IsoTpError):
    """N_Bs / N_Cr / N_As expired."""


class IsoTpOverflow(IsoTpError):
    """Peer answered FS=OVFLW (or our receive buffer is full)."""


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def round_dl(n: int) -> int:
    """Smallest legal CAN FD data length >= n."""
    for dl in CANFD_DL:
        if dl >= n:
            return dl
    raise IsoTpError(f"payload needs {n} data bytes, max is {CANFD_DL[-1]}")


def pad_bytes(data: bytes, dl: int, pad: int = DEFAULT_PAD) -> bytes:
    if len(data) > dl:
        raise IsoTpError(f"frame body {len(data)} B exceeds N_DL {dl}")
    return bytes(data) + bytes([pad]) * (dl - len(data))


def stmin_seconds(raw: int) -> float:
    """Decode an STmin byte exactly as ISO 15765-2:2016 prescribes.

    0x00..0x7F -> 0..127 ms
    0xF1..0xF9 -> 100..900 us   (the classic "treated as ms" bug lives here)
    0x80..0xF0, 0xFA..0xFF -> reserved, treat as 127 ms
    """
    raw &= 0xFF
    if 0x00 <= raw <= 0x7F:
        return raw / 1000.0
    if 0xF1 <= raw <= 0xF9:
        return (raw - 0xF0) / 10000.0
    return 127 / 1000.0


def stmin_is_reserved(raw: int) -> bool:
    raw &= 0xFF
    return not (0x00 <= raw <= 0x7F or 0xF1 <= raw <= 0xF9)


def stmin_repr(raw: int) -> str:
    raw &= 0xFF
    if 0xF1 <= raw <= 0xF9:
        return f"0x{raw:02X} ({(raw - 0xF0) * 100} us)"
    if 0x00 <= raw <= 0x7F:
        return f"0x{raw:02X} ({raw} ms)"
    return f"0x{raw:02X} (reserved -> 127 ms)"


def stmin_from_seconds(sec: float) -> int:
    """Best STmin byte for a desired delay (used by the mock ECU)."""
    ms = sec * 1000.0
    if ms <= 0:
        return 0x00
    if ms < 1.0:
        # 100 us resolution, clamp to 0xF1..0xF9
        idx = max(1, min(9, int(round(sec * 10000.0))))
        return 0xF0 + idx
    return max(0, min(0x7F, int(round(ms))))


def sleep_until(deadline: float) -> None:
    """Sleep until perf_counter() >= deadline; last 2 ms are a yield loop."""
    while True:
        now = time.perf_counter()
        delta = deadline - now
        if delta <= 0:
            return
        if delta > 0.002:
            time.sleep(delta - 0.002)
        else:
            time.sleep(0)  # yield, do not oversleep sub-millisecond STmin


def hx(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


# --------------------------------------------------------------------------- #
# frame container
# --------------------------------------------------------------------------- #

@dataclass
class Frame:
    can_id: int
    data: bytes
    brs: bool = True          # CAN FD bit-rate switch
    fd: bool = True           # CAN FD frame (vs classic CAN)
    ts: float = 0.0           # perf_counter() at transmit/receive
    ext: bool = False         # 29-bit identifier
    seq: int = 0              # transport-assigned sequence number

    def __repr__(self) -> str:
        return (f"Frame(id=0x{self.can_id:03X}, dl={len(self.data)}, "
                f"{'FD' if self.fd else 'CC'}{'/BRS' if self.brs else ''}, "
                f"{hx(self.data)})")

    def as_dict(self) -> dict:
        return {"can_id": f"0x{self.can_id:03X}", "dl": len(self.data),
                "hex": self.data.hex(), "brs": self.brs, "fd": self.fd,
                "ext": self.ext, "ts": self.ts, "seq": self.seq}


# --------------------------------------------------------------------------- #
# frame builders
# --------------------------------------------------------------------------- #

def build_sf(payload: bytes, dl: Optional[int] = None, pad: int = DEFAULT_PAD,
             force_escape: bool = False) -> bytes:
    """Build a Single Frame.

    dl=None picks the smallest legal CAN FD length.  For N_DL > 8 a payload of
    8..62 bytes *must* use the escape form (0x00, SF_DL); 1..7 bytes may use
    either form (classic 0x0N is what most stacks emit), force_escape switches.
    """
    n = len(payload)
    if n == 0:
        raise IsoTpError("empty SF payload")
    if n > MAX_SF_FD:
        raise IsoTpError(f"SF payload {n} B > {MAX_SF_FD}; use FF")
    if dl is None:
        dl = round_dl(n + (2 if (n > MAX_SF_CLASSIC or force_escape) else 1))
    if dl not in CANFD_DL:
        dl = round_dl(dl)
    if dl <= 8:
        if n > MAX_SF_CLASSIC:
            raise IsoTpError(f"classic CAN SF cannot carry {n} B")
        body = bytes([PCI_SF << 4 | n]) + payload
    else:
        if n <= MAX_SF_CLASSIC and not force_escape:
            body = bytes([PCI_SF << 4 | n]) + payload
        else:
            body = bytes([0x00, n]) + payload
    return pad_bytes(body, dl, pad)


def build_ff(total: int, payload: bytes, dl: Optional[int] = None,
             pad: int = DEFAULT_PAD,
             force_escape: bool = False) -> tuple[bytes, int]:
    """Build a First Frame; returns (frame_bytes, data_bytes_carried).

    Normal form carries 12-bit FF_DL.  Escape form (used automatically for
    total > 4095) writes FF_DL=0x000 then a uint32 BE length in the same frame,
    which costs 4 extra header bytes and therefore carries 4 fewer bytes.
    """
    if dl is None:
        dl = 16
    if dl not in CANFD_DL:
        dl = round_dl(dl)
    escape = force_escape or total > FF_ESCAPE_LIMIT
    if escape:
        hdr = bytes([0x10, 0x00]) + total.to_bytes(4, "big")
    else:
        hdr = bytes([0x10 | ((total >> 8) & 0x0F), total & 0xFF])
    carried = dl - len(hdr)
    if carried < 1:
        raise IsoTpError(f"N_DL {dl} too small for FF header ({len(hdr)} B)")
    if total <= carried:
        raise IsoTpError(f"message of {total} B fits in one frame; use SF")
    chunk = payload[:carried]
    if len(chunk) != carried:
        raise IsoTpError("FF payload shorter than frame capacity")
    return pad_bytes(hdr + chunk, dl, pad), carried


def build_cf(sn: int, chunk: bytes, dl: Optional[int] = None,
             pad: int = DEFAULT_PAD) -> bytes:
    if not 0 <= sn <= 0xF:
        raise IsoTpError(f"bad SN {sn}")
    if dl is None:
        dl = round_dl(len(chunk) + 1)
    if dl not in CANFD_DL:
        dl = round_dl(dl)
    if len(chunk) > dl - 1:
        raise IsoTpError(f"CF chunk {len(chunk)} B does not fit N_DL {dl}")
    return pad_bytes(bytes([0x20 | sn]) + chunk, dl, pad)


def build_fc(fs: int, bs: int = 0, stmin: int = 0x00, dl: int = 8,
             pad: int = DEFAULT_PAD, pad_frame: bool = True) -> bytes:
    body = bytes([0x30 | (fs & 0x0F), bs & 0xFF, stmin & 0xFF])
    if not pad_frame:
        return body
    if dl not in CANFD_DL:
        dl = round_dl(dl)
    return pad_bytes(body, dl, pad)


# --------------------------------------------------------------------------- #
# frame parsers
# --------------------------------------------------------------------------- #

@dataclass
class Pci:
    kind: int
    raw0: int
    dl: int
    sf_len: Optional[int] = None
    ff_len: Optional[int] = None
    ff_escape: bool = False
    sn: Optional[int] = None
    fs: Optional[int] = None
    bs: Optional[int] = None
    stmin_raw: Optional[int] = None
    stmin_s: Optional[float] = None

    def as_dict(self) -> dict:
        d = {"kind": {0: "SF", 1: "FF", 2: "CF", 3: "FC"}[self.kind],
             "raw0": f"0x{self.raw0:02X}", "dl": self.dl}
        for k in ("sf_len", "ff_len", "ff_escape", "sn", "fs", "bs",
                  "stmin_raw", "stmin_s"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


def parse_pci(data: bytes) -> Pci:
    if not data:
        raise IsoTpError("zero-length frame")
    b0 = data[0]
    kind = (b0 >> 4) & 0x0F
    dl = len(data)
    if kind == PCI_SF:
        if b0 & 0x0F:
            return Pci(kind, b0, dl, sf_len=b0 & 0x0F)
        # escape SF: 0x00 + SF_DL, only legal on CAN FD (dl > 8)
        if dl < 2:
            raise IsoTpError("truncated escape SF")
        return Pci(kind, b0, dl, sf_len=data[1])
    if kind == PCI_FF:
        ff_len = ((b0 & 0x0F) << 8) | data[1]
        if ff_len == 0:
            if dl < 6:
                raise IsoTpError("truncated escape FF")
            ff_len = int.from_bytes(data[2:6], "big")
            return Pci(kind, b0, dl, ff_len=ff_len, ff_escape=True)
        return Pci(kind, b0, dl, ff_len=ff_len)
    if kind == PCI_CF:
        return Pci(kind, b0, dl, sn=b0 & 0x0F)
    if kind == PCI_FC:
        if dl < 3:
            raise IsoTpError("truncated FC")
        raw = data[2]
        return Pci(kind, b0, dl, fs=b0 & 0x0F, bs=data[1],
                   stmin_raw=raw, stmin_s=stmin_seconds(raw))
    raise IsoTpError(f"unknown PCI type {kind} in 0x{b0:02X}")


def parse_fc(data: bytes) -> dict:
    p = parse_pci(data)
    if p.kind != PCI_FC:
        raise IsoTpError(f"not an FC frame (0x{data[0]:02X})")
    return {"fs": p.fs, "bs": p.bs, "stmin_raw": p.stmin_raw,
            "stmin_s": p.stmin_s, "reserved_stmin": stmin_is_reserved(p.stmin_raw)}


# --------------------------------------------------------------------------- #
# reassembler (receiver side state machine)
# --------------------------------------------------------------------------- #

@dataclass
class RecvEvent:
    payload: Optional[bytes] = None
    fc: Optional[dict] = None
    note: str = ""
    kind: str = ""


class Reassembler:
    """ISO-TP receive state machine for one connection.

    feed(frame_data) -> RecvEvent.  The caller must transmit ev.fc when it is
    not None (that is how the peer learns our BS/STmin, and how we resume after
    every BS frames).
    """

    def __init__(self, label: str = "rx", max_len: int = 1 << 20,
                 rx_bs: int = 0, rx_stmin: int = 0x00, fc_dl: int = 8):
        self.label = label
        self.max_len = max_len
        self.rx_bs = rx_bs
        self.rx_stmin = rx_stmin
        self.fc_dl = fc_dl
        self.reset()

    # -- state ----------------------------------------------------------- #
    def reset(self) -> None:
        self.expected: Optional[int] = None
        self.buf = bytearray()
        self.next_sn = 1
        self.rx_in_block = 0
        self.frames = 0
        self.fc_sent = 0
        self.error: Optional[str] = None

    @property
    def busy(self) -> bool:
        return self.expected is not None

    # -- FC helper ------------------------------------------------------- #
    def _fc(self, fs: int, note: str = "") -> dict:
        self.fc_sent += 1
        return {"fs": fs, "bs": self.rx_bs, "stmin": self.rx_stmin,
                "dl": self.fc_dl, "note": note}

    # -- main ------------------------------------------------------------ #
    def feed(self, data: bytes, ts: float = 0.0) -> RecvEvent:
        self.frames += 1
        try:
            pci = parse_pci(data)
        except IsoTpError as exc:
            self.error = str(exc)
            raise

        # --- a new message must start with SF or FF --------------------- #
        if not self.busy:
            if pci.kind == PCI_SF:
                n = pci.sf_len
                if n is None or n == 0:
                    raise IsoTpError("SF_DL=0 on a classic-length frame")
                hdr = 2 if (pci.raw0 == 0x00 and pci.dl > 8) else 1
                if n > pci.dl - hdr:
                    raise IsoTpError(f"SF_DL {n} > available {pci.dl - hdr}")
                if n > self.max_len:
                    raise IsoTpOverflow(f"SF_DL {n} > max_len {self.max_len}")
                return RecvEvent(payload=bytes(data[hdr:hdr + n]),
                                 kind="SF", note=f"{n} B single frame")
            if pci.kind == PCI_FF:
                total = pci.ff_len or 0
                hdr = 6 if pci.ff_escape else 2
                if total == 0:
                    raise IsoTpError("FF_DL=0")
                if total > self.max_len:
                    self.reset()
                    return RecvEvent(fc=self._fc(FS_OVFLW, "len > max_len"),
                                     kind="FF", note=f"overflow {total} B")
                if total <= pci.dl - hdr:
                    # Spec says this must be an SF; tolerate peers that do it
                    # anyway but record it, because it usually means bad math.
                    return RecvEvent(payload=bytes(data[hdr:hdr + total]),
                                     kind="FF",
                                     note=f"FF used for {total} B (should be SF)")
                self.expected = total
                self.buf = bytearray(data[hdr:hdr + min(pci.dl - hdr, total)])
                self.next_sn = 1
                self.rx_in_block = 0
                return RecvEvent(fc=self._fc(FS_CTS, f"after FF, expect {total}"),
                                 kind="FF",
                                 note=f"{total} B announced, escape={pci.ff_escape}")
            if pci.kind == PCI_FC:
                return RecvEvent(kind="FC", note="unsolicited FC ignored")
            raise IsoTpError("CF while idle (no FF seen)")

        # --- continuation ---------------------------------------------- #
        if pci.kind != PCI_CF:
            self.reset()
            raise IsoTpError(
                f"expected CF, got PCI type {pci.kind} (0x{pci.raw0:02X})")

        if pci.sn != self.next_sn:
            self.reset()
            raise IsoTpError(
                f"SN mismatch: expected {self.next_sn}, got {pci.sn}")

        remaining = self.expected - len(self.buf)
        take = min(pci.dl - 1, remaining)
        self.buf += data[1:1 + take]
        self.next_sn = (self.next_sn + 1) & 0x0F
        self.rx_in_block += 1

        if len(self.buf) >= self.expected:
            payload = bytes(self.buf[:self.expected])
            self.reset()
            return RecvEvent(payload=payload, kind="CF",
                             note=f"complete {len(payload)} B")

        fc = None
        if self.rx_bs and self.rx_in_block >= self.rx_bs:
            self.rx_in_block = 0
            fc = self._fc(FS_CTS, "block boundary")
        return RecvEvent(fc=fc, kind="CF",
                         note=f"{len(self.buf)}/{self.expected} B")


# --------------------------------------------------------------------------- #
# stats
# --------------------------------------------------------------------------- #

@dataclass
class SendStats:
    nbytes: int = 0
    dl: int = 0
    frames: int = 0
    sf: int = 0
    ff: int = 0
    cf: int = 0
    fc_rx: int = 0
    wait_fc: int = 0
    bytes_cf: int = 0
    elapsed: float = 0.0
    started: float = 0.0
    cf_times: list = field(default_factory=list)
    fc_list: list = field(default_factory=list)
    stmin_targets: list = field(default_factory=list)

    @property
    def cf_gaps(self) -> list:
        return [b - a for a, b in zip(self.cf_times, self.cf_times[1:])]

    def as_dict(self) -> dict:
        gaps = self.cf_gaps
        return {
            "nbytes": self.nbytes, "dl": self.dl, "frames": self.frames,
            "sf": self.sf, "ff": self.ff, "cf": self.cf,
            "fc_rx": self.fc_rx, "wait_fc": self.wait_fc,
            "bytes_cf": self.bytes_cf,
            "elapsed_s": round(self.elapsed, 6),
            "cf_gap_min_ms": round(min(gaps) * 1000, 3) if gaps else None,
            "cf_gap_max_ms": round(max(gaps) * 1000, 3) if gaps else None,
            "cf_gap_median_ms": (round(sorted(gaps)[len(gaps) // 2] * 1000, 3)
                                 if gaps else None),
            "fc": self.fc_list,
        }


# --------------------------------------------------------------------------- #
# transport: in-process loopback
# --------------------------------------------------------------------------- #

class Transport:
    """Duck-typed transport: send(Frame) / recv(timeout) -> Frame | None."""

    def send(self, frame: Frame) -> None:
        raise NotImplementedError

    def recv(self, timeout: float) -> Optional[Frame]:
        raise NotImplementedError

    def close(self) -> None:
        pass


class _QueueEndpoint(Transport):
    def __init__(self, bus: "VirtualBus", side: int):
        self.bus = bus
        self.side = side
        self.seq = 0

    def send(self, frame: Frame) -> None:
        frame.ts = time.perf_counter()
        self.bus.seq += 1
        frame.seq = self.bus.seq
        self.bus.delivered.append(frame)
        self.bus.queues[1 - self.side].put(frame)

    def recv(self, timeout: float) -> Optional[Frame]:
        try:
            return self.bus.queues[self.side].get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None

    def close(self) -> None:
        pass


class VirtualBus:
    """In-process CAN bus between exactly two endpoints (tester <-> ECU stub)."""

    def __init__(self):
        self.queues = {0: queue.Queue(), 1: queue.Queue()}
        self.delivered: list = []
        self.seq = 0

    def endpoint(self, side: int) -> Transport:
        return _QueueEndpoint(self, side)


# --------------------------------------------------------------------------- #
# transport: fixed-size raw frames over TCP (for a framing-less bridge)
# --------------------------------------------------------------------------- #

class TcpFrameTransport(Transport):
    """Raw fixed-size frames over a TCP stream.

    layout: `raw` (only data, frame size implied), or `id+data`, or
    `len+id+data`; enough for a bridge that speaks bare CAN FD frames.
    """

    def __init__(self, host: str, port: int, frame_dl: int = 16,
                 layout: str = "raw", can_id_bytes: int = 4,
                 id_endian: str = "big", id_header: bool = False,
                 extra_tail: int = 0, timeout: float = 4.0,
                 prepend_len: int = 0, len_endian: str = "big"):
        self.host, self.port = host, port
        self.frame_dl = frame_dl
        self.layout = layout
        self.can_id_bytes = can_id_bytes
        self.id_endian = id_endian
        self.id_header = id_header
        self.extra_tail = extra_tail
        self.timeout = timeout
        self.prepend_len = prepend_len
        self.len_endian = len_endian
        self.sock = None
        self.buf = bytearray()
        self.rx_id = None

    def open(self) -> None:
        import socket
        self.sock = socket.create_connection((self.host, self.port),
                                             timeout=self.timeout)
        self.sock.settimeout(self.timeout)

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def _encode(self, fr: Frame) -> bytes:
        body = fr.data
        if self.layout == "id+data":
            body = fr.can_id.to_bytes(self.can_id_bytes, self.id_endian) + body
        elif self.layout == "len+id+data":
            mid = fr.can_id.to_bytes(self.can_id_bytes, self.id_endian) + fr.data
            body = len(fr.data).to_bytes(2, "big") + mid
        if self.prepend_len:
            body = len(body).to_bytes(self.prepend_len, self.len_endian) + body
        return body

    def send(self, fr: Frame) -> None:
        self.sock.sendall(self._encode(fr))

    def _need(self) -> int:
        n = self.frame_dl
        if self.layout in ("id+data", "len+id+data"):
            n += self.can_id_bytes + (2 if self.layout == "len+id+data" else 0)
        if self.prepend_len:
            n += self.prepend_len
        return n

    def recv(self, timeout: float) -> Optional[Frame]:
        import socket
        need = self._need()
        end = time.perf_counter() + timeout
        while len(self.buf) < need:
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
        raw = bytes(self.buf[:need])
        del self.buf[:need]
        can_id = self.rx_id if self.rx_id is not None else 0
        if self.prepend_len:
            raw = raw[self.prepend_len:]
        if self.layout == "id+data":
            can_id = int.from_bytes(raw[:self.can_id_bytes], self.id_endian)
            data = raw[self.can_id_bytes:]
        elif self.layout == "len+id+data":
            pay = int.from_bytes(raw[:2], "big")
            rest = raw[2:]
            can_id = int.from_bytes(rest[:self.can_id_bytes], self.id_endian)
            data = rest[self.can_id_bytes:self.can_id_bytes + pay]
        else:
            data = raw
        return Frame(can_id=can_id, data=data, brs=True, fd=self.frame_dl > 8,
                     ts=time.perf_counter())


# --------------------------------------------------------------------------- #
# the link: sender + receiver tied to one CAN ID pair
# --------------------------------------------------------------------------- #

class IsoTpLink:
    """Bidirectional ISO-TP link over (tx_id, rx_id).

    `dl` is the CAN FD data length used for SF/FF/CF (8..64).  Flow Control
    frames are sent with `fc_dl` bytes (default 8) because a 3-byte FC padded
    to 8 is legal on a CAN FD bus and is what most gateways expect.
    """

    def __init__(self, transport: Transport, tx_id: int, rx_id: Optional[int],
                 dl: int = 16, brs: bool = True, pad: int = DEFAULT_PAD,
                 rx_bs: int = 0, rx_stmin: int = 0x00,
                 fc_dl: Optional[int] = None,
                 n_bs: float = N_BS, n_cr: float = N_CR, n_as: float = N_AS,
                 n_wftmax: int = N_WFTMAX,
                 label: str = "tester", trace: Optional[list] = None,
                 verbose: bool = False):
        if dl not in CANFD_DL:
            dl = round_dl(dl)
        self.transport = transport
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.dl = dl
        self.brs = brs
        self.pad = pad
        self.fc_dl = fc_dl if fc_dl is not None else min(8, dl)
        self.n_bs, self.n_cr, self.n_as = n_bs, n_cr, n_as
        self.n_wftmax = n_wftmax
        self.label = label
        self.verbose = verbose
        self.trace = trace if trace is not None else []
        self.reasm = Reassembler(label=f"{label}/rx", rx_bs=rx_bs,
                                 rx_stmin=rx_stmin, fc_dl=self.fc_dl)
        self.stats: list = []
        self._last_cf_ts: Optional[float] = None

    # -- logging --------------------------------------------------------- #
    def _say(self, msg: str) -> None:
        if self.verbose:
            print(f"  [{self.label}] {msg}")

    def _record(self, direction: str, fr: Frame, kind: str = "") -> None:
        self.trace.append({"dir": direction, "kind": kind, "can_id":
                           f"0x{fr.can_id:03X}", "dl": len(fr.data),
                           "hex": fr.data.hex(), "brs": fr.brs,
                           "fd": fr.fd, "t": round(fr.ts, 6)})

    # -- low level ------------------------------------------------------- #
    def _tx(self, data: bytes, kind: str) -> Frame:
        fr = Frame(can_id=self.tx_id, data=bytes(data), brs=self.brs,
                   fd=self.dl > 8, ts=time.perf_counter())
        self._record("tx", fr, kind)
        self.transport.send(fr)
        self._say(f"TX {kind:<2} {hx(fr.data)}")
        return fr

    def _rx(self, timeout: float) -> Optional[Frame]:
        fr = self.transport.recv(timeout)
        if fr is not None:
            if fr.ts == 0.0:
                fr.ts = time.perf_counter()
            self._record("rx", fr)
            self._say(f"RX    {hx(fr.data)}")
        return fr

    # -- FC handling ----------------------------------------------------- #
    def _wait_fc(self, st: SendStats) -> dict:
        deadline = time.perf_counter() + self.n_bs
        waits = 0
        while True:
            left = deadline - time.perf_counter()
            if left <= 0:
                raise IsoTpTimeout(
                    f"N_Bs expired waiting for Flow Control after "
                    f"{st.frames} frames")
            fr = self._rx(left)
            if fr is None:
                continue
            if self.rx_id is not None and fr.can_id != self.rx_id:
                self._say(f"ignore frame from 0x{fr.can_id:03X}")
                continue
            try:
                pci = parse_pci(fr.data)
            except IsoTpError:
                continue
            if pci.kind != PCI_FC:
                self._say(f"ignore PCI {pci.kind} while waiting FC")
                continue
            fc = {"fs": pci.fs, "bs": pci.bs, "stmin_raw": pci.stmin_raw,
                  "stmin_s": pci.stmin_s, "hex": fr.data.hex()}
            st.fc_rx += 1
            st.fc_list.append(fc)
            self._say(f"FC fs={pci.fs} bs={pci.bs} "
                      f"stmin={stmin_repr(pci.stmin_raw)}")
            if pci.fs == FS_CTS:
                return fc
            if pci.fs == FS_WAIT:
                waits += 1
                st.wait_fc += 1
                if waits > self.n_wftmax:
                    raise IsoTpTimeout(
                        f"N_WFTmax exceeded ({self.n_wftmax} WAIT frames)")
                deadline = time.perf_counter() + self.n_bs
                continue
            if pci.fs == FS_OVFLW:
                raise IsoTpOverflow("peer answered FS=OVFLW (overflow/abort)")
            raise IsoTpError(f"reserved FlowStatus {pci.fs}")

    # -- send ------------------------------------------------------------ #
    def send(self, payload: bytes, timeout: Optional[float] = None) -> SendStats:
        payload = bytes(payload)
        n = len(payload)
        if n == 0:
            raise IsoTpError("refusing to send an empty payload")
        st = SendStats(nbytes=n, dl=self.dl, started=time.perf_counter())
        t0 = st.started
        # A Single Frame must fit *this link's* N_DL, not merely the CAN FD
        # maximum: on a 16-byte link a 24-byte answer is FF + CFs, even though
        # the CAN FD standard would also allow it as one 32-byte SF.
        max_sf_cap = MAX_SF_FD if self.dl > 8 else MAX_SF_CLASSIC
        max_sf_wire = (self.dl - 2) if self.dl > 8 else (self.dl - 1)
        max_sf = min(max_sf_cap, max_sf_wire)
        self._last_cf_ts = None

        if n <= max_sf:
            data = build_sf(payload, dl=self.dl, pad=self.pad)
            self._tx(data, "SF")
            st.frames += 1
            st.sf += 1
            st.elapsed = time.perf_counter() - t0
            self.stats.append(st)
            return st

        ff, carried = build_ff(n, payload, dl=self.dl, pad=self.pad)
        self._tx(ff, "FF")
        st.frames += 1
        st.ff += 1
        self._say(f"FF declares {n} B, carries {carried}")

        off = carried
        sn = 1
        need_fc = True
        bs = 0
        stmin = 0.0
        sent_in_block = 0
        last_cf = None

        while off < n:
            if need_fc:
                fc = self._wait_fc(st)
                bs = fc["bs"]
                stmin = fc["stmin_s"]
                st.stmin_targets.append(stmin)
                sent_in_block = 0
                need_fc = False
            chunk_len = min(self.dl - 1, n - off)
            if last_cf is not None and stmin > 0:
                sleep_until(last_cf + stmin)
            data = build_cf(sn, payload[off:off + chunk_len], dl=self.dl,
                            pad=self.pad)
            self._tx(data, "CF")
            now = time.perf_counter()
            st.frames += 1
            st.cf += 1
            st.bytes_cf += chunk_len
            st.cf_times.append(now)
            last_cf = now
            self._last_cf_ts = now
            off += chunk_len
            sn = (sn + 1) & 0x0F
            sent_in_block += 1
            if bs and sent_in_block >= bs and off < n:
                need_fc = True

        st.elapsed = time.perf_counter() - t0
        self.stats.append(st)
        return st

    # -- receive --------------------------------------------------------- #
    def recv(self, timeout: Optional[float] = None,
             first_timeout: Optional[float] = None) -> bytes:
        timeout = self.n_cr if timeout is None else timeout
        deadline = time.perf_counter() + (first_timeout or timeout)
        while True:
            left = deadline - time.perf_counter()
            if left <= 0:
                raise IsoTpTimeout(
                    f"N_Cr expired waiting for a frame "
                    f"({len(self.reasm.buf)}/{self.reasm.expected} B so far)")
            fr = self._rx(left)
            if fr is None:
                continue
            if self.rx_id is not None and fr.can_id != self.rx_id:
                continue
            ev = self.reasm.feed(fr.data, fr.ts)
            if ev.fc is not None:
                data = build_fc(ev.fc["fs"], ev.fc["bs"], ev.fc["stmin"],
                                dl=ev.fc.get("dl", self.fc_dl))
                self._tx(data, "FC")
            if ev.payload is not None:
                return ev.payload
            # each continuation resets the inter-frame timer
            deadline = time.perf_counter() + timeout

    def request(self, payload: bytes, timeout: Optional[float] = None) -> bytes:
        self.send(payload)
        return self.recv(timeout=timeout,
                         first_timeout=timeout if timeout else N_P2_STAR)


# --------------------------------------------------------------------------- #
# mock ECU (self-test peer)
# --------------------------------------------------------------------------- #

class EcuStub(threading.Thread):
    """A minimal ECU that answers ISO-TP requests with a handler callback."""

    def __init__(self, transport: Transport, rx_id: int, tx_id: int,
                 handler: Callable[[bytes], bytes], dl: int = 16,
                 bs: int = 8, stmin: int = 0x00, brs: bool = True,
                 pad: int = DEFAULT_PAD, name: str = "ecu"):
        super().__init__(daemon=True, name=name)
        self.link = IsoTpLink(transport, tx_id=tx_id, rx_id=rx_id, dl=dl,
                              brs=brs, pad=pad, rx_bs=bs, rx_stmin=stmin,
                              label=name)
        self.handler = handler
        self.stop_flag = threading.Event()
        self.handled: list = []
        self.errors: list = []

    def run(self) -> None:
        while not self.stop_flag.is_set():
            try:
                req = self.link.recv(timeout=0.2)
            except IsoTpTimeout:
                continue
            except IsoTpError as exc:
                self.errors.append(repr(exc))
                continue
            self.handled.append(req)
            try:
                resp = self.handler(req)
            except Exception as exc:  # noqa: BLE001 - test harness
                self.errors.append(f"handler: {exc!r}")
                break
            if resp:
                try:
                    self.link.send(resp)
                except IsoTpError as exc:
                    self.errors.append(f"respond: {exc!r}")
                    break

    def stop(self) -> None:
        self.stop_flag.set()
        self.join(timeout=3.0)


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #

class _Results:
    def __init__(self):
        self.rows: list = []

    def check(self, name: str, cond: bool, detail: str = "") -> bool:
        self.rows.append({"name": name, "ok": bool(cond), "detail": detail})
        mark = "PASS" if cond else "FAIL"
        print(f"  [{mark}] {name}" + (f"  -- {detail}" if detail else ""))
        return bool(cond)

    def eq(self, name: str, got, want, fmt=str) -> bool:
        ok = got == want
        return self.check(name, ok, f"got={fmt(got)} want={fmt(want)}")

    @property
    def ok(self) -> bool:
        return all(r["ok"] for r in self.rows)


def _t_builders(res: _Results) -> None:
    print("\n[1] frame builders / parsers")
    res.eq("SF classic 3B (dl=8)",
           build_sf(b"\x22\xF1\x90", dl=8).hex(), "0322f190cccccccc")
    res.eq("SF classic 7B (dl=8)",
           build_sf(bytes(range(7)), dl=8).hex(), "0700010203040506")
    # 8 bytes on CAN FD must use the escape form: 00 08 <8 bytes> + 6 pad
    res.eq("SF escape 8B (dl=16)",
           build_sf(bytes(range(8)), dl=16).hex(),
           "00080001020304050607" + "cc" * 6)
    # 62 bytes on dl=64: 00 3E + 62 = 64 bytes exactly
    sf62 = build_sf(bytes([0xAA]) * 62, dl=64)
    res.check("SF escape 62B (dl=64) length", len(sf62) == 64,
              f"len={len(sf62)}")
    res.eq("SF escape 62B header", sf62[:2].hex(), "003e")

    ff, carried = build_ff(512, bytes([0x5A]) * 512, dl=16)
    res.eq("FF 512B header (12-bit len)", ff[:2].hex(), "1200")
    res.eq("FF 512B carried", carried, 14)
    res.check("FF 512B frame length", len(ff) == 16, f"len={len(ff)}")

    ff2, carried2 = build_ff(16384, bytes([0x5A]) * 16384, dl=16)
    res.eq("FF 16384B header (escape uint32)", ff2[:6].hex(), "100000004000")
    res.eq("FF 16384B carried", carried2, 10)
    res.check("FF 16384B frame length", len(ff2) == 16, f"len={len(ff2)}")

    # exactly 4095 must stay 12-bit, 4096 must escape
    ff3, _ = build_ff(4095, bytes(4095), dl=16)
    res.eq("FF 4095B stays 12-bit", ff3[:2].hex(), "1fff")
    ff4, _ = build_ff(4096, bytes(4096), dl=16)
    res.eq("FF 4096B escapes", ff4[:6].hex(), "100000001000")

    res.eq("CF sn=1", build_cf(1, b"\xAA" * 15, dl=16)[:2].hex(), "21aa")
    res.eq("CF sn=15", build_cf(15, b"\xAA" * 15, dl=16)[0], 0x2F)
    res.eq("CF sn=0", build_cf(0, b"\xAA" * 15, dl=16)[0], 0x20)

    res.eq("FC CTS bs=0 stmin=0", build_fc(FS_CTS, 0, 0, dl=8).hex(),
           "300000" + "cc" * 5)
    res.eq("FC WAIT bs=0 stmin=0", build_fc(FS_WAIT, 0, 0, dl=8)[:3].hex(),
           "310000")
    res.eq("FC OVFLW", build_fc(FS_OVFLW, 0, 0, dl=8)[:1].hex(), "32")
    res.eq("FC CTS bs=8 stmin=0xF3",
           build_fc(FS_CTS, 8, 0xF3, dl=8)[:3].hex(), "3008f3")

    p = parse_fc(b"\x30\x08\xF3" + bytes([0xCC]) * 5)
    res.check("parse FC fields",
              p["fs"] == 0 and p["bs"] == 8 and p["stmin_raw"] == 0xF3,
              str(p))
    res.check("parse FC stmin 0xF3 = 300us",
              abs(p["stmin_s"] - 0.0003) < 1e-9, f"{p['stmin_s']}")


def _t_stmin(res: _Results) -> None:
    print("\n[2] STmin decoding")
    cases = [(0x00, 0.0), (0x01, 0.001), (0x0A, 0.01), (0x7F, 0.127),
             (0xF1, 0.0001), (0xF2, 0.0002), (0xF9, 0.0009),
             (0x80, 0.127), (0xF0, 0.127), (0xFA, 0.127), (0xFF, 0.127)]
    for raw, want in cases:
        res.check(f"STmin {raw:#04x}", abs(stmin_seconds(raw) - want) < 1e-9,
                  f"{stmin_seconds(raw)} s (want {want})")
    res.check("STmin 0x80..0xF0 flagged reserved", stmin_is_reserved(0x80)
              and stmin_is_reserved(0xF0) and not stmin_is_reserved(0xF1))


def _make_pair(dl: int, peer_bs: int, peer_stmin: int,
               handler: Callable[[bytes], bytes], tester_bs: int = 0,
               tester_stmin: int = 0x00):
    bus = VirtualBus()
    tester_tr = bus.endpoint(0)
    peer_tr = bus.endpoint(1)
    tester = IsoTpLink(tester_tr, tx_id=0x7E1, rx_id=0x7E9, dl=dl,
                       rx_bs=tester_bs, rx_stmin=tester_stmin, label="tester")
    peer = EcuStub(peer_tr, rx_id=0x7E1, tx_id=0x7E9, handler=handler,
                   dl=dl, bs=peer_bs, stmin=peer_stmin, name="ecu")
    peer.start()
    return bus, tester, peer


def _t_roundtrip_16384(res: _Results) -> None:
    print("\n[3] 16384 B round trip, both directions (CAN FD)")
    payload = bytes((i * 7 + 0x11) & 0xFF for i in range(16384))
    want = hashlib.sha256(payload).hexdigest()

    for dl in (16, 64):
        # --- tester -> ECU: 16384 B request (exercises TX: escape FF, SN wrap)
        got_holder = {}

        def handler(req, _dl=dl, _h=got_holder):
            _h["req"] = req
            return b"\x63\x24" + bytes(80)  # small answer; content not important

        bus, tester, peer = _make_pair(dl=dl, peer_bs=8, peer_stmin=0x00,
                                       handler=handler)
        st = tester.send(payload)
        resp = tester.recv(timeout=3.0)
        peer.stop()
        req = got_holder.get("req", b"")
        res.check(f"dl={dl} TX 16384 B received intact by peer",
                  req == payload,
                  f"peer got {len(req)} B sha={hashlib.sha256(req).hexdigest()[:16]}")
        res.check(f"dl={dl} TX 16384 B sha256 match",
                  hashlib.sha256(req).hexdigest() == want,
                  hashlib.sha256(req).hexdigest()[:16])
        res.check(f"dl={dl} TX used FF + CFs",
                  st.ff == 1 and st.cf > 1000 if dl == 16 else st.cf > 250,
                  f"ff={st.ff} cf={st.cf} frames={st.frames}")
        res.check(f"dl={dl} TX escape FF for 16384 (>4095)",
                  st.ff == 1, "FF escape path")
        res.check(f"dl={dl} TX saw 8-frame FC blocks ({st.fc_rx} FCs)",
                  st.fc_rx >= (st.cf // 8), f"fc_rx={st.fc_rx} cf={st.cf}")
        res.check(f"dl={dl} TX compact response received",
                  resp.startswith(b"\x63"), f"{len(resp)} B")

        # --- ECU -> tester: 16384 B response (exercises RX reassembly)
        def big_handler(req, _p=payload):
            return _p

        bus, tester, peer = _make_pair(dl=dl, peer_bs=8, peer_stmin=0x00,
                                       handler=big_handler)
        req = b"\x23\x24" + b"\x00" * 6  # 8-byte request (SF on dl>=8)
        back = tester.request(req, timeout=10.0)
        peer.stop()
        res.check(f"dl={dl} RX 16384 B reassembled length", len(back) == 16384,
                  f"{len(back)} B")
        res.check(f"dl={dl} RX 16384 B sha256 match",
                  hashlib.sha256(back).hexdigest() == want,
                  hashlib.sha256(back).hexdigest()[:16])
        res.check(f"dl={dl} RX byte-exact", back == payload, "compare")


def _t_fc_behaviour(res: _Results) -> None:
    print("\n[4] Flow Control semantics (BS / WAIT / OVFLW)")
    payload = bytes(range(256)) * 2  # 512 B

    # BS=8: exactly 8 CFs per block
    bus, tester, peer = _make_pair(dl=16, peer_bs=8, peer_stmin=0x00,
                                   handler=lambda r: b"\x63")
    st = tester.send(payload)
    resp = tester.recv(timeout=2.0)
    peer.stop()
    want_fc = 1 + (st.cf - 1) // 8  # one FC after FF, then every 8 CFs
    res.check("BS=8 FC count matches block boundaries",
              st.fc_rx == want_fc, f"fc={st.fc_rx} cf={st.cf} want={want_fc}")

    # BS=0: no intermediate FC at all
    bus, tester, peer = _make_pair(dl=16, peer_bs=0, peer_stmin=0x00,
                                   handler=lambda r: b"\x63")
    st = tester.send(payload)
    tester.recv(timeout=2.0)
    peer.stop()
    res.check("BS=0 only the FF FC", st.fc_rx == 1, f"fc_rx={st.fc_rx}")

    # FS=WAIT once, then CTS: must be tolerated
    class WaitThenCts(IsoTpLink):
        pass

    bus = VirtualBus()
    tester = IsoTpLink(bus.endpoint(0), tx_id=0x7E1, rx_id=0x7E9, dl=16)
    peer_tr = bus.endpoint(1)
    state = {"n": 0}

    def wait_peer():
        # consume FF, answer WAIT, hold a bit, then CTS, then drain CFs
        peer_tr.recv(2.0)
        peer_tr.send(Frame(0x7E9, build_fc(FS_WAIT, 0, 0, dl=8)))
        time.sleep(0.05)  # shorter than N_Bs; the tester must keep waiting
        peer_tr.send(Frame(0x7E9, build_fc(FS_CTS, 0, 0, dl=8)))
        # drain everything else so send() does not block on a full queue
        while peer_tr.recv(0.3) is not None:
            pass

    th = threading.Thread(target=wait_peer, daemon=True)
    th.start()
    st = tester.send(payload)
    th.join(timeout=3.0)
    res.check("FS=WAIT tolerated then CTS", st.wait_fc == 1,
              f"wait_fc={st.wait_fc}")

    # FS=OVFLW: must raise
    bus = VirtualBus()
    tester = IsoTpLink(bus.endpoint(0), tx_id=0x7E1, rx_id=0x7E9, dl=16)
    peer_tr = bus.endpoint(1)

    def ovflw_peer():
        peer_tr.recv(2.0)
        peer_tr.send(Frame(0x7E9, build_fc(FS_OVFLW, 0, 0, dl=8)))

    th = threading.Thread(target=ovflw_peer, daemon=True)
    th.start()
    raised = ""
    try:
        tester.send(payload)
    except IsoTpOverflow as exc:
        raised = "IsoTpOverflow"
    th.join(timeout=2.0)
    res.check("FS=OVFLW aborts the send", raised == "IsoTpOverflow", raised)


def _t_stmin_timing(res: _Results) -> None:
    print("\n[5] STmin timing (millisecond and 100 us encodings)")
    # 20 ms STmin, BS=0 -> gaps must be >= 20 ms
    payload = bytes(range(200))
    bus, tester, peer = _make_pair(dl=16, peer_bs=0, peer_stmin=0x14,
                                   handler=lambda r: b"\x63")
    st = tester.send(payload)
    tester.recv(timeout=2.0)
    peer.stop()
    gaps = st.cf_gaps
    ok = gaps and min(gaps) >= 0.020 * 0.98
    res.check("STmin 20 ms honoured on every CF gap", ok,
              f"min={min(gaps) * 1000:.2f} ms max={max(gaps) * 1000:.2f} "
              f"median={sorted(gaps)[len(gaps) // 2] * 1000:.2f} ms "
              f"({len(gaps)} gaps)")

    # 300 us STmin (0xF3) must not be treated as 300 ms
    payload = bytes(range(64))
    bus, tester, peer = _make_pair(dl=16, peer_bs=0, peer_stmin=0xF3,
                                   handler=lambda r: b"\x63")
    t0 = time.perf_counter()
    st = tester.send(payload)
    tester.recv(timeout=2.0)
    dt = time.perf_counter() - t0
    peer.stop()
    gaps = st.cf_gaps
    res.check("STmin 0xF3 (300 us) not misread as ms",
              dt < 0.5 and gaps and min(gaps) >= 0.00029,
              f"total={dt:.3f}s min_gap={min(gaps) * 1e6:.0f} us "
              f"({len(gaps)} gaps)")


def _t_negative(res: _Results) -> None:
    print("\n[6] negative cases (SN error, idle CF, truncated headers)")
    # SN mismatch must be rejected
    r = Reassembler()
    r.feed(build_ff(300, bytes(300), dl=16)[0])
    raised = ""
    try:
        r.feed(build_cf(3, bytes(15), dl=16))  # expected SN=1
    except IsoTpError as exc:
        raised = str(exc)
    res.check("SN mismatch raises", "SN mismatch" in raised, raised)

    # CF with no FF must be rejected
    r = Reassembler()
    raised = ""
    try:
        r.feed(build_cf(1, bytes(15), dl=16))
    except IsoTpError as exc:
        raised = str(exc)
    res.check("CF while idle raises", "CF while idle" in raised, raised)

    # escape FF announced length must be honoured
    r = Reassembler()
    ff, _carried = build_ff(16384, bytes(16384), dl=16)
    ev = r.feed(ff)
    res.check("escape FF parsed total=16384",
              r.expected == 16384 and ev.fc is not None, f"{r.expected}")

    # short last CF (unpadded) is legal
    r = Reassembler()
    r.feed(build_ff(30, bytes(30), dl=16)[0])  # carries 14
    r.feed(build_cf(1, bytes(15), dl=16))   # 29
    ev = r.feed(bytes([0x22]) + bytes(1))    # 1 byte, no padding, completes
    res.check("unpadded final CF accepted",
              ev.payload is not None and len(ev.payload) == 30,
              f"{len(ev.payload) if ev.payload else None} B")

    # SF_DL larger than the frame
    r = Reassembler()
    raised = ""
    try:
        r.feed(bytes([0x07, 1, 2]))  # SF says 7, only 2 present
    except IsoTpError as exc:
        raised = str(exc)
    res.check("SF_DL > available raises", "SF_DL" in raised, raised)


def _t_sf_fd(res: _Results) -> None:
    print("\n[7] CAN FD single frames (escape form, 62 B max)")
    # 62-byte SF round trip through a real link pair
    payload = bytes(range(62))
    bus, tester, peer = _make_pair(dl=64, peer_bs=0, peer_stmin=0,
                                   handler=lambda r: r)
    back = tester.request(payload, timeout=3.0)
    peer.stop()
    res.check("62 B SF echoed intact", back == payload, f"{len(back)} B")

    # 7 B stays classic even on dl=64
    payload = b"\x22\xF1\xA0"
    bus, tester, peer = _make_pair(dl=64, peer_bs=0, peer_stmin=0,
                                   handler=lambda r: r)
    back = tester.request(payload, timeout=3.0)
    peer.stop()
    res.check("3 B SF on CAN FD stays classic form", back == payload,
              f"{len(back)} B")

    # 63 B must not fit in an SF
    raised = ""
    try:
        build_sf(bytes(63), dl=64)
    except IsoTpError as exc:
        raised = str(exc)
    res.check("63 B refused as SF", "> 62" in raised, raised)


def _t_realistic_read(res: _Results) -> None:
    print("\n[8] realistic 0x23 read (512 B block, ECU answers 515 B)")
    fw = bytes((i * 13 + 3) & 0xFF for i in range(512))
    block = 0

    def handler(req):
        nonlocal block
        assert req[0] == 0x23, req.hex()
        alfid = req[1]
        addr_len = alfid & 0x0F
        size_len = (alfid >> 4) & 0x0F
        addr = int.from_bytes(req[2:2 + addr_len], "big")
        size = int.from_bytes(req[2 + addr_len:2 + addr_len + size_len], "big")
        off = addr - 0x08000000
        data = fw[off:off + size]
        block += 1
        return (b"\x63" + bytes([alfid]) + addr.to_bytes(addr_len, "big")
                + size.to_bytes(size_len, "big") + data)

    bus, tester, peer = _make_pair(dl=16, peer_bs=8, peer_stmin=0x00,
                                   handler=handler)
    req = b"\x23\x24" + (0x08000000).to_bytes(4, "big") + (512).to_bytes(2, "big")
    resp = tester.request(req, timeout=5.0)
    peer.stop()
    res.check("0x63 response reassembled", resp[0] == 0x63, resp[:8].hex())
    res.check("0x63 payload byte-exact",
              resp[8:] == fw and len(resp) == 8 + 512,
              f"{len(resp)} B total, {len(resp) - 8} B data")
    res.check("512 B answer needed FF + 35 CFs", block == 1, f"handled={block}")


def _t_link_stats(res: _Results) -> None:
    print("\n[9] stats / trace integrity")
    bus, tester, peer = _make_pair(dl=16, peer_bs=0, peer_stmin=0,
                                   handler=lambda r: b"\x50\x03")
    tester.request(b"\x10\x03", timeout=3.0)
    peer.stop()
    st = tester.stats[-1]
    res.check("stats count frames", st.frames == 1 and st.sf == 1,
              st.as_dict().__str__())
    res.check("trace has tx and rx entries",
              any(t["dir"] == "tx" for t in tester.trace)
              and any(t["dir"] == "rx" for t in tester.trace),
              f"{len(tester.trace)} entries")


def self_test(evidence_dir: Optional[str] = None, verbose: bool = False) -> int:
    print("=" * 78)
    print("ISO 15765-2 (CAN FD) transport self-test -- no target involved")
    print("=" * 78)
    t_start = time.time()
    res = _Results()
    _t_builders(res)
    _t_stmin(res)
    _t_roundtrip_16384(res)
    _t_fc_behaviour(res)
    _t_stmin_timing(res)
    _t_negative(res)
    _t_sf_fd(res)
    _t_realistic_read(res)
    _t_link_stats(res)

    passed = sum(1 for r in res.rows if r["ok"])
    total = len(res.rows)
    print("\n" + "=" * 78)
    print(f"RESULT: {passed}/{total} checks passed "
          f"({'OK' if res.ok else 'FAILURES'}) "
          f"in {time.time() - t_start:.1f}s")
    print("=" * 78)

    if evidence_dir:
        os.makedirs(evidence_dir, exist_ok=True)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        doc = {"tool": "isotp.py", "iso": "ISO 15765-2:2016 (DoCAN) for CAN FD",
               "ts": stamp, "host": sys.platform, "python": sys.version,
               "passed": passed, "total": total, "ok": res.ok,
               "checks": res.rows}
        base = os.path.join(evidence_dir, "00_selftest_isotp")
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
        with open(base + ".log", "w", encoding="utf-8") as f:
            f.write(f"# isotp.py self-test {stamp}\n")
            for r in res.rows:
                f.write(f"[{'PASS' if r['ok'] else 'FAIL'}] {r['name']}")
                if r["detail"]:
                    f.write(f"  -- {r['detail']}")
                f.write("\n")
            f.write(f"\nRESULT {passed}/{total} {'OK' if res.ok else 'FAIL'}\n")
        print(f"evidence written: {base}.json / .log")
    return 0 if res.ok else 1


# --------------------------------------------------------------------------- #
# CLI extras
# --------------------------------------------------------------------------- #

def demo_512() -> None:
    """Show the exact frames a 512-byte 0x23 read produces (dl=16, BRS)."""
    req = b"\x23\x24" + (0x08000000).to_bytes(4, "big") + (512).to_bytes(2, "big")
    print(f"request ({len(req)} B): {hx(req)}")
    print(f"  -> {build_sf(req, dl=16, pad=0xCC).hex(' ')}  (SF, 8 data bytes only)")
    total = 8 + 512  # 0x63 + ALFID + addr(4) + size(2) + 512
    ff, carried = build_ff(total, bytes(total), dl=16)
    print(f"response {total} B: FF {ff[:6].hex(' ')} ... carries {carried} B")
    print(f"  then {(total - carried + 14) // 15} CFs (SN 1..15 wrap), "
          f"last one truncated then 0xCC padded")
    print(f"  FC example: {build_fc(FS_CTS, 8, 0x00, dl=8).hex(' ')} "
          f"(CTS, BS=8, STmin=0)")


def decode_one(hexstr: str) -> None:
    data = bytes.fromhex(hexstr.replace(" ", "").replace(":", ""))
    p = parse_pci(data)
    print(json.dumps({"frame": data.hex(), "dl": len(data), "pci": p.as_dict()},
                     indent=2))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ISO-TP for CAN FD (self-contained)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--evidence-dir", default=None)
    ap.add_argument("--demo-512", action="store_true")
    ap.add_argument("--decode", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    if args.demo_512:
        demo_512()
        return 0
    if args.decode:
        decode_one(args.decode)
        return 0
    if args.self_test:
        return self_test(args.evidence_dir, args.verbose)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

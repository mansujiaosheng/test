#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""isotp_client.py -- real ISO-TP (ISO 15765-2:2016) sender over pluggable transports.

Target of the whole exercise
----------------------------
CTF CyberCar challenge 10: the VCU accepts a 1116-byte signed+encrypted firmware
update package transferred over a *bidirectional ISO-TP* link.  The tester must
segment the 1116 bytes into ISO-TP frames, honour the VCU's Flow Control
(BlockSize / STmin) and answer its FC frames.  The VCU itself is at
10.224.139.7:8080 and is (as of 2026-11-14) not routable from this host, so
everything here must be runnable offline; the wire transports are selected at
run time and exercised by --self-test against an in-process mock peer.

What is implemented
-------------------
TX side (this file's core)
  * Single Frame (SF), including the 4/5/6/7-byte "classic CAN" and the
    CAN-FD 12/16/20/24/32/48/64-byte single-frame forms.
  * First Frame (FF) with 12-bit FF_DL, plus the escape sequence for
    payloads > 4095 bytes (FF_DL = 0x000, real length follows inside the
    first CF as 4 big-endian bytes).
  * Consecutive Frame (CF) with the 4-bit SN that wraps 15 -> 0 (starts at 1).
  * Flow Control (FC) parsing of all three fields: FS (0 continueToSend,
    1 wait, 2 overflow/abort, 3 reserved), BS (0 = send everything), and
    STmin -- including the 0xF1..0xF9 microsecond encodings (100..900 us),
    the 0x00..0x7F millisecond encodings, and the reserved ranges 0x80..0xF0
    and 0xFA..0xFF which the standard says to treat as 0x7F (127 ms).
  * Strict obedience: exactly BS consecutive frames per block, then wait for
    the next FC; STmin enforced *between* consecutive frames with a busy-wait
    so that sub-millisecond values are actually honoured on Windows.
  * Timeouts: N_Bs (wait for FC), N_Cr-ish sender guard, and N_As-style
    transmit guard; N_WFTmax limit on FS=1 (WAIT) frames; FS=2 raises.
  * Per-frame timestamp log (monotonic relative ms + wall clock), printable
    and dumpable to JSONL/CSV so STmin compliance can be audited afterwards.

RX side (needed to consume the VCU's answers and to build the mock peer)
  * IsoTpReassembler: SF/FF/CF reassembly with SN checking, BS/STmin
    emission driving a matching FC generator.

Transports
  * MockTransport     in-process loopback; used by --self-test, no target.
  * TCPSocketTransport  raw ISO-TP frames on a TCP stream (fixed frame size,
                        padded to 8 like classic CAN by default).
  * DoIPTransport     each ISO-TP frame is carried inside a DoIP
                        diagnosticMessage (0x8001) payload after the SA/TA
                        pair -- for gateways that bridge ISO-TP frames.
                        Re-uses the login/RA logic of 05_TOOLS/cgw_doip.py; the
                        module is loaded lazily so this file also runs on hosts
                        without it.

Read-only discipline: the module never transmits an ECU-state-changing UDS
service by itself. It only carries whatever payload the caller hands it, and
`--guard-read-only` (default ON for the CLI) refuses mutating SIDs unless
explicitly overridden with --allow-mutating, because the CTF rules forbid
destroying the target.

Usage
-----
  python isotp_client.py --self-test
  python isotp_client.py --self-test --stmin 20 --bs 8       # the 1116 case
  python isotp_client.py --list-tests
  python isotp_client.py --dry-run --payload-hex 22F190 --stmin 5 --bs 4
  python isotp_client.py --transport tcp --host 10.224.139.7 --port 8080 \
         --payload-file update.bin
  python isotp_client.py --transport doip --host 10.229.221.2 --port 13400 \
         --sa 0E00 --ta 1000 --payload-file update.bin

Every option has a --help text; exit code 0 means the run met its own checks.
"""

from __future__ import annotations

import argparse
import binascii
import csv
import json
import os
import queue
import socket
import struct
import sys
import threading
import time
from datetime import datetime

# --------------------------------------------------------------------------
# Protocol constants
# --------------------------------------------------------------------------
PCI_SF = 0x0
PCI_FF = 0x1
PCI_CF = 0x2
PCI_FC = 0x3

FS_CONTINUE = 0
FS_WAIT = 1
FS_OVERFLOW = 2
FS_RESERVED = 3

FS_NAMES = {
    FS_CONTINUE: "continueToSend(CTS)",
    FS_WAIT: "wait(WAIT)",
    FS_OVERFLOW: "overflow(OVFLW)",
    FS_RESERVED: "reserved/invalid",
}

# ISO 15765-2 default network layer timings (seconds).
DEFAULT_N_BS = 1.0     # sender waits for FC
DEFAULT_N_CR = 1.0     # receiver waits for CF (used by the mock peer)
DEFAULT_N_AR = 1.0
DEFAULT_N_WFTMAX = 0   # 0 means "wait frames not permitted" in many stacks

STMIN_RESERVED_AS_MS = 0x7F  # 0x80..0xF0 and 0xFA..0xFF -> treat as 0x7F
STMIN_MAX_MS = 0x7F


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def hx(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii").upper()


def now_wall() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def stmin_to_seconds(raw: int) -> float:
    """Decode an STmin byte into seconds exactly as ISO 15765-2 prescribes.

    0x00..0x7F -> 0..127 ms
    0xF1..0xF9 -> 100..900 us
    everything else (0x80..0xF0, 0xFA..0xFF) is reserved and must be treated
    as 0x7F, i.e. 127 ms.  Nothing here is allowed to fall through to a
    "milliseconds" assumption for 0xF1..0xF9 -- that is the classic bug this
    function exists to avoid.
    """
    if 0x00 <= raw <= 0x7F:
        return raw / 1000.0
    if 0xF1 <= raw <= 0xF9:
        return (raw - 0xF0) / 10000.0
    return STMIN_RESERVED_AS_MS / 1000.0


def stmin_describe(raw: int) -> str:
    if 0x00 <= raw <= 0x7F:
        return f"0x{raw:02X} = {raw} ms"
    if 0xF1 <= raw <= 0xF9:
        return f"0x{raw:02X} = {(raw - 0xF0) * 100} us"
    return f"0x{raw:02X} = reserved -> treated as 127 ms"


def precise_sleep_until(deadline: float) -> float:
    """Sleep until time.perf_counter() >= deadline; returns overshoot in seconds.

    Windows' default timer granularity makes time.sleep() useless below ~1 ms,
    so short STmin values are met with a hybrid sleep/busy-wait.  The busy-wait
    window is kept at ~5 ms and yields the GIL periodically so that in-process
    peers (and socket reader threads) are not starved.
    """
    spins = 0
    while True:
        rem = deadline - time.perf_counter()
        if rem <= 0:
            break
        if rem > 0.006:
            time.sleep(rem - 0.005)
        else:
            while time.perf_counter() < deadline:
                spins += 1
                if spins & 0x3FF == 0:
                    time.sleep(0)  # release the GIL
            break
    return max(0.0, time.perf_counter() - deadline)


# --------------------------------------------------------------------------
# Frame log
# --------------------------------------------------------------------------
class FrameLog:
    """Ordered record of every frame with relative + absolute timestamps."""

    def __init__(self):
        self.rows = []
        self.times = []   # absolute perf_counter of each row, parallel to rows
        self.t0 = None

    def start(self):
        self.t0 = time.perf_counter()

    def open_window(self):
        # each new start() call re-bases the relative clock
        self.t0 = time.perf_counter()

    def add(self, direction: str, frame: bytes, kind: str, note: str = "",
            extra: dict | None = None, t: float | None = None):
        if self.t0 is None:
            self.start()
        # `t` lets callers stamp the exact moment a frame was handed to the
        # transport, so inter-frame gaps are not polluted by logging overhead.
        t = time.perf_counter() if t is None else t
        row = {
            "n": len(self.rows) + 1,
            "dir": direction,
            "t_rel_ms": round((t - self.t0) * 1000.0, 3),
            "wall": now_wall(),
            "kind": kind,
            "hex": hx(frame),
            "len": len(frame),
            "note": note,
        }
        if extra:
            row.update(extra)
        self.rows.append(row)
        self.times.append(t)
        return row

    def last_tx_index(self):
        for i in range(len(self.rows) - 1, -1, -1):
            if self.rows[i]["dir"] == "TX":
                return i
        return -1

    def gaps_between_cf(self):
        """[(n, gap_ms)] for each pair of consecutive TX CF frames."""
        idx = [i for i, r in enumerate(self.rows)
               if r["dir"] == "TX" and r["kind"] == "CF"]
        return [(self.rows[idx[i]]["n"],
                 round((self.times[idx[i]] - self.times[idx[i - 1]]) * 1000.0, 3))
                for i in range(1, len(idx))]

    def dump_jsonl(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            for r in self.rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def dump_csv(self, path: str):
        keys = ["n", "dir", "t_rel_ms", "wall", "kind", "hex", "len", "note"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            for r in self.rows:
                w.writerow(r)

    def render(self, limit: int | None = None) -> str:
        rows = self.rows if limit is None else self.rows[:limit]
        out = []
        out.append(f"{'#':>4} {'dir':>3} {'t_rel_ms':>10}  {'kind':<10} {'len':>4}  hex")
        for r in rows:
            out.append(f"{r['n']:>4} {r['dir']:>3} {r['t_rel_ms']:>10.3f}  "
                       f"{r['kind']:<10} {r['len']:>4}  {r['hex']}"
                       + (f"   ; {r['note']}" if r["note"] else ""))
        return "\n".join(out)


# --------------------------------------------------------------------------
# Frame builders / parsers
# --------------------------------------------------------------------------
def build_single_frame(payload: bytes, tx_dl: int = 8, pad: bool = True,
                       pad_byte: int = 0xCC, ext_addr: bytes = b"") -> bytes:
    """Return one ISO-TP SF.  tx_dl is the frame data length (8 for classic CAN)."""
    room = tx_dl - 1 - len(ext_addr)
    if len(payload) > room:
        raise ValueError(f"payload {len(payload)} B does not fit an SF of tx_dl={tx_dl}")
    frame = ext_addr + bytes([(PCI_SF << 4) | len(payload)]) + payload
    if pad:
        frame = frame + bytes([pad_byte]) * (tx_dl - len(frame))
    return frame


def build_first_frame(payload: bytes, tx_dl: int = 8, pad: bool = True,
                      pad_byte: int = 0xCC, ext_addr: bytes = b"",
                      force_escape: bool = False, msg_len: int | None = None) -> bytes:
    """Build an FF.

    Normal form:  PCI=0x1, FF_DL (12 bit), then (tx_dl-2) data bytes.
    Escape form:  used when the message is longer than 4095 bytes.  FF_DL is
                 0x000 and the real 32-bit length occupies the four bytes right
                  after the FF_DL field (the same layout can-isotp implements:
                  ``ff_dl = struct.unpack('>I', data[2:6])``), which leaves
                  tx_dl-6 data bytes in the FF itself.
    """
    n = len(payload) if msg_len is None else msg_len
    ea = len(ext_addr)
    if n <= tx_dl - 2 - ea:
        raise ValueError("payload fits in a single frame; use build_single_frame")
    use_escape = force_escape or n > 0xFFF
    if use_escape:
        # PCI byte 0x10 + FF_DL low byte 0x00 (= 0x000) + 32-bit length, 6 bytes total
        head = ext_addr + bytes([(PCI_FF << 4), 0x00]) + struct.pack(">I", n)
        room = tx_dl - 2 - ea - 4
    else:
        head = ext_addr + struct.pack(">H", (PCI_FF << 12) | n)
        room = tx_dl - 2 - ea
    frame = head + payload[:max(0, room)]
    if pad:
        frame = frame + bytes([pad_byte]) * (tx_dl - len(frame))
    return frame


def first_frame_carries(tx_dl: int, ext_addr_len: int = 0, escape: bool = False) -> int:
    return tx_dl - 2 - ext_addr_len - (4 if escape else 0)


def build_consecutive_frame(seq: int, chunk: bytes, tx_dl: int = 8, pad: bool = True,
                            pad_byte: int = 0xCC, ext_addr: bytes = b"") -> bytes:
    frame = ext_addr + bytes([(PCI_CF << 4) | (seq & 0x0F)]) + chunk
    if pad:
        frame = frame + bytes([pad_byte]) * (tx_dl - len(frame))
    return frame


def build_flow_control(fs: int, bs: int, stmin: int, tx_dl: int = 8,
                       pad: bool = True, pad_byte: int = 0xCC,
                       ext_addr: bytes = b"") -> bytes:
    frame = ext_addr + bytes([(PCI_FC << 4) | (fs & 0x0F), bs & 0xFF, stmin & 0xFF])
    if pad:
        frame = frame + bytes([pad_byte]) * (tx_dl - len(frame))
    return frame


def pci_type(frame: bytes, ext_addr_len: int = 0) -> int:
    if len(frame) <= ext_addr_len:
        return -1
    return frame[ext_addr_len] >> 4


def parse_flow_control(frame: bytes, ext_addr_len: int = 0) -> dict:
    """Parse an FC frame into FS / BS / STmin with the STmin already decoded."""
    if len(frame) < ext_addr_len + 3:
        raise ValueError(f"FC frame too short: {hx(frame)}")
    if pci_type(frame, ext_addr_len) != PCI_FC:
        raise ValueError(f"not a Flow Control frame: {hx(frame)}")
    b0 = frame[ext_addr_len]
    fs = b0 & 0x0F
    bs = frame[ext_addr_len + 1]
    st_raw = frame[ext_addr_len + 2]
    return {
        "fs": fs,
        "fs_name": FS_NAMES.get(fs, "?"),
        "bs": bs,
        "stmin_raw": st_raw,
        "stmin_s": stmin_to_seconds(st_raw),
        "stmin_text": stmin_describe(st_raw),
    }


# --------------------------------------------------------------------------
# Receiver side (needed for the mock peer and for reading VCU responses)
# --------------------------------------------------------------------------
class IsoTpReassembler:
    """Reassembles SF/FF/CF sequences and reports what FC should be sent back."""

    def __init__(self, tx_dl: int = 8, ext_addr: bytes = b""):
        self.tx_dl = tx_dl
        self.ext_addr = ext_addr
        self.reset()

    def reset(self):
        self.total = None
        self.buf = bytearray()
        self.next_seq = 1
        self.frames = 0
        self.error = None

    @property
    def busy(self) -> bool:
        return self.total is not None and len(self.buf) < self.total

    def feed(self, frame: bytes):
        """Return (status, payload_or_None, fc_hint).

        status: 'single' | 'first' | 'consecutive' | 'complete' | 'bad'
        fc_hint: dict(fs=..., bs=..., stmin=...) when the sender should be
                 answered with an FC right now (after FF, and after each block).
        """
        ea = len(self.ext_addr)
        if len(frame) <= ea:
            self.error = "empty frame"
            return "bad", None, None
        b0 = frame[ea]
        pci = b0 >> 4

        if pci == PCI_SF:
            n = b0 & 0x0F
            data = frame[ea + 1:ea + 1 + n]
            self.reset()
            return "single", bytes(data[:n]), None

        if pci == PCI_FF:
            len12 = ((b0 & 0x0F) << 8) | frame[ea + 1]
            if len12 == 0:
                # escape sequence: 32-bit length follows FF_DL in this same frame
                if len(frame) < ea + 6:
                    self.error = "escape length truncated in FF"
                    return "bad", None, None
                self.total = struct.unpack(">I", frame[ea + 2:ea + 6])[0]
                self.buf = bytearray(frame[ea + 6:])
            else:
                self.total = len12
                self.buf = bytearray(frame[ea + 2:])
            self.next_seq = 1
            self.frames = 0
            if self.total <= 0:
                self.error = "FF with zero total length"
                return "bad", None, None
            if len(self.buf) >= self.total:
                payload = bytes(self.buf[:self.total])
                self.reset()
                return "complete", payload, None
            return "first", None, {"fs": FS_CONTINUE, "bs": 0, "stmin": 0}

        if pci == PCI_CF:
            if self.total is None:
                self.error = "CF without FF"
                return "bad", None, None
            seq = b0 & 0x0F
            data = frame[ea + 1:]
            if seq != self.next_seq:
                self.error = f"SN mismatch: got {seq} want {self.next_seq}"
                return "bad", None, None
            self.buf += data
            self.next_seq = (self.next_seq + 1) & 0x0F
            self.frames += 1
            if len(self.buf) >= self.total:
                payload = bytes(self.buf[:self.total])
                self.reset()
                return "complete", payload, None
            return "consecutive", None, None

        self.error = f"unexpected PCI 0x{pci:X} in a data frame"
        return "bad", None, None


# --------------------------------------------------------------------------
# Transports
# --------------------------------------------------------------------------
class TransportError(RuntimeError):
    pass


class BaseTransport:
    name = "base"

    def open(self):
        pass

    def close(self):
        pass

    def describe(self) -> str:
        return self.name

    def send_frame(self, frame: bytes):
        raise NotImplementedError

    def recv_frame(self, timeout: float):
        """Return one ISO-TP frame (bytes) or None on timeout."""
        raise NotImplementedError


class MockTransport(BaseTransport):
    """Two in-memory queues + a peer thread implementing an ISO-TP receiver.

    The peer is deliberately strict: it validates SN, enforces its own N_Cr,
    can be told to emit WAIT frames, and records the inter-frame gaps it
    actually observes so the caller can prove STmin compliance.
    """

    name = "mock"

    def __init__(self, tx_dl=8, pad=True, pad_byte=0xCC,
                 peer_bs=0, peer_stmin_raw=0x14, peer_n_cr=1.0,
                 wait_frames=0, overflow_after=None, reply_payload=None,
                 drop_after=None, ext_addr=b"", verbose=False):
        self.tx_dl = tx_dl
        self.pad = pad
        self.pad_byte = pad_byte
        self.ext_addr = ext_addr
        self.peer_bs = peer_bs
        self.peer_stmin_raw = peer_stmin_raw
        self.peer_n_cr = peer_n_cr
        self.wait_frames = wait_frames
        self.overflow_after = overflow_after
        self.drop_after = drop_after
        self.reply_payload = reply_payload
        self.verbose = verbose

        self.to_peer = queue.Queue()
        self.to_tester = queue.Queue()
        self.reassembler = IsoTpReassembler(tx_dl, ext_addr)
        self.received = None           # final payload the peer saw
        self.cf_times = []             # perf_counter of every CF arrival
        self.ff_time = None
        self.fc_sent = []
        self.blocks = 0
        self.frame_count = 0
        self.closed = False
        self._thread = None

    # -- tester side ------------------------------------------------------
    def open(self):
        self._thread = threading.Thread(target=self._peer_loop, daemon=True)
        self._thread.start()
        return self

    def close(self):
        self.closed = True
        self.to_peer.put(None)
        if self._thread:
            self._thread.join(timeout=2.0)

    def send_frame(self, frame: bytes):
        if self.drop_after is not None and self.frame_count >= self.drop_after:
            return  # silently swallow (simulates a lost frame / dead peer)
        self.frame_count += 1
        self.to_peer.put(frame)

    def recv_frame(self, timeout: float):
        try:
            return self.to_tester.get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None

    # -- peer side --------------------------------------------------------
    def _send_fc(self, fs, bs, stmin):
        self.fc_sent.append({"fs": fs, "bs": bs, "stmin": stmin,
                             "stmin_s": stmin_to_seconds(stmin)})
        self.to_tester.put(build_flow_control(fs, bs, stmin, self.tx_dl,
                                              self.pad, self.pad_byte, self.ext_addr))

    def _peer_loop(self):
        waiting_for_cf = False
        cf_in_block = 0
        pending_wait = self.wait_frames
        while True:
            try:
                frame = self.to_peer.get(timeout=0.05)
            except queue.Empty:
                if waiting_for_cf and self._peer_deadline is not None:
                    if time.perf_counter() > self._peer_deadline:
                        # N_Cr expiry: abort silently like a real ECU
                        waiting_for_cf = False
                        self.reassembler.reset()
                continue
            if frame is None:
                return  # sentinel: everything queued before it was processed
            status, payload, fc_hint = self.reassembler.feed(frame)
            now = time.perf_counter()

            if status == "bad":
                if self.verbose:
                    print(f"[peer] bad frame: {self.reassembler.error}")
                self.reassembler.reset()
                waiting_for_cf = False
                continue

            if status == "single":
                self.received = payload
                if self.reply_payload is not None:
                    self._reply(payload)
                self._maybe_finish()
                continue

            if status == "first":
                self.ff_time = now
                self.cf_times = []
                cf_in_block = 0
                waiting_for_cf = True
                self._peer_deadline = now + self.peer_n_cr
                if self.overflow_after is not None and self.overflow_after == 0:
                    self._send_fc(FS_OVERFLOW, 0, 0)
                    self.reassembler.reset()
                    waiting_for_cf = False
                    continue
                if pending_wait > 0:
                    pending_wait -= 1
                    # a real ECU answers WAIT first and the real CTS afterwards;
                    # both are queued here so the tester's N_Bs handling is exercised
                    self._send_fc(FS_WAIT, 0, 0)
                    self._send_fc(FS_CONTINUE, self.peer_bs, self.peer_stmin_raw)
                    self.blocks += 1
                else:
                    self._send_fc(FS_CONTINUE, self.peer_bs, self.peer_stmin_raw)
                    self.blocks += 1
                continue

            if status == "consecutive":
                self.cf_times.append(now)
                cf_in_block += 1
                self._peer_deadline = now + self.peer_n_cr
                if self.overflow_after is not None and len(self.reassembler.buf) > self.overflow_after:
                    self._send_fc(FS_OVERFLOW, 0, 0)
                    self.reassembler.reset()
                    waiting_for_cf = False
                    continue
                if self.peer_bs and cf_in_block >= self.peer_bs:
                    cf_in_block = 0
                    self.blocks += 1
                    self._send_fc(FS_CONTINUE, self.peer_bs, self.peer_stmin_raw)
                continue

            if status == "complete":
                self.received = payload
                waiting_for_cf = False
                if self.reply_payload is not None:
                    self._reply(payload)
                self._maybe_finish()

    def _reply(self, request_payload: bytes):
        data = self.reply_payload
        if len(data) <= self.tx_dl - 1 - len(self.ext_addr):
            self.to_tester.put(build_single_frame(data, self.tx_dl, self.pad,
                                                  self.pad_byte, self.ext_addr))
        else:
            # keep replies small: cap at FF capacity here; the sender side of
            # this mock only exists to prove FC parsing, not to fragment.
            self.to_tester.put(build_single_frame(data[:self.tx_dl - 1 - len(self.ext_addr)],
                                                  self.tx_dl, self.pad, self.pad_byte,
                                                  self.ext_addr))

    def _maybe_finish(self):
        # mark the deadline so a late CF does not resurrect a finished transfer
        self._peer_deadline = None

    _peer_deadline = None


class TCPSocketTransport(BaseTransport):
    """Raw ISO-TP frames on a TCP stream, fixed frame size, padded like CAN."""

    name = "tcp"

    def __init__(self, host: str, port: int, tx_dl: int = 8, connect_timeout: float = 4.0,
                 verbose: bool = False):
        self.host, self.port = host, port
        self.tx_dl = tx_dl
        self.connect_timeout = connect_timeout
        self.sock = None
        self.verbose = verbose
        self.rx_bytes = 0

    def open(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return self

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def describe(self) -> str:
        return f"tcp {self.host}:{self.port} frame_len={self.tx_dl}"

    def send_frame(self, frame: bytes):
        if not self.sock:
            raise TransportError("socket not open")
        self.sock.sendall(frame)

    def recv_frame(self, timeout: float):
        if not self.sock:
            raise TransportError("socket not open")
        self.sock.settimeout(max(0.01, timeout))
        buf = b""
        while len(buf) < self.tx_dl:
            try:
                chunk = self.sock.recv(self.tx_dl - len(buf))
            except socket.timeout:
                return None
            except OSError as e:
                raise TransportError(f"recv failed: {e}")
            if not chunk:
                raise TransportError("peer closed the connection")
            buf += chunk
            self.rx_bytes += len(chunk)
        return buf


class DoIPTransport(BaseTransport):
    """ISO-TP frames wrapped in DoIP diagnosticMessage payloads.

    Each ISO-TP frame becomes one 0x8001 payload: SA(2) TA(2) + frame.  On
    receive, 0x8001 bodies are unwrapped and trimmed back to tx_dl; 0x8002 /
    0x8003 acknowledgements are handed to `ack_sink` so the caller can see
    them without confusing them with FC frames.
    """

    name = "doip"

    PT_ROUTING_ACT_REQ = 0x0005
    PT_ROUTING_ACT_RSP = 0x0006
    PT_DIAG_MSG = 0x8001
    PT_DIAG_ACK = 0x8002
    PT_DIAG_NACK = 0x8003

    def __init__(self, host: str, port: int, sa: int = 0x0E00, ta: int = 0x1000,
                 tx_dl: int = 8, connect_timeout: float = 4.0,
                 do_activation: bool = True, verbose: bool = False):
        self.host, self.port = host, port
        self.sa, self.ta = sa, ta
        self.tx_dl = tx_dl
        self.connect_timeout = connect_timeout
        self.do_activation = do_activation
        self.sock = None
        self.buf = b""
        self.verbose = verbose
        self.ack_sink = []
        self.activation = None

    # -- framing ----------------------------------------------------------
    @staticmethod
    def _pkt(ptype: int, payload: bytes, ver: int = 0x02) -> bytes:
        return (bytes([ver, 0xFF - ver]) + struct.pack(">H", ptype)
                + struct.pack(">I", len(payload)) + payload)

    def open(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.do_activation:
            self._activate()
        return self

    def _activate(self):
        payload = struct.pack(">H", self.sa) + b"\x00" + b"\x00\x00\x00\x00"
        self.sock.sendall(self._pkt(self.PT_ROUTING_ACT_REQ, payload))
        fr = self._recv_doip(2.0)
        self.activation = None
        if fr and fr[0] == self.PT_ROUTING_ACT_RSP and len(fr[1]) >= 5:
            tester, entity, code = struct.unpack(">HHB", fr[1][:5])
            self.activation = {"tester_sa": tester, "entity_la": entity, "code": code}
            if self.verbose:
                print(f"[doip] routing activation code=0x{code:02X}")
            if code not in (0x10, 0x11):
                raise TransportError(f"routing activation denied: code 0x{code:02X}")
        elif fr is None:
            raise TransportError("no routing activation response")

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def describe(self) -> str:
        act = ""
        if self.activation:
            act = f" ra_code=0x{self.activation['code']:02X}"
        return f"doip {self.host}:{self.port} sa=0x{self.sa:04X} ta=0x{self.ta:04X}{act}"

    def send_frame(self, frame: bytes):
        self.sock.sendall(self._pkt(self.PT_DIAG_MSG,
                                    struct.pack(">HH", self.sa, self.ta) + frame))

    def _recv_doip(self, timeout: float):
        """One DoIP frame -> (ptype, payload) or None."""
        end = time.perf_counter() + timeout
        while True:
            if len(self.buf) >= 8:
                ver, inv, ptype, plen = struct.unpack(">BBHI", self.buf[:8])
                if len(self.buf) >= 8 + plen:
                    payload = self.buf[8:8 + plen]
                    self.buf = self.buf[8 + plen:]
                    return ptype, payload
            rem = end - time.perf_counter()
            if rem <= 0:
                return None
            self.sock.settimeout(max(0.01, rem))
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                return None
            if not chunk:
                raise TransportError("peer closed the DoIP connection")
            self.buf += chunk

    def recv_frame(self, timeout: float):
        end = time.perf_counter() + timeout
        while True:
            rem = end - time.perf_counter()
            if rem <= 0:
                return None
            fr = self._recv_doip(rem)
            if fr is None:
                return None
            ptype, payload = fr
            if ptype == self.PT_DIAG_MSG and len(payload) >= 4:
                body = payload[4:]
                # trim padding back to the declared frame size
                return body[:self.tx_dl]
            if ptype in (self.PT_DIAG_ACK, self.PT_DIAG_NACK):
                self.ack_sink.append({"ptype": f"0x{ptype:04X}", "hex": hx(payload)})
                if self.verbose:
                    print(f"[doip] ack/nack 0x{ptype:04X} {hx(payload)}")
                continue
            if self.verbose:
                print(f"[doip] ignoring ptype 0x{ptype:04X}")
            continue


# --------------------------------------------------------------------------
# The sender
# --------------------------------------------------------------------------
class SendResult:
    def __init__(self):
        self.ok = False
        self.reason = ""
        self.frames_sent = 0
        self.blocks = 0
        self.waits = 0
        self.gaps_ms = []
        self.fc_frames = []
        self.elapsed_ms = 0.0
        self.stmin_violations = []
        self.reply = None

    def as_dict(self):
        return {
            "ok": self.ok,
            "reason": self.reason,
            "frames_sent": self.frames_sent,
            "blocks": self.blocks,
            "wait_frames": self.waits,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "gap_ms": self.gaps_ms,
            "fc": self.fc_frames,
            "stmin_violations": self.stmin_violations,
            "reply_hex": hx(self.reply) if self.reply else None,
        }


class IsoTpSender:
    """Send one payload over ISO-TP, honouring the peer's FC frames."""

    def __init__(self, transport: BaseTransport, tx_dl: int = 8, pad: bool = True,
                 pad_byte: int = 0xCC, ext_addr: bytes = b"",
                 n_bs: float = DEFAULT_N_BS, n_wftmax: int = DEFAULT_N_WFTMAX,
                 bs_override: int | None = None,
                 stmin_override: float | None = None,
                 stmin_cap: float | None = None,
                 log: FrameLog | None = None, verbose: bool = True,
                 strict_stmin: bool = True):
        self.t = transport
        self.tx_dl = tx_dl
        self.pad, self.pad_byte = pad, pad_byte
        self.ext_addr = ext_addr
        self.n_bs = n_bs
        self.n_wftmax = n_wftmax
        self.bs_override = bs_override
        self.stmin_override = stmin_override
        self.stmin_cap = stmin_cap
        self.log = log if log is not None else FrameLog()
        self.verbose = verbose
        self.strict_stmin = strict_stmin

    # -- helpers ----------------------------------------------------------
    def _say(self, msg: str):
        if self.verbose:
            print(msg, flush=True)

    def _wait_fc(self, label: str, result: SendResult) -> dict:
        """Block until a valid FC arrives; apply N_Bs / N_WFTmax rules."""
        deadline = time.perf_counter() + self.n_bs
        waits = 0
        while True:
            rem = deadline - time.perf_counter()
            if rem <= 0:
                raise TransportError(f"N_Bs timeout after {self.n_bs:.2f}s waiting for FC ({label})")
            frame = self.t.recv_frame(rem)
            if frame is None:
                continue
            self.log.add("RX", frame, "FC?", note=label)
            try:
                fc = parse_flow_control(frame, len(self.ext_addr))
            except ValueError as e:
                raise TransportError(f"expected Flow Control, got {hx(frame)}: {e}")
            result.fc_frames.append(fc)
            self._say(f"  [FC] fs=0x{fc['fs']:X} {fc['fs_name']} bs={fc['bs']} "
                      f"stmin={fc['stmin_text']}")
            fs = fc["fs"]
            if fs == FS_CONTINUE:
                return fc
            if fs == FS_WAIT:
                waits += 1
                result.waits += 1
                if waits > self.n_wftmax:
                    raise TransportError(
                        f"peer sent {waits} WAIT frames, exceeds N_WFTmax={self.n_wftmax}")
                deadline = time.perf_counter() + self.n_bs
                continue
            if fs == FS_OVERFLOW:
                raise TransportError("peer reports overflow (FS=2 OVFLW): payload too large for its buffer")
            raise TransportError(f"reserved FS=0x{fs:X} in FC frame {hx(frame)}")

    def _apply_fc(self, fc: dict) -> tuple[int, float]:
        bs = self.bs_override if self.bs_override is not None else fc["bs"]
        stmin = self.stmin_override if self.stmin_override is not None else fc["stmin_s"]
        if self.stmin_cap is not None and stmin > self.stmin_cap:
            stmin = self.stmin_cap
        return bs, stmin

    # -- main -------------------------------------------------------------
    def send(self, payload: bytes) -> SendResult:
        res = SendResult()
        self.log.open_window()
        t_start = time.perf_counter()
        try:
            self._send_inner(payload, res)
            res.ok = True
            res.reason = "completed"
        except TransportError as e:
            res.ok = False
            res.reason = str(e)
        except Exception as e:  # noqa: BLE001 - surface anything as a failed send
            res.ok = False
            res.reason = f"{type(e).__name__}: {e}"
        res.elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        res.gaps_ms = [g for _, g in self.log.gaps_between_cf()]
        return res

    def _send_inner(self, payload: bytes, res: SendResult):
        n = len(payload)
        ea = len(self.ext_addr)
        sf_room = self.tx_dl - 1 - ea

        if n == 0:
            raise TransportError("refusing to send an empty payload")

        # ---------------- Single Frame ----------------
        if n <= sf_room:
            frame = build_single_frame(payload, self.tx_dl, self.pad, self.pad_byte, self.ext_addr)
            self.t.send_frame(frame)
            self.log.add("TX", frame, "SF", note=f"{n} B payload")
            res.frames_sent = 1
            self._say(f"[TX] SF {n} B in one frame")
            return

        # ---------------- First Frame ----------------
        escape = n > 0xFFF
        ff = build_first_frame(payload, self.tx_dl, self.pad, self.pad_byte,
                               self.ext_addr, force_escape=escape)
        carried = first_frame_carries(self.tx_dl, ea, escape)
        offset = carried
        self.t.send_frame(ff)
        self.log.add("TX", ff, "FF",
                     note=(f"len={n} escape={'yes' if escape else 'no'} "
                           f"carried={min(carried, n)}"))
        res.frames_sent = 1
        self._say(f"[TX] FF len={n}{' (escape: 32-bit len at FF+2)' if escape else ''} "
                  f"carries {min(carried, n)} B")

        seq = 1
        in_block = 0
        block_no = 1
        fc = self._wait_fc(f"after FF (block {block_no})", res)
        bs, stmin = self._apply_fc(fc)
        res.blocks = 1
        gap_deadline = None

        while offset < n:
            # respect the block boundary: ask for a fresh FC after BS frames
            if bs and in_block >= bs:
                fc = self._wait_fc(f"block {block_no} complete (BS={bs})", res)
                new_bs, new_stmin = self._apply_fc(fc)
                if new_stmin != stmin:
                    self._say(f"  [FC] STmin changed {stmin*1000:.2f} ms -> {new_stmin*1000:.2f} ms")
                bs, stmin = new_bs, new_stmin
                in_block = 0
                block_no += 1
                res.blocks = block_no

            if gap_deadline is not None:
                over = precise_sleep_until(gap_deadline)
                if over > 0.002:
                    res.stmin_violations.append(round(over * 1000, 3))

            chunk = payload[offset:offset + (self.tx_dl - 1 - ea)]
            cf = build_consecutive_frame(seq, chunk, self.tx_dl, self.pad,
                                         self.pad_byte, self.ext_addr)
            t_frame = time.perf_counter()
            self.t.send_frame(cf)
            self.log.add("TX", cf, "CF",
                         note=f"SN={seq} off={offset}/{n} "
                              f"stmin={stmin*1000:.2f}ms", t=t_frame)
            offset += len(chunk)
            seq = (seq + 1) & 0x0F
            in_block += 1
            res.frames_sent += 1
            gap_deadline = t_frame + stmin if stmin > 0 else time.perf_counter()

            if self.verbose and (res.frames_sent % 32 == 0 or offset >= n):
                pct = 100.0 * offset / n
                self._say(f"  ...{offset}/{n} B ({pct:.0f}%), block {block_no}")

        # A real receiver may answer the whole transfer; grab it if it is
        # already sitting in the socket so callers can see the verdict.
        reply = self.t.recv_frame(min(0.35, max(0.05, self.n_bs)))
        if reply is not None:
            self.log.add("RX", reply, "REPLY", note="post-transfer frame")
            res.reply = reply


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def _mock_case(name, payload_len, bs, stmin_raw, wait_frames=0, overflow=False,
               expect_ok=True, tx_dl=8, drop_after=None):
    tr = MockTransport(tx_dl=tx_dl, peer_bs=bs, peer_stmin_raw=stmin_raw,
                       wait_frames=wait_frames, drop_after=drop_after,
                       overflow_after=(1 if overflow else None),
                       verbose=False).open()
    payload = bytes((i * 7 + 3) & 0xFF for i in range(payload_len))
    log = FrameLog()
    sender = IsoTpSender(tr, tx_dl=tx_dl, n_bs=0.6, n_wftmax=4,
                         log=log, verbose=False)
    t0 = time.perf_counter()
    res = sender.send(payload)
    wall = time.perf_counter() - t0
    tr.close()

    checks = []
    checks.append(("send ok" if expect_ok else "send failed",
                   res.ok == expect_ok, f"ok={res.ok} reason={res.reason}"))
    if expect_ok:
        checks.append(("peer got all bytes",
                       tr.received == payload,
                       f"got={0 if tr.received is None else len(tr.received)}B "
                       f"want={payload_len}B"))
    # STmin compliance is judged on the SENDER's own frame timestamps: those are
    # the moments the bytes were handed to the transport, i.e. the wire spacing.
    # (Peer-side arrival stamps are only informational -- an in-process peer is
    # subject to GIL scheduling and can see reordering-sized jitter that a real
    # CAN controller never would.)
    if expect_ok and len(res.gaps_ms) > 1 and stmin_to_seconds(stmin_raw) > 0:
        want_ms = stmin_to_seconds(stmin_raw) * 1000.0
        gmin = min(res.gaps_ms)
        checks.append((f"min sender CF gap >= STmin {want_ms:.3f} ms",
                       gmin >= want_ms - 0.15,
                       f"min gap {gmin:.3f} ms over {len(res.gaps_ms)} gaps"))
        if len(tr.cf_times) > 1:
            peer_gaps = [(tr.cf_times[i] - tr.cf_times[i - 1]) * 1000.0
                         for i in range(1, len(tr.cf_times))]
            checks.append(("peer-side gap median ~= STmin (informational)",
                           True,
                           f"median {sorted(peer_gaps)[len(peer_gaps)//2]:.3f} ms"))
    if bs and expect_ok:
        cf_total = -(-(payload_len - (tx_dl - 2)) // (tx_dl - 1))
        expected_fc = 1 + (cf_total // bs)
        checks.append((f"peer emitted ~{expected_fc} CTS frames for {cf_total} CFs @BS={bs}",
                       abs(len(tr.fc_sent) - expected_fc) <= 2,
                       f"peer emitted {len(tr.fc_sent)} FC total, {tr.blocks} blocks"))
    if wait_frames:
        checks.append((f"observed >= 1 WAIT",
                       any(f["fs"] == FS_WAIT for f in tr.fc_sent),
                       f"fs list={[f['fs'] for f in tr.fc_sent]}"))

    return {"name": name, "checks": checks, "result": res, "log": log,
            "peer": {"received_len": 0 if tr.received is None else len(tr.received),
                     "blocks": tr.blocks, "fc": tr.fc_sent}, "wall_s": wall}


def _report_case(case, verbose_frames="auto"):
    print("")
    print("=" * 78)
    print(f"[CASE] {case['name']}")
    print("-" * 78)
    res = case["result"]
    print(f"  ok={res.ok}  reason={res.reason}  frames={res.frames_sent}  "
          f"blocks={res.blocks}  waits={res.waits}")
    print(f"  elapsed={res.elapsed_ms:.1f} ms   peer_blocks={case['peer']['blocks']}  "
          f"peer_fc_frames={len(case['peer']['fc'])}")
    gaps = res.gaps_ms
    if gaps:
        print(f"  CF gaps (ms), first 12: {[round(g,3) for g in gaps[:12]]}")
        print(f"  CF gap min={min(gaps):.3f} max={max(gaps):.3f} n={len(gaps)}")
    if res.stmin_violations:
        print(f"  !! STmin overshoot samples: {res.stmin_violations[:8]}")
    show = (verbose_frames == "always"
            or (verbose_frames == "auto" and 0 < len(case["log"].rows) <= 40))
    if show:
        print("")
        print(case["log"].render())
    ok_all = True
    for label, passed, detail in case["checks"]:
        mark = "PASS" if passed else "FAIL"
        if not passed:
            ok_all = False
        print(f"  [{mark}] {label}   ({detail})")
    return ok_all


def self_test(stmin_ms: float = 20.0, bs: int = 8, total: int = 1116,
              verbose_frames="auto", dump_dir: str | None = None) -> int:
    stmin_raw = int(round(stmin_ms))
    if not (0 <= stmin_raw <= 0x7F):
        stmin_raw = 0x14

    print("=" * 78)
    print("ISO-TP sender self-test (no target host contacted)")
    print(f"  python={sys.version.split()[0]}  platform={os.name}")
    print(f"  main case: {total} B, BS={bs}, STmin={stmin_raw} (0x{stmin_raw:02X})")
    print("=" * 78)

    cases = []
    # 1. the case that matters: 1116 bytes, BS=8, STmin=20 ms
    cases.append(_mock_case(f"1116 B, BS={bs}, STmin={stmin_raw} ms ({stmin_ms} ms)",
                            total, bs, stmin_raw))
    # 2. BS=0 means "send everything in one block"
    cases.append(_mock_case("1116 B, BS=0 (no block boundary), STmin=5 ms",
                            total, 0, 0x05))
    # 3. sub-millisecond STmin must not be read as milliseconds
    cases.append(_mock_case("300 B, BS=4, STmin=0xF1 (100 us microsecond encoding)",
                            300, 4, 0xF1))
    # 4. WAIT frames
    cases.append(_mock_case("200 B, BS=4, STmin=1 ms, one WAIT frame",
                            200, 4, 0x01, wait_frames=1))
    # 5. overflow must be surfaced, not retried
    cases.append(_mock_case("200 B, peer answers OVFLW", 200, 4, 0x01,
                            overflow=True, expect_ok=False))
    # 6. single frame
    cases.append(_mock_case("7 B single frame", 7, 0, 0x00))
    # 7. escape sequence (32-bit length)
    cases.append(_mock_case("5000 B, BS=0, escape length path", 5000, 0, 0x00))
    # 8. 4096 exactly (first length that needs escape)
    cases.append(_mock_case("4096 B, BS=16, escape length path", 4096, 16, 0x00))

    ok = True
    for c in cases:
        ok = _report_case(c, verbose_frames) and ok

    # ---- structural checks on the 1116 byte framing ----------------------
    print("")
    print("=" * 78)
    print("[CASE] frame layout of 1116 B at tx_dl=8 (offline computation)")
    print("-" * 78)
    payload = bytes(1116)
    ff = build_first_frame(payload, 8, pad=True)
    carried = 6
    cf_total = -(-(1116 - carried) // 7)
    print(f"  FF            : {hx(ff)}  (6 payload bytes)")
    print(f"  CF count      : {cf_total}   (last CF carries {1116 - carried - (cf_total-1)*7} B)")
    print(f"  total frames  : {1 + cf_total}")
    print(f"  blocks @BS=8  : {-(-cf_total // 8)}")
    sn_ok = True
    seqs = []
    seq = 1
    for i in range(cf_total):
        seqs.append(seq)
        seq = (seq + 1) & 0x0F
    print(f"  SN sequence   : {seqs}")
    # prove the SN wraps and restarts at 1 after 15
    if seqs[15] != 0 or seqs[16] != 1:
        sn_ok = False
    print(f"  [{'PASS' if sn_ok else 'FAIL'}] SN wraps 15 -> 0 -> 1 (index 15 is 0, 16 is 1)")

    # escape length encoding check: PCI=0x1, FF_DL=0x000, then the 32-bit length
    ff_esc = build_first_frame(payload, 8, pad=True, force_escape=True)
    esc_ok = (ff_esc[0] == 0x10 and ff_esc[1] == 0x00
              and struct.unpack(">I", ff_esc[2:6])[0] == 1116)
    print(f"  [{'PASS' if esc_ok else 'FAIL'}] escape FF = {hx(ff_esc)} "
          f"(PCI=1, FF_DL=0x000, u32 len at bytes 2..5 = 1116, 2 data bytes)")
    # and the escape form must survive a full reassembly round trip
    esc_payload = bytes((i * 11 + 5) & 0xFF for i in range(5000))
    esc_sender_frame = build_first_frame(esc_payload, 8, pad=True)
    r = IsoTpReassembler(8)
    st, _, _ = r.feed(esc_sender_frame)
    esc_rt = (st == "first" and r.total == 5000)
    print(f"  [{'PASS' if esc_rt else 'FAIL'}] reassembler reads escape length "
          f"{r.total} from FF (status={st})")
    seq_ok = cf_total == 159
    print(f"  [{'PASS' if seq_ok else 'FAIL'}] CF count for 1116 B is 159 "
          f"(1110 B / 7 = 158.57 -> 159)")
    ok = ok and sn_ok and esc_ok and seq_ok

    # ---- STmin decoder table --------------------------------------------
    print("")
    print("=" * 78)
    print("[CASE] STmin decoder")
    print("-" * 78)
    table = [
        (0x00, 0.0, "0 ms"), (0x01, 0.001, "1 ms"), (0x14, 0.020, "20 ms"),
        (0x7F, 0.127, "127 ms"), (0xF1, 0.0001, "100 us"), (0xF5, 0.0005, "500 us"),
        (0xF9, 0.0009, "900 us"), (0x80, 0.127, "reserved->127 ms"),
        (0xFA, 0.127, "reserved->127 ms"), (0xFF, 0.127, "reserved->127 ms"),
    ]
    for raw, want, text in table:
        got = stmin_to_seconds(raw)
        passed = abs(got - want) < 1e-9
        ok = ok and passed
        print(f"  [{'PASS' if passed else 'FAIL'}] 0x{raw:02X} -> {got*1000:.3f} ms  (expect {text})")

    # ---- FC parser ------------------------------------------------------
    print("")
    print("=" * 78)
    print("[CASE] FC parser on real frame bytes")
    print("-" * 78)
    fc_cases = [
        ("30 08 14 CC CC CC CC CC", {"fs": 0, "bs": 8, "stmin_raw": 0x14}),
        ("31 00 00 CC CC CC CC CC", {"fs": 1, "bs": 0, "stmin_raw": 0x00}),
        ("32 00 00 CC CC CC CC CC", {"fs": 2, "bs": 0, "stmin_raw": 0x00}),
        ("30 00 F1 AA AA AA AA AA", {"fs": 0, "bs": 0, "stmin_raw": 0xF1}),
    ]
    for text, want in fc_cases:
        fc = parse_flow_control(bytes.fromhex(text.replace(" ", "")))
        passed = all(fc[k] == v for k, v in want.items())
        ok = ok and passed
        print(f"  [{'PASS' if passed else 'FAIL'}] {text} -> fs=0x{fc['fs']:X} "
              f"bs={fc['bs']} stmin={fc['stmin_text']}")

    print("")
    print("=" * 78)
    print(f"SELF-TEST RESULT: {'PASS' if ok else 'FAIL'}")
    print("=" * 78)

    if dump_dir:
        os.makedirs(dump_dir, exist_ok=True)
        for i, c in enumerate(cases, 1):
            safe = "".join(ch if ch.isalnum() else "_" for ch in c["name"])[:48]
            p = os.path.join(dump_dir, f"selftest_{i:02d}_{safe}.jsonl")
            c["log"].dump_jsonl(p)
            print(f"  wrote {p}")
        summary = [{"name": c["name"], "res": c["result"].as_dict(),
                    "peer": {"len": c["peer"]["received_len"],
                             "blocks": c["peer"]["blocks"]},
                    "checks": [{"label": l, "pass": p, "detail": d}
                               for l, p, d in c["checks"]]} for c in cases]
        sp = os.path.join(dump_dir, "selftest_summary.json")
        with open(sp, "w", encoding="utf-8") as f:
            json.dump({"ok": ok, "stmin_ms": stmin_ms, "bs": bs, "total": total,
                       "cases": summary}, f, indent=2)
        print(f"  wrote {sp}")

    return 0 if ok else 1


def list_tests():
    print("self-test cases run by --self-test:")
    for line in [
        " 1. 1116 B, peer BS=8, STmin=20 ms          (the challenge payload)",
        " 2. 1116 B, peer BS=0 (single block), 5 ms   (BS=0 => never wait for FC)",
        " 3. 300 B, BS=4, STmin=0xF1                  (100 us encoding, sub-ms)",
        " 4. 200 B, BS=4, 1 ms, one FS=1 WAIT frame   (N_WFTmax path)",
        " 5. 200 B, peer answers FS=2 OVFLW           (must abort, not retry)",
        " 6. 7 B single frame                         (SF path)",
        " 7. 5000 B, escape 32-bit length             (FF_DL=0 + 4-byte len in CF1)",
        " 8. 4096 B, BS=16, escape length             (first escape-sized payload)",
        " + frame-layout proof, STmin decoder table, FC parser cases",
    ]:
        print(line)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
MUTATING_SIDS = {0x2E, 0x2F, 0x11, 0x14, 0x28, 0x85, 0x34, 0x35, 0x36, 0x37, 0x38}


def guard_read_only(payload: bytes):
    """Refuse UDS services that change ECU state unless --allow-mutating."""
    if not payload:
        return
    sid = payload[0]
    if sid in MUTATING_SIDS:
        raise SystemExit(
            f"[guard] refusing to send SID 0x{sid:02X}: it can change ECU state. "
            f"Pass --allow-mutating only if the challenge explicitly authorises it.")


def build_parser():
    ap = argparse.ArgumentParser(
        description="ISO-TP (ISO 15765-2) sender: SF/FF/CF/FC with BS+STmin obedience.",
        epilog="Run --self-test first: it proves the segmentation and timing offline.")
    ap.add_argument("--self-test", action="store_true", help="run the offline mock-peer test suite")
    ap.add_argument("--list-tests", action="store_true", help="print the self-test case list")
    ap.add_argument("--selftest-stmin", type=float, default=20.0,
                    help="STmin in ms for the main self-test case (default 20)")
    ap.add_argument("--selftest-bs", type=int, default=8, help="BlockSize for the main self-test case")
    ap.add_argument("--selftest-total", type=int, default=1116, help="payload size for the main case")
    ap.add_argument("--selftest-out", default="", help="directory for self-test frame logs")
    ap.add_argument("--frames", default="auto", choices=["auto", "always", "never"],
                    help="print frame tables in the self-test")

    ap.add_argument("--transport", default="dry", choices=["dry", "mock", "tcp", "doip"])
    ap.add_argument("--host", default="10.224.139.7")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--sa", default="0E00", help="DoIP tester logical address (hex)")
    ap.add_argument("--ta", default="1000", help="DoIP target logical address (hex)")
    ap.add_argument("--no-activation", action="store_true",
                    help="skip DoIP routing activation")
    ap.add_argument("--frame-len", type=int, default=8, help="ISO-TP frame data length (8 classic CAN)")
    ap.add_argument("--no-pad", action="store_true", help="do not pad frames to --frame-len")
    ap.add_argument("--pad-byte", default="CC", help="padding byte (hex, default CC)")

    ap.add_argument("--payload-hex", default="", help="payload given as hex string")
    ap.add_argument("--payload-file", default="", help="payload read from a binary file")
    ap.add_argument("--payload-len", type=int, default=0,
                    help="generate a synthetic payload of N bytes (0x00.. sequence)")
    ap.add_argument("--bs-override", type=int, default=None,
                    help="ignore the peer's BlockSize and use this value")
    ap.add_argument("--stmin-override", type=float, default=None,
                    help="ignore the peer's STmin and use this many ms")
    ap.add_argument("--stmin-cap", type=float, default=None,
                    help="clamp the peer's STmin to at most this many ms")
    ap.add_argument("--n-bs", type=float, default=DEFAULT_N_BS, help="N_Bs timeout in seconds")
    ap.add_argument("--n-wftmax", type=int, default=DEFAULT_N_WFTMAX,
                    help="max WAIT frames tolerated (default 0 per ISO default)")
    ap.add_argument("--allow-mutating", action="store_true",
                    help="allow UDS SIDs that change ECU state (off by default)")
    ap.add_argument("--dry-run", action="store_true",
                    help="segment and print frames without any transport")
    ap.add_argument("--log-jsonl", default="", help="write the frame log to this JSONL file")
    ap.add_argument("--log-csv", default="", help="write the frame log to this CSV file")
    ap.add_argument("--quiet", action="store_true", help="only print the summary")
    return ap


def dry_run(payload: bytes, args) -> int:
    """Segment the payload and print the exact frames, no socket involved.

    A synthetic Flow Control generator answers each FC wait of the sender, so
    the printed sequence is exactly what would go on the wire for the given
    BS/STmin -- including the CF gaps implied by STmin.
    """
    pad = not args.no_pad
    pad_byte = int(args.pad_byte, 16)
    tx_dl = args.frame_len
    ea = 0

    log = FrameLog()
    log.open_window()

    # how many FC frames the sender will ask for
    sf_room = tx_dl - 1 - ea
    if len(payload) > sf_room:
        carried = tx_dl - 2 - ea
        cf_total = -(-(len(payload) - carried) // (tx_dl - 1 - ea))
        bs = args.bs_override if args.bs_override is not None else 0
        expected_fc = 1 + ((-(-cf_total // bs)) if bs else 0)
    else:
        expected_fc = 0

    fc_bs = args.bs_override if args.bs_override is not None else 0
    fc_stmin_raw = 0x00
    if args.stmin_override:
        ms = max(0, min(0x7F, int(round(args.stmin_override))))
        fc_stmin_raw = ms

    class _DryTransport(BaseTransport):
        name = "dry"

        def __init__(self):
            self.fc_given = 0

        def describe(self):
            return "dry run (no socket)"

        def send_frame(self, frame):
            # logging is done by IsoTpSender so that every frame appears once,
            # stamped at the moment it was handed over
            pass

        def recv_frame(self, timeout):
            if self.fc_given >= expected_fc:
                return None
            self.fc_given += 1
            fc = build_flow_control(FS_CONTINUE, fc_bs, fc_stmin_raw, tx_dl, pad, pad_byte)
            log.add("RX", fc, "FC",
                    note=f"synthetic FC (dry): BS={fc_bs} STmin=0x{fc_stmin_raw:02X}")
            return fc

    sender = IsoTpSender(_DryTransport(), tx_dl=tx_dl, pad=pad, pad_byte=pad_byte,
                         n_bs=args.n_bs, n_wftmax=args.n_wftmax,
                         log=log, verbose=not args.quiet)
    res = sender.send(payload)
    print("")
    print(log.render())
    print("")
    print(f"result: ok={res.ok} frames={res.frames_sent} blocks={res.blocks} "
          f"reason={res.reason}")
    if res.gaps_ms:
        print(f"CF gaps min={min(res.gaps_ms):.3f} ms max={max(res.gaps_ms):.3f} ms")
    return 0 if res.ok else 1


def load_payload(args) -> bytes:
    if args.payload_file:
        with open(args.payload_file, "rb") as f:
            return f.read()
    if args.payload_hex:
        return bytes.fromhex(args.payload_hex.replace(" ", "").replace(":", ""))
    if args.payload_len:
        return bytes((i * 7 + 3) & 0xFF for i in range(args.payload_len))
    return b""


def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if args.list_tests:
        list_tests()
        return 0

    if args.self_test:
        out = args.selftest_out or ""
        return self_test(args.selftest_stmin, args.selftest_bs, args.selftest_total,
                         args.frames, out or None)

    payload = load_payload(args)
    if not payload:
        ap.error("no payload: use --payload-hex, --payload-file or --payload-len")
    if not args.allow_mutating:
        guard_read_only(payload)

    pad = not args.no_pad
    pad_byte = int(args.pad_byte, 16)

    if args.dry_run or args.transport == "dry":
        return dry_run(payload, args)

    if args.transport == "tcp":
        tr = TCPSocketTransport(args.host, args.port, args.frame_len,
                                verbose=not args.quiet)
    elif args.transport == "doip":
        tr = DoIPTransport(args.host, args.port, int(args.sa, 16), int(args.ta, 16),
                           args.frame_len, do_activation=not args.no_activation,
                           verbose=not args.quiet)
    else:
        ap.error(f"unsupported transport {args.transport}")

    print(f"[*] transport: {tr.describe()}")
    log = FrameLog()
    sender = IsoTpSender(tr, tx_dl=args.frame_len, pad=pad, pad_byte=pad_byte,
                         n_bs=args.n_bs, n_wftmax=args.n_wftmax,
                         bs_override=args.bs_override,
                         stmin_override=args.stmin_override,
                         stmin_cap=args.stmin_cap,
                         log=log, verbose=not args.quiet)
    try:
        tr.open()
    except Exception as e:  # noqa: BLE001
        print(f"[!] could not open transport: {type(e).__name__}: {e}")
        return 2
    try:
        res = sender.send(payload)
    finally:
        tr.close()

    print("")
    print(log.render(limit=None if not args.quiet else 24))
    print("")
    print(f"payload={len(payload)} B  frames={res.frames_sent}  blocks={res.blocks}  "
          f"waits={res.waits}  elapsed={res.elapsed_ms:.1f} ms")
    print(f"result: ok={res.ok} reason={res.reason}")
    if res.gaps_ms:
        print(f"CF gaps min={min(res.gaps_ms):.3f} ms max={max(res.gaps_ms):.3f} ms")
    if res.reply:
        print(f"reply: {hx(res.reply)}")
    if getattr(tr, "ack_sink", None):
        print(f"doip acks: {tr.ack_sink}")

    if args.log_jsonl:
        log.dump_jsonl(args.log_jsonl)
        print(f"[*] wrote {args.log_jsonl}")
    if args.log_csv:
        log.dump_csv(args.log_csv)
        print(f"[*] wrote {args.log_csv}")

    return 0 if res.ok else 1


if __name__ == "__main__":
    sys.exit(main())

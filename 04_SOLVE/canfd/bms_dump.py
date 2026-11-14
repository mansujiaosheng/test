#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bms_dump.py -- pull the full 16 KiB RV32IM BMS image with 0x23.

Task 06: on the powertrain CAN FD bus, issue 32 x 512-byte
ReadMemoryByAddress (UDS service 0x23) reads and reassemble the whole 16384-byte
firmware, then sanity-check the result.

Wire facts this is built around
-------------------------------
* The gateway answers 22 F1A0 with `07E0 07E8 07E1 07E9`, i.e. two logical
  ECUs: ECU1 = 0x7E0 request / 0x7E8 response, ECU2 = 0x7E1 / 0x7E9.  The BMS
  is expected on the *second* pair, so the default IDs are 0x7E1/0x7E9 and
  `--pair ecu1` switches.
* 0x23 request layout:  `23 <ALFID> <memoryAddress> <memorySize>`
  ALFID packs two nibbles: high nibble = size of the memorySize field, low
  nibble = size of the memoryAddress field.  The challenge statement names
  0x14 / 0x24 / 0x44, which are size-of-size 1 / 2 / 4 with a 4-byte address;
  0x14 cannot express 512 in one byte, so it is tried and expected to be
  rejected (NRC 0x13) -- that rejection is itself evidence about the ECU.
* 0x23 response:        `63 <ALFID> <memoryAddress> <memorySize> <data...>`
  The echoed ALFID is parsed rather than assumed.

Read-only discipline
--------------------
`ReadOnlyGuard` refuses any request whose SID is not in the allow-list
(0x23 ReadMemoryByAddress, 0x3E TesterPresent, 0x10 DiagnosticSessionControl
for the session the ECU requires).  Mutating services (0x2E / 0x31 / 0x34 /
0x36 / 0x37 / 0x27) are refused before a byte reaches the bus.  0x31 is refused
even though it *can* be read-only, because RoutineControl is how ECUs erase
flash.

Self-test (no target)
---------------------
`--self-test` builds a synthetic 16384-byte RV32IM-looking image, runs a stub
ECU behind an in-process ISO-TP loopback, and asserts:
  * ALFID negotiation (0x14 rejected with NRC 0x13 -> falls back to 0x24)
  * 32 blocks of 512 B, addresses incrementing, full coverage
  * double read of every block compares equal
  * a transient corruption is detected and repaired by the retry
  * the reassembled image is byte-identical and has the right sha256
  * boundary re-reads agree with the per-block reads

Real run (after the bridge opens)
---------------------------------
    python bms_dump.py --tap 10.226.193.2 --port 13401 --framing auto \
        --pair ecu2 --base 0x00000000 --out ../../03_EVIDENCE/canfd/bms_fw.bin \
        --evidence-dir ../../03_EVIDENCE/canfd
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Optional, Sequence

import isotp

# --------------------------------------------------------------------------- #
# UDS constants
# --------------------------------------------------------------------------- #

SID_READ_MEMORY = 0x23
SID_READ_MEMORY_RESP = 0x63
SID_SESSION = 0x10
SID_TESTER_PRESENT = 0x3E
SID_NEGATIVE = 0x7F

NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x14: "responseTooLong",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x72: "generalProgrammingFailure",
    0x78: "requestCorrectlyReceived-ResponsePending",
}

#: ALFID = (size_of_size << 4) | size_of_address
ALFID_CANDIDATES = (0x24, 0x14, 0x44)

#: ECU pairs from the gateway's 22 F1A0 answer
ID_PAIRS = {"ecu1": (0x7E0, 0x7E8), "ecu2": (0x7E1, 0x7E9)}

#: services this tool is allowed to put on the bus
ALLOWED_SIDS = {SID_READ_MEMORY, SID_TESTER_PRESENT, SID_SESSION}


class UdsError(RuntimeError):
    def __init__(self, sid: int, nrc: int, raw: bytes = b""):
        self.sid = sid
        self.nrc = nrc
        self.raw = raw
        super().__init__(f"0x{sid:02X} -> NRC 0x{nrc:02X} "
                         f"({NRC.get(nrc, 'unknown')})")


class ReadOnlyViolation(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# request / response codecs
# --------------------------------------------------------------------------- #

def alfid_split(alfid: int) -> tuple:
    """(memorySize width, memoryAddress width) in bytes."""
    return ((alfid >> 4) & 0x0F, alfid & 0x0F)


def build_23(addr: int, size: int, alfid: int = 0x24) -> bytes:
    size_len, addr_len = alfid_split(alfid)
    if size_len == 0 or addr_len == 0:
        raise ValueError(f"ALFID 0x{alfid:02X} has a zero-width field")
    if size >= (1 << (8 * size_len)):
        raise ValueError(f"size {size} does not fit {size_len} B")
    if addr >= (1 << (8 * addr_len)):
        raise ValueError(f"address 0x{addr:X} does not fit {addr_len} B")
    return (bytes([SID_READ_MEMORY, alfid])
            + addr.to_bytes(addr_len, "big")
            + size.to_bytes(size_len, "big"))


@dataclass
class ReadMemoryAnswer:
    alfid: int
    addr: int
    size: int
    data: bytes
    raw: bytes

    @property
    def ok(self) -> bool:
        return len(self.data) == self.size


def parse_63(resp: bytes) -> ReadMemoryAnswer:
    if not resp:
        raise ValueError("empty response")
    if resp[0] == SID_NEGATIVE:
        sid = resp[1] if len(resp) > 1 else 0
        nrc = resp[2] if len(resp) > 2 else 0
        raise UdsError(sid, nrc, resp)
    if resp[0] != SID_READ_MEMORY_RESP:
        raise ValueError(f"unexpected SID 0x{resp[0]:02X} (not 0x63)")
    if len(resp) < 3:
        raise ValueError("truncated 0x63 response")
    alfid = resp[1]
    size_len, addr_len = alfid_split(alfid)
    hdr = 2 + size_len + addr_len
    if len(resp) < hdr:
        raise ValueError(f"0x63 header needs {hdr} B, got {len(resp)}")
    addr = int.from_bytes(resp[2:2 + addr_len], "big")
    size = int.from_bytes(resp[2 + addr_len:hdr], "big")
    data = resp[hdr:]
    return ReadMemoryAnswer(alfid=alfid, addr=addr, size=size, data=data,
                            raw=resp)


def parse_negative(resp: bytes) -> Optional[tuple]:
    if len(resp) >= 3 and resp[0] == SID_NEGATIVE:
        return resp[1], resp[2]
    return None


# --------------------------------------------------------------------------- #
# read-only guard
# --------------------------------------------------------------------------- #

class ReadOnlyGuard:
    """Refuse anything that is not an explicitly allow-listed read service."""

    def __init__(self, allowed: Optional[set] = None, strict: bool = True):
        self.allowed = set(ALLOWED_SIDS if allowed is None else allowed)
        self.strict = strict
        self.refused: list = []

    def check(self, payload: bytes) -> None:
        if not payload:
            raise ReadOnlyViolation("empty request")
        sid = payload[0]
        if sid in self.allowed:
            return
        self.refused.append(payload.hex())
        if self.strict:
            raise ReadOnlyViolation(
                f"SID 0x{sid:02X} is not read-only; refused "
                f"(allowed: {sorted(self.allowed)})")


# --------------------------------------------------------------------------- #
# dump session
# --------------------------------------------------------------------------- #

@dataclass
class BlockRecord:
    index: int
    addr: int
    size: int
    data: bytes
    attempts: int = 1
    mismatches: int = 0
    alfid: int = 0
    note: str = ""

    def as_dict(self) -> dict:
        return {"index": self.index, "addr": f"0x{self.addr:08X}",
                "size": self.size, "attempts": self.attempts,
                "mismatches": self.mismatches, "alfid": f"0x{self.alfid:02X}",
                "sha256": hashlib.sha256(self.data).hexdigest()[:16],
                "note": self.note}


class DumpSession:
    def __init__(self, link: "isotp.IsoTpLink", base_addr: int = 0x00000000,
                 block_size: int = 512, blocks: Optional[int] = None,
                 total: int = 16384, alfid: Optional[int] = None,
                 retries: int = 3, timeout: float = 2.0,
                 guard: Optional[ReadOnlyGuard] = None,
                 alfid_candidates: Sequence[int] = ALFID_CANDIDATES,
                 verbose: bool = False, label: str = "bms"):
        self.link = link
        self.base = base_addr
        self.block = block_size
        self.total = total
        self.blocks = blocks if blocks is not None else total // block_size
        self.alfid = alfid
        self.retries = retries
        self.timeout = timeout
        self.guard = guard or ReadOnlyGuard()
        self.alfid_candidates = tuple(alfid_candidates)
        self.verbose = verbose
        self.label = label
        self.records: list = []
        self.transcript: list = []
        self.alvid_trials: list = []
        self.session_kind = None

    # -- one request/response ------------------------------------------- #
    def raw_request(self, payload: bytes) -> bytes:
        self.guard.check(payload)
        self.transcript.append({"t": time.time(), "tx": payload.hex()})
        resp = self.link.request(payload, timeout=self.timeout)
        self.transcript.append({"t": time.time(), "rx": resp.hex()})
        if self.verbose:
            print(f"    TX {payload.hex()}  RX {resp.hex()[:40]}"
                  f"{'...' if len(resp) > 20 else ''} "
                  f"({len(resp)} B)")
        return resp

    def session(self, kind: int = 0x01) -> bytes:
        return self.raw_request(bytes([SID_SESSION, kind]))

    def tester_present(self) -> bytes:
        return self.raw_request(bytes([SID_TESTER_PRESENT, 0x00]))

    def ensure_session(self, kinds: Sequence[int] = (0x01, 0x03)) -> Optional[int]:
        """Open a diagnostic session if the ECU wants one before 0x23.

        Tolerant by design: a gateway that only implements 0x22 answers NRC
        0x11 here, and an ECU that is already in the default session answers
        0x50 01 to 0x10 01.  Either way the dump proceeds and the transcript
        records what happened.
        """
        for kind in kinds:
            try:
                resp = self.session(kind)
            except (UdsError, isotp.IsoTpError) as exc:
                self.transcript.append({"session": kind, "error": str(exc)})
                continue
            if resp and resp[0] == 0x50:
                self.session_kind = kind
                self.transcript.append({"session": kind, "ok": True,
                                        "resp": resp.hex()})
                return kind
        return None

    # -- ALFID negotiation ---------------------------------------------- #
    def negotiate_alfid(self, probe_size: int = 16,
                        candidates: Optional[Sequence[int]] = None) -> int:
        """Pick the first ALFID the ECU actually accepts at this address."""
        if self.alfid is not None:
            return self.alfid
        if candidates is None:
            candidates = self.alfid_candidates
        for alfid in candidates:
            size_len, _ = alfid_split(alfid)
            try:
                req = build_23(self.base, probe_size, alfid)
            except ValueError as exc:
                self.alvid_trials.append({"alfid": alfid, "result":
                                          f"unencodable: {exc}"})
                continue
            try:
                ans = parse_63(self.raw_request(req))
                ok = len(ans.data) >= probe_size
                self.alvid_trials.append({
                    "alfid": f"0x{alfid:02X}", "size_len": size_len,
                    "result": "accepted" if ok else "short", "bytes":
                    len(ans.data)})
                if ok:
                    self.alfid = alfid
                    return alfid
            except UdsError as exc:
                self.alvid_trials.append({"alfid": f"0x{alfid:02X}",
                                          "size_len": size_len,
                                          "result": f"NRC 0x{exc.nrc:02X}",
                                          "nrc_name": NRC.get(exc.nrc)})
                continue
        raise RuntimeError(f"no ALFID accepted: {self.alvid_trials}")

    # -- one block, read twice ------------------------------------------ #
    def _read_once(self, addr: int, size: int) -> bytes:
        req = build_23(addr, size, self.alfid)
        ans = parse_63(self.raw_request(req))
        if ans.addr != addr:
            raise ValueError(f"address echo 0x{ans.addr:08X} != 0x{addr:08X}")
        if ans.size != size:
            raise ValueError(f"size echo {ans.size} != {size}")
        if len(ans.data) != size:
            raise ValueError(f"payload {len(ans.data)} B != {size} B")
        return ans.data

    def read_block(self, index: int) -> BlockRecord:
        addr = self.base + index * self.block
        size = min(self.block, self.total - index * self.block)
        first = None
        mismatches = 0
        attempts = 0
        last_error = ""
        for attempt in range(1, self.retries + 1):
            attempts = attempt
            try:
                data = self._read_once(addr, size)
            except (UdsError, ValueError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if self.verbose:
                    print(f"    block {index:02d} attempt {attempt}: {last_error}")
                continue
            if first is None:
                first = data
                continue
            if data == first:
                return BlockRecord(index, addr, size, first, attempts, mismatches,
                                   self.alfid)
            mismatches += 1
            if self.verbose:
                print(f"    block {index:02d} attempt {attempt}: mismatch vs "
                      f"first read, retrying")
            if attempt == 2:
                first = data  # adopt the newer read as the reference
        if first is None:
            raise RuntimeError(f"block {index} at 0x{addr:08X} unreadable: "
                               f"{last_error}")
        return BlockRecord(index, addr, size, first, attempts, mismatches,
                           self.alfid, note=f"unconfirmed: {last_error}")

    # -- whole image ----------------------------------------------------- #
    def dump(self, out_path: Optional[str] = None,
             verify_boundaries: bool = False) -> dict:
        t0 = time.perf_counter()
        self.ensure_session()
        self.negotiate_alfid()
        chunks = []
        for i in range(self.blocks):
            rec = self.read_block(i)
            self.records.append(rec)
            chunks.append(rec.data)
            print(f"  [{i + 1:02d}/{self.blocks:02d}] 0x{rec.addr:08X} "
                  f"{rec.size} B  attempts={rec.attempts} "
                  f"mismatch={rec.mismatches} sha={hashlib.sha256(rec.data).hexdigest()[:12]}")
        image = b"".join(chunks)
        elapsed = time.perf_counter() - t0

        boundaries = None
        if verify_boundaries:
            boundaries = self.verify_boundaries(image)

        report = {
            "tool": "bms_dump.py",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "can_ids": {"tx": f"0x{self.link.tx_id:03X}",
                        "rx": (f"0x{self.link.rx_id:03X}"
                               if self.link.rx_id is not None else None)},
            "dl": self.link.dl, "brs": self.link.brs,
            "alfid": f"0x{self.alfid:02X}" if self.alfid is not None else None,
            "session_kind": (f"0x{self.session_kind:02X}"
                             if self.session_kind is not None else None),
            "alfid_trials": self.alvid_trials,
            "base": f"0x{self.base:08X}", "block": self.block,
            "blocks": self.blocks, "total": len(image),
            "sha256": hashlib.sha256(image).hexdigest(),
            "elapsed_s": round(elapsed, 2),
            "retries_used": sum(1 for r in self.records if r.attempts > 1),
            "mismatch_blocks": sum(1 for r in self.records if r.mismatches),
            "unconfirmed_blocks": [r.index for r in self.records if r.note],
            "blocks_detail": [r.as_dict() for r in self.records],
            "boundaries": boundaries,
            "rv32": rv32_sanity(image),
        }
        if out_path:
            os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(image)
            report["out_path"] = out_path
            print(f"\nimage written: {out_path} ({len(image)} B) "
                  f"sha256={report['sha256']}")
        return report

    # -- boundary cross-check ------------------------------------------- #
    def verify_boundaries(self, image: bytes, window: int = 64) -> dict:
        """Re-read 64 B across each block seam and compare with the image."""
        mismatches = []
        checked = 0
        for i in range(1, self.blocks):
            addr = self.base + i * self.block - window // 2
            try:
                data = self._read_once(addr, window)
            except (UdsError, ValueError) as exc:
                mismatches.append({"seam": i, "addr": f"0x{addr:08X}",
                                   "error": str(exc)})
                continue
            off = addr - self.base
            checked += 1
            if image[off:off + window] != data:
                mismatches.append({"seam": i, "addr": f"0x{addr:08X}",
                                   "error": "data differs from per-block reads"})
        print(f"  boundary check: {checked} seams read, "
              f"{len(mismatches)} mismatch(es)")
        return {"seams_checked": checked, "mismatches": mismatches}


# --------------------------------------------------------------------------- #
# RV32IM image sanity (no disassembler needed)
# --------------------------------------------------------------------------- #

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    import math
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def find_isolated_constants(image: bytes, block: int = 32,
                            high: int = 20, low: int = 12) -> list:
    """Find key-shaped constants: high byte diversity surrounded by low diversity.

    A 16/32-byte AES/HMAC key embedded in an otherwise zero-filled or
    code-filled region is exactly this shape.  A dense encrypted body is not
    flagged because its neighbours are just as diverse.
    """
    n = len(image) // block
    if n < 1:
        return []
    diversity = [len(set(image[i * block:(i + 1) * block])) for i in range(n)]
    found = []
    for i in range(n):
        if diversity[i] < high:
            continue
        prev_ok = (i == 0) or diversity[i - 1] < low
        next_ok = (i == n - 1) or diversity[i + 1] < low
        if prev_ok and next_ok:
            found.append({"off": f"0x{i * block:04X}", "len": block,
                          "distinct_bytes": diversity[i],
                          "entropy": round(entropy(image[i * block:(i + 1) * block]), 2)})
    return found


def rv32_sanity(image: bytes) -> dict:
    """Cheap structural checks: does this look like a bare-metal RV32 image?"""
    out = {"size": len(image)}
    if len(image) < 64:
        out["verdict"] = "too small"
        return out
    first = struct.unpack_from("<I", image, 0)[0]
    second = struct.unpack_from("<I", image, 4)[0]
    out["word0"] = f"0x{first:08X}"
    out["word1"] = f"0x{second:08X}"
    # classic RV32 reset vectors: jal x0/ra with a small offset
    out["reset_vector_like"] = first in (0x0000006F, 0x000000EF,
                                         0x0140006F, 0x0180006F)
    out["opcode0"] = first & 0x7F
    # strings
    strings = []
    cur = bytearray()
    for b in image:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= 5:
                strings.append(bytes(cur).decode("ascii"))
            cur.clear()
    if len(cur) >= 5:
        strings.append(bytes(cur).decode("ascii"))
    out["strings"] = strings[:40]
    out["string_count"] = len(strings)
    # high-entropy windows -> candidate keys / compressed blobs
    windows = []
    step = 64
    for off in range(0, len(image) - step + 1, step):
        h = entropy(image[off:off + step])
        if h > 7.0:
            windows.append({"off": f"0x{off:04X}", "entropy": round(h, 2)})
    out["high_entropy_windows"] = windows[:40]
    out["entropy_overall"] = round(entropy(image), 2)
    out["key_like_constants"] = find_isolated_constants(image)
    # uniform (erased / unmapped) regions
    runs = []
    start = None
    for i, b in enumerate(image + b"\x00"):
        if b == 0xFF and start is None:
            start = i
        elif b != 0xFF and start is not None:
            if i - start >= 256:
                runs.append({"off": f"0x{start:04X}", "len": i - start})
            start = None
    out["erased_runs_ff"] = runs
    out["verdict"] = ("looks like RV32 bare metal"
                      if out["reset_vector_like"] or out["string_count"] > 3
                      else "unrecognised")
    return out


# --------------------------------------------------------------------------- #
# synthetic image + stub ECU for the self-test
# --------------------------------------------------------------------------- #

def make_synthetic_image(size: int = 16384) -> bytes:
    """A plausible RV32IM image: reset vector, strings, a key-looking blob."""
    img = bytearray(size)
    struct.pack_into("<I", img, 0x00, 0x000000EF)   # jal ra, 4
    struct.pack_into("<I", img, 0x04, 0x00000000)
    struct.pack_into("<I", img, 0x08, 0x0000006F)   # jal x0, 0
    for off, text in ((0x40, b"CV6-BMS-RV32IM"), (0x60, b"root key derivation"),
                      (0x80, b"HKDF-SHA256 salt=VIN inf")):
        img[off:off + len(text)] = text
    # a 32-byte high-entropy "key" blob
    key = hashlib.sha256(b"cv6-bms-root-key").digest()
    img[0x200:0x220] = key
    # body: deterministic pseudo-random so hashes are stable
    seed = hashlib.sha256(b"body").digest()
    body = bytearray()
    while len(body) < size - 0x400:
        seed = hashlib.sha256(seed).digest()
        body += seed
    img[0x400:0x400 + len(body)] = body
    return bytes(img)


class StubBmsEcu:
    """ISO-TP-facing fake BMS: honours 0x23, needs 0x10 01 first, faults once."""

    def __init__(self, image: bytes, base: int = 0, reject_alfid=0x14,
                 require_session: bool = True, corrupt_once_at: Optional[int] = None):
        self.image = image
        self.base = base
        self.reject_alfid = reject_alfid
        self.require_session = require_session
        self.corrupt_once_at = corrupt_once_at
        self.session_open = not require_session
        self.calls = 0
        self.corrupted = False
        self.log: list = []

    def __call__(self, req: bytes) -> bytes:
        self.calls += 1
        if not req:
            return bytes([0x7F, 0x00, 0x13])
        sid = req[0]
        if sid == SID_SESSION:
            self.session_open = True
            return bytes([0x50, req[1] if len(req) > 1 else 0x01])
        if sid == SID_TESTER_PRESENT:
            return bytes([0x7E, 0x00])
        if sid != SID_READ_MEMORY:
            return bytes([0x7F, sid, 0x11])
        if self.require_session and not self.session_open:
            return bytes([0x7F, sid, 0x31])
        if len(req) < 3:
            return bytes([0x7F, sid, 0x13])
        alfid = req[1]
        if alfid == self.reject_alfid:
            return bytes([0x7F, sid, 0x13])
        size_len, addr_len = alfid_split(alfid)
        if len(req) != 2 + addr_len + size_len:
            return bytes([0x7F, sid, 0x13])
        addr = int.from_bytes(req[2:2 + addr_len], "big")
        size = int.from_bytes(req[2 + addr_len:2 + addr_len + size_len], "big")
        off = addr - self.base
        if off < 0 or off + size > len(self.image):
            return bytes([0x7F, sid, 0x31])
        data = bytearray(self.image[off:off + size])
        if (self.corrupt_once_at is not None and not self.corrupted
                and off == self.corrupt_once_at):
            data[0] ^= 0xFF  # one transient bit flip, repaired on re-read
            self.corrupted = True
            self.log.append(f"injected fault at 0x{off:08X}")
        return (bytes([SID_READ_MEMORY_RESP, alfid])
                + addr.to_bytes(addr_len, "big")
                + size.to_bytes(size_len, "big")
                + bytes(data))


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #

class _Res:
    def __init__(self):
        self.rows = []

    def check(self, name, cond, detail=""):
        self.rows.append({"name": name, "ok": bool(cond), "detail": detail})
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}" +
              (f"  -- {detail}" if detail else ""))
        return bool(cond)

    @property
    def ok(self):
        return all(r["ok"] for r in self.rows)


def _loopback(ecu, dl=16, bs=8, stmin=0x00):
    bus = isotp.VirtualBus()
    tester = isotp.IsoTpLink(bus.endpoint(0), tx_id=0x7E1, rx_id=0x7E9, dl=dl,
                             brs=True, label="tester")
    peer = isotp.EcuStub(bus.endpoint(1), rx_id=0x7E1, tx_id=0x7E9,
                         handler=ecu, dl=dl, bs=bs, stmin=stmin, name="bms")
    peer.start()
    return tester, peer


def _t_codec(res: _Res) -> None:
    print("\n[1] 0x23 request/response codec")
    req = build_23(0x08000000, 512, 0x24)
    res.check("0x24 request layout",
              req.hex() == "2324080000000200", req.hex())
    res.check("0x14 request layout (1-byte size)",
              build_23(0x1000, 16, 0x14).hex() == "23140000100010",
              build_23(0x1000, 16, 0x14).hex())
    res.check("0x44 request layout (4-byte size)",
              build_23(0x1000, 512, 0x44).hex() == "23440000100000000200",
              build_23(0x1000, 512, 0x44).hex())
    try:
        build_23(0, 512, 0x14)
        ok = False
    except ValueError:
        ok = True
    res.check("0x14 cannot encode 512 (expected)", ok, "ValueError")

    resp = bytes([0x63, 0x24]) + (0x1000).to_bytes(4, "big") + (4).to_bytes(2, "big") + b"\xDE\xAD\xBE\xEF"
    ans = parse_63(resp)
    res.check("0x63 parse", ans.addr == 0x1000 and ans.size == 4
              and ans.data == b"\xDE\xAD\xBE\xEF", ans.data.hex())
    res.check("0x63 ok flag", ans.ok)

    try:
        parse_63(bytes([0x7F, 0x23, 0x31]))
        ok = False
    except UdsError as exc:
        ok = exc.nrc == 0x31
    res.check("NRC path parsed", ok, "0x31 requestOutOfRange")

    # guard
    g = ReadOnlyGuard()
    g.check(bytes([0x23, 0x24]))
    try:
        g.check(bytes([0x2E, 0xF1, 0x90, 0x00]))
        blocked = False
    except ReadOnlyViolation:
        blocked = True
    res.check("mutating SID refused by guard", blocked, "0x2E blocked")
    try:
        g.check(bytes([0x31, 0x01, 0x02, 0x02]))
        blocked = False
    except ReadOnlyViolation:
        blocked = True
    res.check("0x31 RoutineControl refused by guard", blocked, "0x31 blocked")


def _t_dump(res: _Res) -> None:
    print("\n[2] 32 x 512 B dump over ISO-TP loopback")
    image = make_synthetic_image()
    want = hashlib.sha256(image).hexdigest()
    ecu = StubBmsEcu(image, require_session=True, reject_alfid=0x14,
                     corrupt_once_at=3 * 512)
    tester, peer = _loopback(ecu)
    sess = DumpSession(tester, base_addr=0, block_size=512, total=16384,
                       retries=3, timeout=2.0, verbose=False,
                       alfid_candidates=(0x14, 0x24, 0x44))
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "_selftest_bms.bin")
    report = sess.dump(out_path=out_path)
    peer.stop()

    res.check("ALFID negotiation fell back to 0x24",
              report["alfid"] == "0x24",
              json.dumps(report["alfid_trials"]))
    res.check("0x14 rejected with NRC 0x13 first",
              report["alfid_trials"][0]["result"] == "NRC 0x13",
              str(report["alfid_trials"][0]))
    res.check("32 blocks read", len(report["blocks_detail"]) == 32,
              str(len(report["blocks_detail"])))
    res.check("16384 bytes total", report["total"] == 16384,
              str(report["total"]))
    res.check("sha256 matches synthetic image",
              report["sha256"] == want,
              f"{report['sha256'][:16]} vs {want[:16]}")
    res.check("transient corruption was detected",
              report["mismatch_blocks"] >= 1,
              f"{report['mismatch_blocks']} block(s) needed a re-read")
    res.check("no unconfirmed blocks", not report["unconfirmed_blocks"],
              str(report["unconfirmed_blocks"]))
    res.check("stub saw 32+ reads", ecu.calls >= 34, f"{ecu.calls} requests")
    res.check("all addresses covered once",
              [r["addr"] for r in report["blocks_detail"]]
              == [f"0x{i * 512:08X}" for i in range(32)],
              "0x0000..0x7C00 step 0x200")
    with open(out_path, "rb") as f:
        disk = f.read()
    res.check("file on disk is byte-identical", disk == image,
              f"{len(disk)} B")
    res.check("rv32 sanity sees the reset vector",
              report["rv32"]["reset_vector_like"], report["rv32"]["word0"])
    res.check("rv32 sanity found the magic string",
              any("CV6-BMS" in s for s in report["rv32"]["strings"]),
              str(report["rv32"]["strings"][:3]))
    consts = report["rv32"]["key_like_constants"]
    res.check("rv32 sanity flagged the embedded key blob",
              any(c["off"] == "0x0200" for c in consts),
              f"{len(consts)} isolated constant(s): "
              f"{[c['off'] for c in consts][:5]}")
    res.check("dense body is not mistaken for a key",
              all(c["off"] != "0x0400" for c in consts), "0x0400 excluded")
    try:
        os.remove(out_path)
    except OSError:
        pass


def _t_boundaries(res: _Res) -> None:
    print("\n[3] boundary cross-check")
    image = make_synthetic_image()
    ecu = StubBmsEcu(image, require_session=False)
    tester, peer = _loopback(ecu)
    sess = DumpSession(tester, base_addr=0, block_size=512, total=4096,
                       retries=2, timeout=2.0)
    report = sess.dump(verify_boundaries=True)
    peer.stop()
    res.check("seams checked", report["boundaries"]["seams_checked"] == 7,
              str(report["boundaries"]["seams_checked"]))
    res.check("no seam mismatch", not report["boundaries"]["mismatches"],
              str(report["boundaries"]["mismatches"]))
    res.check("partial dump still byte-exact",
              report["sha256"] == hashlib.sha256(image[:4096]).hexdigest(),
              report["sha256"][:16])


def _t_base_addr(res: _Res) -> None:
    print("\n[4] non-zero base address (0x08000000)")
    image = make_synthetic_image(4096)
    ecu = StubBmsEcu(image, base=0x08000000, require_session=False)
    tester, peer = _loopback(ecu, bs=8)
    sess = DumpSession(tester, base_addr=0x08000000, block_size=512,
                       total=4096, retries=2)
    report = sess.dump()
    peer.stop()
    res.check("base echoed correctly",
              report["blocks_detail"][0]["addr"] == "0x08000000",
              report["blocks_detail"][0]["addr"])
    res.check("image matches", report["sha256"] == hashlib.sha256(image).hexdigest(),
              report["sha256"][:16])


def _t_session_gate(res: _Res) -> None:
    print("\n[5] session prerequisite")
    image = make_synthetic_image(1024)
    ecu = StubBmsEcu(image, require_session=True)
    tester, peer = _loopback(ecu)
    sess = DumpSession(tester, block_size=512, total=1024, retries=1,
                       alfid=0x24)  # skip negotiation: this test is about the gate
    # without a session the ECU answers NRC 0x31 -> dump must fail loudly
    failed = ""
    try:
        sess.read_block(0)
    except RuntimeError as exc:
        failed = str(exc)
    res.check("read without session fails", "unreadable" in failed, failed)
    resp = sess.session(0x01)
    res.check("0x10 01 accepted", resp[0] == 0x50, resp.hex())
    rec = sess.read_block(0)
    res.check("read after session succeeds", rec.data == image[:512], "512 B")
    peer.stop()


def self_test(evidence_dir: Optional[str] = None) -> int:
    print("=" * 78)
    print("bms_dump.py self-test -- 0x23 ReadMemoryByAddress over ISO-TP loopback")
    print("=" * 78)
    t0 = time.time()
    res = _Res()
    _t_codec(res)
    _t_dump(res)
    _t_boundaries(res)
    _t_base_addr(res)
    _t_session_gate(res)
    passed = sum(1 for r in res.rows if r["ok"])
    total = len(res.rows)
    print("\n" + "=" * 78)
    print(f"RESULT: {passed}/{total} checks passed "
          f"({'OK' if res.ok else 'FAILURES'}) in {time.time() - t0:.1f}s")
    print("=" * 78)
    if evidence_dir:
        os.makedirs(evidence_dir, exist_ok=True)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        base = os.path.join(evidence_dir, "02_selftest_bms_dump")
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump({"tool": "bms_dump.py", "ts": stamp, "passed": passed,
                       "total": total, "ok": res.ok, "checks": res.rows},
                      f, indent=2, ensure_ascii=False)
        with open(base + ".log", "w", encoding="utf-8") as f:
            f.write(f"# bms_dump.py self-test {stamp}\n")
            for r in res.rows:
                f.write(f"[{'PASS' if r['ok'] else 'FAIL'}] {r['name']}")
                if r["detail"]:
                    f.write(f"  -- {r['detail']}")
                f.write("\n")
            f.write(f"\nRESULT {passed}/{total} {'OK' if res.ok else 'FAIL'}\n")
        print(f"evidence written: {base}.json / .log")
    return 0 if res.ok else 1


# --------------------------------------------------------------------------- #
# real target
# --------------------------------------------------------------------------- #

def make_link(args) -> "isotp.IsoTpLink":
    """Build a link to the real bridge (framing is discovered by tap13401)."""
    import tap13401  # local import: keeps --self-test dependency-free

    transport, info = tap13401.open_transport(
        host=args.tap, port=args.port, framing=args.framing,
        timeout=args.timeout, can_id=args.tx_id)
    print(f"[tap] {json.dumps(info, indent=2)}")
    tx, rx = args.tx_id, args.rx_id
    return isotp.IsoTpLink(transport, tx_id=tx, rx_id=rx, dl=args.dl,
                           brs=not args.no_brs, label="bms")


def scan_target(args) -> int:
    """Probe both ECU pairs and several address bases with 16-byte 0x23 reads.

    All reads; nothing here changes ECU state.  The point is to spend one
    connection to learn (a) which CAN ID pair answers 0x23 and (b) which base
    address holds real code, instead of discovering it during a 32-block dump.
    """
    import tap13401

    bases = [int(x, 0) for x in args.bases.split(",")]
    transport, info = tap13401.open_transport(
        host=args.tap, port=args.port, framing=args.framing,
        timeout=args.timeout, can_id=ID_PAIRS["ecu1"][0])
    print(json.dumps(info, indent=2))
    results = []
    for pair_name, (tx, rx) in ID_PAIRS.items():
        link = isotp.IsoTpLink(transport, tx_id=tx, rx_id=rx, dl=args.dl,
                               brs=not args.no_brs, label=pair_name)
        sess = DumpSession(link, base_addr=0, block_size=16, total=16,
                           alfid=0x24, retries=1, timeout=args.timeout)
        entry = {"pair": pair_name, "tx": f"0x{tx:03X}", "rx": f"0x{rx:03X}",
                 "reads": []}
        try:
            entry["session"] = (sess.ensure_session() is not None)
        except Exception as exc:  # noqa: BLE001 - diagnostics only
            entry["session_error"] = str(exc)
        for base in bases:
            row = {"base": f"0x{base:08X}"}
            try:
                data = sess._read_once(base, 16)
                row["data"] = data.hex()
                row["erased"] = all(b == 0xFF for b in data)
                row["zeros"] = all(b == 0x00 for b in data)
            except (UdsError, ValueError, isotp.IsoTpError) as exc:
                row["error"] = str(exc)
            entry["reads"].append(row)
        results.append(entry)
        print(json.dumps(entry, indent=2, ensure_ascii=False))
    alive = [e for e in results
             if any("data" in r for r in e["reads"])]
    print(f"\nsummary: {len(alive)} pair(s) answered 0x23")
    if args.evidence_dir:
        os.makedirs(args.evidence_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = os.path.join(args.evidence_dir, f"11_bms_scan_{stamp}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"tap": info, "results": results}, f, indent=2,
                      ensure_ascii=False)
        print(f"evidence written: {path}")
    return 0 if alive else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="BMS firmware dump over CAN FD")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--evidence-dir", default=None)
    ap.add_argument("--analyze", default=None, help="only sanity-check a file")
    ap.add_argument("--tap", default="10.226.193.2")
    ap.add_argument("--port", type=int, default=13401)
    ap.add_argument("--framing", default="auto")
    ap.add_argument("--pair", default="ecu2", choices=sorted(ID_PAIRS))
    ap.add_argument("--tx-id", default=None)
    ap.add_argument("--rx-id", default=None)
    ap.add_argument("--dl", type=int, default=16)
    ap.add_argument("--no-brs", action="store_true")
    ap.add_argument("--base", default="0x00000000")
    ap.add_argument("--block", type=int, default=512)
    ap.add_argument("--total", type=int, default=16384)
    ap.add_argument("--alfid", default=None)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--out", default=None)
    ap.add_argument("--verify-boundaries", action="store_true")
    ap.add_argument("--scan", action="store_true",
                    help="probe both ECU pairs and several bases, then stop")
    ap.add_argument("--bases", default="0x00000000,0x08000000,0x80000000,0x20000000")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    if args.analyze:
        with open(args.analyze, "rb") as f:
            img = f.read()
        print(json.dumps(rv32_sanity(img), indent=2, ensure_ascii=False))
        return 0
    if args.self_test:
        return self_test(args.evidence_dir)
    if args.scan:
        return scan_target(args)

    pair_tx, pair_rx = ID_PAIRS[args.pair]
    args.tx_id = int(str(args.tx_id), 0) if args.tx_id else pair_tx
    args.rx_id = int(str(args.rx_id), 0) if args.rx_id else pair_rx
    base = int(str(args.base), 0)
    alfid = int(str(args.alfid), 0) if args.alfid else None
    out = args.out or os.path.join("03_EVIDENCE", "canfd", "bms_fw.bin")

    link = make_link(args)
    sess = DumpSession(link, base_addr=base, block_size=args.block,
                       total=args.total, alfid=alfid, retries=args.retries,
                       timeout=args.timeout, verbose=args.verbose)
    report = sess.dump(out_path=out,
                       verify_boundaries=args.verify_boundaries)
    print(json.dumps(report, indent=2, ensure_ascii=False)[:4000])
    if args.evidence_dir:
        os.makedirs(args.evidence_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = os.path.join(args.evidence_dir, f"10_bms_dump_{stamp}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"evidence written: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""secoc.py -- AUTOSAR-style SecOC authenticator, parameterised and crackable.

Why this file is parameterised
------------------------------
Task 05 asks for a *16-byte CAN FD control frame with BRS* that carries a
truncated AES-CMAC over (DataID, payload, freshness) and is accepted by the
BCM.  The wire profile is not documented anywhere in the bundle, and no bus
trace exists yet (the CAN FD bridge is still closed), so hard-coding one
guessed layout would be worthless.  Instead this module exposes the layout as
data (`SecocProfile`) and ships a search that recovers the layout from a
handful of captured frames once the bridge opens.

The two halves
--------------
1. `SecocProfile` + `build_secured_pdu()` + `verify_frame()`
   A faithful, configurable implementation of the AUTOSAR SecOC construction:

       Secured I-PDU  = [TruncatedFreshness] || Authentic I-PDU || Authenticator
       MAC            = CMAC-AES128(K, DataID || Authentic I-PDU || Freshness)
       Authenticator  = truncate(MAC, mac_bits)

   Everything that varies between OEM profiles is a field: DataID width and
   endianness, freshness width and endianness, MAC length and which bits are
   kept, the concatenation order of the three MAC inputs, the section order in
   the frame, the filler byte, and the CAN FD data length.

2. `crack()` / `SearchSpace`
   Given >=2 captured frames (same payload, different freshness) it enumerates
   profiles and keeps only those that reproduce *every* frame byte-for-byte.
   Requiring agreement across frames kills the 1/2^24 false positives that a
   single 24-bit MAC would otherwise produce.

Self-test (runs with no target):
  * RFC 4493 AES-CMAC vectors (empty, 16, 40, 64 byte messages)
  * truncated MAC handling
  * a hidden synthetic profile is generated, frames are produced, and `crack()`
    must recover DataID / freshness width / endianness / MAC bits / order
  * negative control: a wrong key must not match

Read-only note: nothing in this file transmits.  It builds and checks bytes;
sending a control frame is a separate, deliberate step (task 05 requires a BCM
ACK, so the frames will be sent by the operator only after the layout is
confirmed by `crack()`).

CLI
---
    python secoc.py --self-test
    python secoc.py --rfc4493
    python secoc.py --spec --key 00112233445566778899aabbccddeeff \
                    --dataid 0x0A1B --freshness 0x1122334455667788 \
                    --payload 0322f190 --mac-bits 24
    python secoc.py --crack captures.json --key <hex> --dataid 0x0A1B
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
import time
from dataclasses import dataclass, field, replace
from typing import Iterable, Optional, Sequence

try:
    from cryptography.hazmat.primitives import cmac as _cmac
    from cryptography.hazmat.primitives.ciphers import algorithms as _algs
except ImportError as exc:  # pragma: no cover - environment guard
    raise SystemExit("cryptography is required: pip install cryptography") from exc


# --------------------------------------------------------------------------- #
# AES-CMAC (RFC 4493) on top of cryptography's CMAC
# --------------------------------------------------------------------------- #

def aes_cmac(key: bytes, message: bytes) -> bytes:
    """AES-CMAC per RFC 4493 / NIST SP 800-38B.  Returns the full 16 bytes."""
    if len(key) not in (16, 24, 32):
        raise ValueError(f"AES key must be 16/24/32 bytes, got {len(key)}")
    c = _cmac.CMAC(_algs.AES(key))
    c.update(bytes(message))
    return c.finalize()


def truncate_mac(mac: bytes, bits: int, take: str = "msb") -> bytes:
    """Truncate a CMAC to `bits`, keeping the MSBs (AUTOSAR) or LSBs.

    Bit lengths that are not a multiple of 8 are legal in AUTOSAR (28 is a
    common one).  The result then occupies ceil(bits/8) bytes and the bits that
    are not part of the truncated value are left as zero; `SecocProfile`
    carries a comparison mask so a peer that leaves them as junk still matches.
    """
    if bits <= 0 or bits > len(mac) * 8:
        raise ValueError(f"cannot keep {bits} of {len(mac) * 8} MAC bits")
    n = (bits + 7) // 8
    if take == "msb":
        out = bytearray(mac[:n])
        extra = n * 8 - bits
        if extra:
            out[-1] &= (0xFF << extra) & 0xFF
        return bytes(out)
    if take == "lsb":
        if bits % 8:
            raise ValueError("non-aligned LSB truncation is not supported")
        return mac[-n:]
    raise ValueError(f"mac_take must be 'msb' or 'lsb', got {take!r}")


# --------------------------------------------------------------------------- #
# profile
# --------------------------------------------------------------------------- #

#: every token that may appear in a MAC input or a frame
TOKENS = ("dataid", "payload", "freshness", "trunc_freshness", "mac", "pad")

DEFAULT_MAC_ORDER = ("dataid", "payload", "freshness")
DEFAULT_FRAME_ORDER = ("payload", "mac")


@dataclass(frozen=True)
class SecocProfile:
    """One concrete SecOC wire profile.

    key                AES-128 (or 192/256) CMAC key
    data_id            numeric DataID carried into the MAC input
    data_id_bytes      width of the DataID as serialised (2 or 3 typical)
    data_id_endian     "big" | "little"
    freshness_bytes    width of the *full* freshness value fed to the MAC
    freshness_endian   "big" | "little"
    mac_bits           retained MAC bits (24/28/32/64)
    mac_take           "msb" (AUTOSAR) | "lsb"
    mac_order          concatenation order of the MAC input tokens
    frame_order        section order inside the secured PDU
    trunc_freshness_bytes  how many low-order freshness bytes travel in-frame
    pad_byte           filler for the unused tail of the payload field
    pad_to             CAN FD data length of the secured frame (16 typical)
    """
    key: bytes
    data_id: int = 0x0000
    data_id_bytes: int = 2
    data_id_endian: str = "big"
    freshness_bytes: int = 8
    freshness_endian: str = "big"
    mac_bits: int = 24
    mac_take: str = "msb"
    mac_order: tuple = DEFAULT_MAC_ORDER
    frame_order: tuple = DEFAULT_FRAME_ORDER
    trunc_freshness_bytes: int = 0
    pad_byte: int = 0xCC
    pad_to: int = 16
    label: str = ""

    # -- derived --------------------------------------------------------- #
    @property
    def mac_len(self) -> int:
        """Bytes the authenticator occupies on the wire (28 bits -> 4)."""
        return (self.mac_bits + 7) // 8

    def mac_offset(self) -> int:
        """Byte offset of the authenticator inside the secured PDU."""
        off = 0
        for token in self.frame_order:
            if token == "mac":
                return off
            if token == "payload":
                off += self.pad_to - self.mac_len - self.trunc_freshness_bytes
            elif token == "trunc_freshness":
                off += self.trunc_freshness_bytes
            else:
                raise ValueError(f"unknown frame_order token {token!r}")
        raise ValueError("frame_order has no 'mac' section")

    def compare_mask(self) -> bytes:
        """Frame-length mask: 0xFF except the unused low bits of a non-aligned MAC."""
        mask = bytearray(b"\xFF" * self.pad_to)
        extra = self.mac_len * 8 - self.mac_bits
        if extra:
            idx = self.mac_offset() + self.mac_len - 1
            if self.mac_take == "msb":
                mask[idx] = (0xFF << extra) & 0xFF
            else:
                mask[self.mac_offset()] = (0xFF >> extra) & 0xFF
        return bytes(mask)

    def data_id_bytes_value(self) -> bytes:
        if self.data_id_endian == "big":
            return self.data_id.to_bytes(self.data_id_bytes, "big")
        return self.data_id.to_bytes(self.data_id_bytes, "little")

    def freshness_bytes_value(self, freshness: int) -> bytes:
        width = self.freshness_bytes
        if freshness >= (1 << (8 * width)):
            raise ValueError(f"freshness 0x{freshness:x} does not fit {width} B")
        if self.freshness_endian == "big":
            return freshness.to_bytes(width, "big")
        return freshness.to_bytes(width, "little")

    def truncated_freshness(self, freshness: int) -> bytes:
        n = self.trunc_freshness_bytes
        if not n:
            return b""
        if self.freshness_endian == "big":
            return freshness.to_bytes(self.freshness_bytes, "big")[-n:]
        return freshness.to_bytes(self.freshness_bytes, "little")[:n]

    # -- MAC ------------------------------------------------------------- #
    def mac_input(self, payload: bytes, freshness: int) -> bytes:
        parts = []
        for token in self.mac_order:
            if token == "dataid":
                parts.append(self.data_id_bytes_value())
            elif token == "payload":
                parts.append(bytes(payload))
            elif token == "freshness":
                parts.append(self.freshness_bytes_value(freshness))
            elif token == "trunc_freshness":
                parts.append(self.truncated_freshness(freshness))
            elif token in ("mac", "pad"):
                raise ValueError(f"token {token!r} cannot appear in mac_order")
            else:
                raise ValueError(f"unknown mac_order token {token!r}")
        return b"".join(parts)

    def mac(self, payload: bytes, freshness: int) -> bytes:
        return aes_cmac(self.key, self.mac_input(payload, freshness))

    def authenticator(self, payload: bytes, freshness: int) -> bytes:
        return truncate_mac(self.mac(payload, freshness), self.mac_bits,
                            self.mac_take)

    # -- frame ----------------------------------------------------------- #
    def build(self, payload: bytes, freshness: int) -> bytes:
        """Return the secured PDU padded to `pad_to` bytes."""
        auth = self.authenticator(payload, freshness)
        trun = self.truncated_freshness(freshness)
        # payload field absorbs whatever space is left after MAC + truncated FV
        fixed = self.mac_len + len(trun)
        if fixed >= self.pad_to:
            raise ValueError(f"MAC({self.mac_len}) + truncFV({len(trun)}) "
                             f"leave no room in {self.pad_to} B")
        payload_field_len = self.pad_to - fixed
        if len(payload) > payload_field_len:
            raise ValueError(f"payload {len(payload)} B > field "
                             f"{payload_field_len} B; widen pad_to")
        payload_field = bytes(payload) + bytes([self.pad_byte]) * (
            payload_field_len - len(payload))

        sections = {"payload": payload_field, "mac": auth,
                    "trunc_freshness": trun}
        out = bytearray()
        for token in self.frame_order:
            if token not in sections:
                raise ValueError(f"unknown frame_order token {token!r}")
            out += sections[token]
        if len(out) != self.pad_to:
            raise ValueError(f"frame assembled to {len(out)} B, "
                             f"expected {self.pad_to}")
        return bytes(out)

    def matches(self, secured: bytes, payload: bytes, freshness: int) -> bool:
        """Byte-compare, ignoring the unused low bits of a non-aligned MAC."""
        try:
            expected = self.build(payload, freshness)
        except ValueError:
            return False
        if len(expected) != len(secured):
            return False
        mask = self.compare_mask()
        return all((a & m) == (b & m)
                   for a, b, m in zip(expected, bytes(secured), mask))

    def verify(self, secured: bytes, payload: bytes, freshness: int) -> bool:
        return self.matches(secured, payload, freshness)

    def describe(self) -> str:
        return (f"key={self.key.hex()} dataid=0x{self.data_id:0{self.data_id_bytes * 2}X}"
                f"({self.data_id_endian},{self.data_id_bytes}B) "
                f"fresh={self.freshness_bytes}B/{self.freshness_endian} "
                f"mac={self.mac_bits}bit/{self.mac_take} "
                f"mac_order={'|'.join(self.mac_order)} "
                f"frame={'|'.join(self.frame_order)} "
                f"truncFV={self.trunc_freshness_bytes} "
                f"pad=0x{self.pad_byte:02X}@{self.pad_to}B")

    def as_dict(self) -> dict:
        return {"key": self.key.hex(), "data_id": self.data_id,
                "data_id_bytes": self.data_id_bytes,
                "data_id_endian": self.data_id_endian,
                "freshness_bytes": self.freshness_bytes,
                "freshness_endian": self.freshness_endian,
                "mac_bits": self.mac_bits, "mac_take": self.mac_take,
                "mac_order": list(self.mac_order),
                "frame_order": list(self.frame_order),
                "trunc_freshness_bytes": self.trunc_freshness_bytes,
                "pad_byte": self.pad_byte, "pad_to": self.pad_to}


# --------------------------------------------------------------------------- #
# freshness bookkeeping
# --------------------------------------------------------------------------- #

class FreshnessCounter:
    """Local view of the peer's 64-bit freshness value.

    SecOC freshness = (trip/reset counter, message counter) in real ECUs; for
    the challenge the full 64-bit value can be read over UDS once and then
    advanced locally.  `step` matches what the ECU does per secured PDU.
    """

    def __init__(self, start: int, step: int = 1, bits: int = 64):
        self.value = start
        self.step = step
        self.bits = bits
        self.used = 0

    def peek(self) -> int:
        return self.value

    def next(self) -> int:
        v = self.value
        self.value = (self.value + self.step) & ((1 << self.bits) - 1)
        self.used += 1
        return v

    def resync(self, observed: int) -> None:
        self.value = observed


# --------------------------------------------------------------------------- #
# captures + search space
# --------------------------------------------------------------------------- #

@dataclass
class Capture:
    """One observed secured frame plus the facts we know about it."""
    payload: bytes
    freshness: int
    secured: bytes
    can_id: Optional[int] = None
    note: str = ""

    @staticmethod
    def from_dict(d: dict) -> "Capture":
        return Capture(payload=bytes.fromhex(d["payload"]),
                       freshness=int(str(d["freshness"]), 0),
                       secured=bytes.fromhex(d["secured"]),
                       can_id=(int(str(d["can_id"]), 0) if d.get("can_id") else None),
                       note=d.get("note", ""))

    def as_dict(self) -> dict:
        return {"payload": self.payload.hex(), "freshness": self.freshness,
                "secured": self.secured.hex(), "can_id": self.can_id,
                "note": self.note}


@dataclass
class SearchSpace:
    """The grid `crack()` walks.  Keep it wide, then narrow from the first hit."""
    data_ids: Sequence[int] = (0x0000,)
    data_id_bytes: Sequence[int] = (2, 3)
    data_id_endians: Sequence[str] = ("big", "little")
    freshness_bytes: Sequence[int] = (8, 4)
    freshness_endians: Sequence[str] = ("big", "little")
    mac_bits: Sequence[int] = (24, 32, 28, 64)
    mac_takes: Sequence[str] = ("msb", "lsb")
    mac_orders: Sequence[tuple] = (
        ("dataid", "payload", "freshness"),   # AUTOSAR canonical
        ("dataid", "freshness", "payload"),
        ("payload", "dataid", "freshness"),
        ("payload", "freshness", "dataid"),
        ("freshness", "payload", "dataid"),
        ("freshness", "dataid", "payload"),
        ("dataid", "payload"),                # profile without freshness
        ("payload", "dataid"),
        ("payload", "freshness"),
        ("freshness", "payload"),
        ("payload",),
    )
    frame_orders: Sequence[tuple] = (
        ("payload", "mac"),
        ("mac", "payload"),
        ("trunc_freshness", "payload", "mac"),
        ("payload", "mac", "trunc_freshness"),
        ("payload", "trunc_freshness", "mac"),
    )
    trunc_freshness_bytes: Sequence[int] = (0,)
    pad_bytes: Sequence[int] = (0xCC, 0x00, 0xAA, 0xFF)
    pad_to: Sequence[int] = (16,)

    def profiles(self, key: bytes, label: str = "") -> Iterable[SecocProfile]:
        for (did, did_b, did_e, fb, fe, mb, mt, mo, fo, tf, pb, pt) in itertools.product(
                self.data_ids, self.data_id_bytes, self.data_id_endians,
                self.freshness_bytes, self.freshness_endians, self.mac_bits,
                self.mac_takes, self.mac_orders, self.frame_orders,
                self.trunc_freshness_bytes, self.pad_bytes, self.pad_to):
            # consistency guards: token/width combinations that cannot work
            if "trunc_freshness" in mo and tf == 0:
                continue
            if tf and "trunc_freshness" not in fo:
                continue
            if "dataid" in mo and did_b * 8 < did.bit_length():
                continue
            if (mb + 7) // 8 >= pt:
                continue
            if did >= (1 << (8 * did_b)):
                continue
            try:
                yield SecocProfile(
                    key=key, data_id=did, data_id_bytes=did_b,
                    data_id_endian=did_e, freshness_bytes=fb,
                    freshness_endian=fe, mac_bits=mb, mac_take=mt,
                    mac_order=mo, frame_order=fo,
                    trunc_freshness_bytes=tf, pad_byte=pb, pad_to=pt,
                    label=label)
            except ValueError:
                continue

    def size(self) -> int:
        return sum(1 for _ in self.profiles(b"\x00" * 16))


@dataclass
class CrackResult:
    profile: SecocProfile
    frames_checked: int
    elapsed: float

    def as_dict(self) -> dict:
        d = self.profile.as_dict()
        d["frames_checked"] = self.frames_checked
        d["elapsed_s"] = round(self.elapsed, 3)
        d["describe"] = self.profile.describe()
        return d


def crack(captures: Sequence[Capture], key: bytes,
          space: Optional[SearchSpace] = None,
          max_hits: int = 8, progress_every: int = 20000,
          verbose: bool = False) -> list:
    """Recover every profile that reproduces all captures byte-for-byte."""
    if not captures:
        raise ValueError("need at least one capture")
    for cap in captures:
        if len(cap.secured) != len(captures[0].secured):
            raise ValueError("all captures must have the same secured length")
    space = space or SearchSpace()
    hits: list = []
    t0 = time.perf_counter()
    n = 0
    for prof in space.profiles(key, label="candidate"):
        n += 1
        if progress_every and n % progress_every == 0:
            print(f"    ... {n} profiles, {len(hits)} hit(s), "
                  f"{time.perf_counter() - t0:.1f}s", flush=True)
        ok = True
        for cap in captures:
            if not prof.matches(cap.secured, cap.payload, cap.freshness):
                ok = False
                break
        if ok:
            hits.append(CrackResult(prof, len(captures),
                                    time.perf_counter() - t0))
            if verbose:
                print(f"    HIT {prof.describe()}")
            if len(hits) >= max_hits:
                break
    return hits


# --------------------------------------------------------------------------- #
# CAN FD framing
# --------------------------------------------------------------------------- #

def to_canfd_frame(secured: bytes, can_id: int, brs: bool = True):
    """Wrap a secured PDU as a CAN FD frame (import isotp lazily, no cycle)."""
    import isotp
    if len(secured) not in isotp.CANFD_DL:
        raise ValueError(f"{len(secured)} B is not a legal CAN FD data length")
    return isotp.Frame(can_id=can_id, data=bytes(secured), brs=brs, fd=True)


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


RFC4493 = [
    ("", "bb1d6929e95937287fa37d129b756746"),
    ("6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"),
    ("6bc1bee22e409f96e93d7e117393172a"
     "ae2d8a571e03ac9c9eb76fac45af8e51"
     "30c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"),
    ("6bc1bee22e409f96e93d7e117393172a"
     "ae2d8a571e03ac9c9eb76fac45af8e51"
     "30c81c46a35ce411e5fbc1191a0a52ef"
     "f69f2445df4f9b17ad2b417be66c3710", "51f0bebf7e3b9d92fc49741779363cfe"),
]


def _t_rfc4493(res: _Res) -> None:
    print("\n[1] AES-CMAC RFC 4493 test vectors")
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    for i, (msg_hex, want) in enumerate(RFC4493):
        got = aes_cmac(key, bytes.fromhex(msg_hex)).hex()
        res.check(f"RFC4493 vector {i} ({len(msg_hex) // 2} B)", got == want,
                  f"{got}")


def _t_truncation(res: _Res) -> None:
    print("\n[2] MAC truncation")
    key = bytes(range(16))
    mac = aes_cmac(key, b"payload")
    for bits in (24, 28, 32, 64):
        t = truncate_mac(mac, bits)
        ok = len(t) == (bits + 7) // 8
        if bits % 8:  # non-aligned: the unused low bits must be zeroed
            ok = ok and (t[-1] & ((1 << (len(t) * 8 - bits)) - 1)) == 0
        res.check(f"truncate {bits} bit", ok, f"{t.hex()} ({len(t)} B)")
    res.check("msb vs lsb differ",
              truncate_mac(mac, 24, "msb") != truncate_mac(mac, 24, "lsb"),
              "ok")


def _synthetic_profile() -> SecocProfile:
    """The 'hidden' OEM profile the cracker must recover."""
    return SecocProfile(
        key=bytes.fromhex("00112233445566778899aabbccddeeff"),
        data_id=0x0A1B, data_id_bytes=2, data_id_endian="big",
        freshness_bytes=8, freshness_endian="big",
        mac_bits=24, mac_take="msb",
        mac_order=("dataid", "payload", "freshness"),
        frame_order=("payload", "mac"),
        trunc_freshness_bytes=0, pad_byte=0xCC, pad_to=16)


def _t_build_verify(res: _Res) -> None:
    print("\n[3] build / verify a 16-byte CAN FD control frame")
    prof = _synthetic_profile()
    payload = bytes.fromhex("0322f190")
    fresh = 0x1122334455667788
    frame = prof.build(payload, fresh)
    res.check("frame is 16 bytes", len(frame) == 16, f"{len(frame)} B")
    res.check("payload carried verbatim", frame[:4] == payload, frame.hex())
    res.check("padding is 0xCC", set(frame[7:13]) == {0xCC}, frame[7:13].hex())
    res.check("MAC is the last 3 bytes", len(frame[-3:]) == 3, frame[-3:].hex())
    res.check("verify() accepts the frame", prof.verify(frame, payload, fresh))
    res.check("verify() rejects wrong freshness",
              not prof.verify(frame, payload, fresh + 1))
    res.check("verify() rejects wrong payload",
              not prof.verify(frame, bytes.fromhex("0322f191"), fresh))
    other = replace(prof, key=bytes(16))
    res.check("verify() rejects wrong key", not other.verify(frame, payload, fresh))

    # MAC must actually be the CMAC, not something else
    want = truncate_mac(aes_cmac(prof.key,
                                 prof.data_id_bytes_value() + payload +
                                 fresh.to_bytes(8, "big")), 24)
    res.check("MAC equals CMAC(DataID||payload||freshness) truncated",
              frame[-3:] == want, frame[-3:].hex())

    # CAN FD wrap keeps BRS
    fr = to_canfd_frame(frame, 0x7E1, brs=True)
    res.check("CAN FD frame carries BRS + 16 B",
              fr.brs and fr.fd and len(fr.data) == 16 and fr.can_id == 0x7E1,
              repr(fr))


def _t_orders(res: _Res) -> None:
    print("\n[4] alternative profiles build distinct frames")
    payload = bytes.fromhex("0102")
    fresh = 0x01
    variants = [
        ("canonical", SecocProfile(key=bytes(16), data_id=1,
                                   mac_order=("dataid", "payload", "freshness"),
                                   frame_order=("payload", "mac"))),
        ("mac first", SecocProfile(key=bytes(16), data_id=1,
                                   mac_order=("dataid", "payload", "freshness"),
                                   frame_order=("mac", "payload"))),
        ("truncFV prefix", SecocProfile(key=bytes(16), data_id=1,
                                        trunc_freshness_bytes=2,
                                        frame_order=("trunc_freshness",
                                                     "payload", "mac"))),
        ("mac 32 lsb", SecocProfile(key=bytes(16), data_id=1, mac_bits=32,
                                    mac_take="lsb")),
        ("freshness first", SecocProfile(key=bytes(16), data_id=1,
                                         mac_order=("freshness", "payload",
                                                    "dataid"))),
    ]
    frames = {}
    for name, prof in variants:
        frames[name] = prof.build(payload, fresh)
        res.check(f"{name}: 16 B", len(frames[name]) == 16,
                  frames[name].hex())
    res.check("all variants differ pairwise",
              len(set(frames.values())) == len(frames),
              f"{len(set(frames.values()))} distinct")


def _t_crack(res: _Res) -> None:
    print("\n[5] crack(): recover a hidden profile from captures")
    hidden = _synthetic_profile()
    payloads = [bytes.fromhex("0322f190"), bytes.fromhex("0322f190")]
    captures = [
        Capture(payload=payloads[0], freshness=0x0000000000000100,
                secured=hidden.build(payloads[0], 0x0000000000000100),
                can_id=0x7E0),
        Capture(payload=payloads[1], freshness=0x0000000000000101,
                secured=hidden.build(payloads[1], 0x0000000000000101),
                can_id=0x7E0),
        Capture(payload=payloads[1], freshness=0x0000000000000102,
                secured=hidden.build(payloads[1], 0x0000000000000102),
                can_id=0x7E0),
    ]
    space = SearchSpace(
        data_ids=[0x0A1B, 0x0A1C, 0x1234],
        data_id_bytes=(2,), data_id_endians=("big",),
        freshness_bytes=(8,), freshness_endians=("big",),
        mac_bits=(24,), mac_takes=("msb",),
        mac_orders=(("dataid", "payload", "freshness"),
                    ("payload", "dataid", "freshness")),
        frame_orders=(("payload", "mac"),),
        trunc_freshness_bytes=(0,), pad_bytes=(0xCC,), pad_to=(16,))
    print(f"  grid size: {space.size()} profiles")
    hits = crack(captures, hidden.key, space, verbose=False)
    res.check("exactly one profile survives", len(hits) == 1,
              f"{len(hits)} hit(s)")
    if hits:
        got = hits[0].profile
        res.check("recovered DataID", got.data_id == hidden.data_id,
                  f"0x{got.data_id:04X}")
        res.check("recovered MAC bits", got.mac_bits == hidden.mac_bits,
                  str(got.mac_bits))
        res.check("recovered mac_order", got.mac_order == hidden.mac_order,
                  "|".join(got.mac_order))
        res.check("recovered frame_order", got.frame_order == hidden.frame_order,
                  "|".join(got.frame_order))
        res.check("recovered profile reproduces all frames",
                  all(got.build(c.payload, c.freshness) == c.secured
                      for c in captures), "3/3")

    # Frame bytes alone do not pin down parameters the MAC never covers.
    # Here the payload fills the whole payload field, so no filler byte is
    # emitted and every candidate pad_byte reproduces the same frames.
    full = bytes(13)  # 16 - 3 (24-bit MAC) => payload field fully occupied
    caps_full = [Capture(payload=full, freshness=0x200 + i,
                         secured=hidden.build(full, 0x200 + i))
                 for i in range(2)]
    pad_space = SearchSpace(
        data_ids=[hidden.data_id], data_id_bytes=(2,), data_id_endians=("big",),
        freshness_bytes=(8,), freshness_endians=("big",),
        mac_bits=(24,), mac_takes=("msb",),
        mac_orders=(("dataid", "payload", "freshness"),),
        frame_orders=(("payload", "mac"),),
        trunc_freshness_bytes=(0,),
        pad_bytes=(0xCC, 0x00, 0xAA, 0xFF), pad_to=(16,))
    hits_pad = crack(caps_full, hidden.key, pad_space, max_hits=8)
    res.check("unused filler byte stays ambiguous (MAC does not cover it)",
              len(hits_pad) == 4,
              f"{len(hits_pad)} hits for 4 candidate fillers")
    res.check("ambiguous hits differ only in pad_byte",
              len({(h.profile.data_id, h.profile.mac_bits,
                    h.profile.frame_order) for h in hits_pad}) == 1,
              "one (DataID, MAC, layout) tuple")

    # wrong key must yield nothing
    hits_bad = crack(captures, bytes(16), space, max_hits=1)
    res.check("wrong key yields no hit", len(hits_bad) == 0,
              f"{len(hits_bad)} hit(s)")


def _t_wide_grid(res: _Res) -> None:
    print("\n[6] wide grid: truncated freshness + 32-bit MAC + little endian")
    hidden = SecocProfile(
        key=bytes.fromhex("ffeeddccbbaa99887766554433221100"),
        data_id=0x0E00, data_id_bytes=2, data_id_endian="little",
        freshness_bytes=8, freshness_endian="little",
        mac_bits=32, mac_take="msb",
        mac_order=("freshness", "payload", "dataid"),
        frame_order=("trunc_freshness", "payload", "mac"),
        trunc_freshness_bytes=2, pad_byte=0xAA, pad_to=20)
    payload = bytes.fromhex("2e0a1b01")
    caps = [Capture(payload=payload, freshness=0x100 + i,
                    secured=hidden.build(payload, 0x100 + i))
            for i in range(3)]
    space = SearchSpace(
        data_ids=[0x0E00], data_id_bytes=(2,),
        data_id_endians=("little", "big"),
        freshness_bytes=(8,), freshness_endians=("little", "big"),
        mac_bits=(32,), mac_takes=("msb",),
        mac_orders=(("freshness", "payload", "dataid"),
                    ("dataid", "payload", "freshness")),
        frame_orders=(("trunc_freshness", "payload", "mac"),
                      ("payload", "mac")),
        trunc_freshness_bytes=(2, 0), pad_bytes=(0xAA,), pad_to=(20,))
    print(f"  grid size: {space.size()} profiles")
    hits = crack(caps, hidden.key, space)
    res.check("wide grid finds exactly one", len(hits) == 1, f"{len(hits)}")
    if hits:
        got = hits[0].profile
        res.check("wide grid recovered trunc_freshness_bytes",
                  got.trunc_freshness_bytes == 2,
                  str(got.trunc_freshness_bytes))
        res.check("wide grid recovered little-endian DataID",
                  got.data_id_endian == "little", got.data_id_endian)
        res.check("wide grid recovered pad_to=20", got.pad_to == 20,
                  str(got.pad_to))
        res.check("wide grid recovered 32-bit MAC", got.mac_bits == 32,
                  str(got.mac_bits))


def _t_freshness_counter(res: _Res) -> None:
    print("\n[7] freshness counter")
    c = FreshnessCounter(0xFFFFFFFFFFFFFFFE)
    res.check("peek does not advance", c.peek() == 0xFFFFFFFFFFFFFFFE)
    c.next()
    c.next()
    res.check("wrap at 64 bits", c.value == 0, f"0x{c.value:016X}")
    c.resync(5)
    res.check("resync", c.peek() == 5)


def self_test(evidence_dir: Optional[str] = None) -> int:
    print("=" * 78)
    print("SecOC (AUTOSAR-style) authenticator + profile cracker self-test")
    print("=" * 78)
    res = _Res()
    t0 = time.time()
    _t_rfc4493(res)
    _t_truncation(res)
    _t_build_verify(res)
    _t_orders(res)
    _t_crack(res)
    _t_wide_grid(res)
    _t_freshness_counter(res)
    passed = sum(1 for r in res.rows if r["ok"])
    total = len(res.rows)
    print("\n" + "=" * 78)
    print(f"RESULT: {passed}/{total} checks passed "
          f"({'OK' if res.ok else 'FAILURES'}) in {time.time() - t0:.1f}s")
    print("=" * 78)
    if evidence_dir:
        os.makedirs(evidence_dir, exist_ok=True)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        base = os.path.join(evidence_dir, "01_selftest_secoc")
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump({"tool": "secoc.py", "ts": stamp, "passed": passed,
                       "total": total, "ok": res.ok, "checks": res.rows},
                      f, indent=2, ensure_ascii=False)
        with open(base + ".log", "w", encoding="utf-8") as f:
            f.write(f"# secoc.py self-test {stamp}\n")
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

def _parse_int(text: str) -> int:
    return int(str(text), 0)


def cmd_spec(args) -> int:
    prof = SecocProfile(
        key=bytes.fromhex(args.key),
        data_id=_parse_int(args.dataid),
        data_id_bytes=args.dataid_bytes,
        data_id_endian=args.dataid_endian,
        freshness_bytes=args.freshness_bytes,
        freshness_endian=args.freshness_endian,
        mac_bits=args.mac_bits,
        mac_take=args.mac_take,
        mac_order=tuple(args.mac_order.split(",")),
        frame_order=tuple(args.frame_order.split(",")),
        trunc_freshness_bytes=args.trunc_freshness_bytes,
        pad_byte=_parse_int(args.pad_byte),
        pad_to=args.pad_to,
    )
    payload = bytes.fromhex(args.payload.replace(" ", "").replace(":", ""))
    fresh = _parse_int(args.freshness)
    frame = prof.build(payload, fresh)
    out = {"profile": prof.as_dict(), "describe": prof.describe(),
           "payload": payload.hex(), "freshness": f"0x{fresh:016X}",
           "mac_input": prof.mac_input(payload, fresh).hex(),
           "cmac_full": prof.mac(payload, fresh).hex(),
           "authenticator": prof.authenticator(payload, fresh).hex(),
           "secured": frame.hex(), "secured_spaced": " ".join(f"{b:02X}" for b in frame),
           "canfd": {"can_id": args.can_id, "brs": True, "dl": len(frame)}}
    print(json.dumps(out, indent=2))
    return 0


def cmd_crack(args) -> int:
    with open(args.crack, "r", encoding="utf-8") as f:
        doc = json.load(f)
    caps = [Capture.from_dict(d) for d in doc["captures"]]
    keys = [bytes.fromhex(args.key)] if args.key else [
        bytes.fromhex(k) for k in doc.get("keys", [])]
    if not keys:
        raise SystemExit("no key: pass --key or put a 'keys' list in the file")
    space = SearchSpace()
    if args.dataid:
        dids = []
        for part in args.dataid.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-")
                dids.extend(range(_parse_int(a), _parse_int(b) + 1))
            else:
                dids.append(_parse_int(part))
        space.data_ids = dids
    if args.dataid_bytes:
        space.data_id_bytes = tuple(int(x) for x in args.dataid_bytes.split(","))
    if args.mac_bits:
        space.mac_bits = tuple(int(x) for x in args.mac_bits.split(","))
    if args.pad_to:
        space.pad_to = tuple(int(x) for x in args.pad_to.split(","))
    print(f"grid size: {space.size()} profiles x {len(keys)} key(s)")
    all_hits = []
    for key in keys:
        hits = crack(caps, key, space, max_hits=args.max_hits,
                     progress_every=args.progress_every)
        for h in hits:
            all_hits.append(h)
            print(f"HIT key={key.hex()} {h.profile.describe()}")
    print(json.dumps({"hits": [h.as_dict() for h in all_hits]}, indent=2))
    return 0 if all_hits else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SecOC authenticator + cracker")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--rfc4493", action="store_true")
    ap.add_argument("--evidence-dir", default=None)
    ap.add_argument("--spec", action="store_true")
    ap.add_argument("--crack", default=None)
    ap.add_argument("--key", default=None)
    ap.add_argument("--dataid", default="0x0000")
    ap.add_argument("--dataid-bytes", type=int, default=2)
    ap.add_argument("--dataid-endian", default="big")
    ap.add_argument("--freshness", default="0")
    ap.add_argument("--freshness-bytes", type=int, default=8)
    ap.add_argument("--freshness-endian", default="big")
    ap.add_argument("--mac-bits", default=None)
    ap.add_argument("--mac-take", default="msb")
    ap.add_argument("--mac-order", default="dataid,payload,freshness")
    ap.add_argument("--frame-order", default="payload,mac")
    ap.add_argument("--trunc-freshness-bytes", type=int, default=0)
    ap.add_argument("--pad-byte", default="0xCC")
    ap.add_argument("--pad-to", default=None)
    ap.add_argument("--payload", default="")
    ap.add_argument("--can-id", default="0x7E0")
    ap.add_argument("--max-hits", type=int, default=8)
    ap.add_argument("--progress-every", type=int, default=20000)
    args = ap.parse_args(argv)

    if args.rfc4493:
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        for msg_hex, want in RFC4493:
            got = aes_cmac(key, bytes.fromhex(msg_hex)).hex()
            print(f"{len(msg_hex) // 2:>2} B  {got}  "
                  f"{'OK' if got == want else 'MISMATCH want ' + want}")
        return 0
    if args.self_test:
        return self_test(args.evidence_dir)
    if args.crack:
        return cmd_crack(args)
    if args.spec:
        # argparse gives str defaults; coerce where the builder needs ints
        args.mac_bits = int(args.mac_bits) if args.mac_bits else 24
        args.pad_to = int(args.pad_to) if args.pad_to else 16
        return cmd_spec(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

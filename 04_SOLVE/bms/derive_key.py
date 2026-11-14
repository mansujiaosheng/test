#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""derive_key.py -- 赛题 08「派生密钥并解锁 VCU 编程会话」离线密码学骨架

目标：拿到 BMS 固件的那一刻，一条命令算出 VCU 二级 SecurityAccess key 的**全部候选**。

设计原则
--------
1. 只用 stdlib（hashlib / hmac / struct / json / argparse）。AES-128 与 CMAC 用纯
   Python 实现并用 RFC 4493 自校验，所以没有 pycryptodome 也能跑。
2. 不猜、不省：root key / salt / info / 最终 key 四层候选**全部输出**，每个候选有
   稳定名字（RK2/S1/I1/K1），拿到 VCU 后逐条试即可。
3. RFC 5869 严格实现（T(0)=空、counter 从 1 起、L <= 255*HashLen 校验），并用
   RFC 5869 Test Case 1/2/3 自校验；self-test 不过就非 0 退出。
4. 没有结构就**不编结构**：识别不出 header 时 S2/S3 直接跳过并在输出里说明，
   只用明确标注 [spec] 的猜测候选补位。

用法
----
    python derive_key.py --self-test
    python derive_key.py --firmware bms.bin --vin CV6FF52FEE9EDDD86
    python derive_key.py --firmware bms.bin --vin CV6FF52FEE9EDDD86 --seed 11223344
    python derive_key.py --firmware bms.bin --vin CV6FF52FEE9EDDD86 --seed 11223344 --uds
    python derive_key.py --firmware bms.bin --vin CV6FF52FEE9EDDD86 --seed 11223344 --out cand.json --fmt json
    python derive_key.py --firmware bms.bin --vin CV6FF52FEE9EDDD86 --rootkey <64hex> --seed 11223344

候选命名（拿到 VCU 后按名字逐条试）
-----------------------------------
    RK1  用户 --rootkey 显式给定
    RK2  固件里第一个 >=16 字节高熵常量（自动延伸到 32/64 字节）
    RK3  固件尾部 32 字节
    RK4  SHA256(entire firmware) 本身
    RK5  'ROOT_KEY'/'rootkey'/'RK' 等字符串之后的 32 字节（RK5/RK5b/RK5c...）
    S1   SHA256(entire file)                 <- 首选（"完整镜像摘要"的字面解读）
    S2   SHA256(payload)，payload = data[header_len:]
    S2b  SHA256(payload 去掉签名尾块)
    S3   SHA256(header)
    S4_* 未识别 header 时按常见 header 长度剥离的猜测候选 [spec]
    I1   VIN ASCII（线上实测字节）
    I2   VIN 第 10 位小写（题述变体）
    I3   VIN 去尾部 NUL/空格
    I4   b"VCU"
    I5   b""（空 info）
    K1   HMAC-SHA256(dv32, seed)                     <- 首选（"二级 SecurityAccess HMAC"字面）
    K2   HMAC-SHA256(dv32, seed || 0x0000)
    K3   AES-CMAC(dv16, seed)                        <- UDS 经典实现
    K4   K1[:len(seed)]                              <- 标准 UDS：key_len == seed_len
    K1_4 / K1_8 / K1_16  显式截断形式

注意：HKDF-Expand(L=16) 的结果恒等于 HKDF-Expand(L=32)[:16]（OKM 是前缀），
所以 dv16 不是独立自由度，脚本会校验这一点而不是当两个候选。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import struct
import sys
from collections import Counter

VERSION = "1.0"
HASH = hashlib.sha256
HASH_LEN = 32

# 已在 DoIP 侧实测到的车辆标识符（03_EVIDENCE/cgw/0001_ident.json 与
# 03_EVIDENCE/cgw-doip/E-cgw-uds-vin-01.txt 双重确认）。仅作 --wide 时的补充 info 候选。
KNOWN_IDENTIFIERS = [
    ("VIN", "CV6FF52FEE9EDDD86",
     "DoIP 0x0001 vehicle announcement + UDS 22 F1 90，两路独立一致"),
    ("EID", "060000001000", "DoIP 0x0004 实体标识"),
    ("GID", "000000000000", "DoIP 0x0004 组标识"),
    ("LA_CGW", "1000", "DoIP 逻辑地址 0x1000（CGW 实体，非 VCU）"),
]


# --------------------------------------------------------------------------- #
# AES-128（纯 Python，仅 encrypt；CMAC 只需要 encrypt）
# --------------------------------------------------------------------------- #

def _gmul(a: int, b: int) -> int:
    """GF(2^8) 乘法，不可约多项式 0x11B。"""
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r & 0xFF


def _rotl8(x: int, s: int) -> int:
    return ((x << s) | (x >> (8 - s))) & 0xFF


def _build_sbox():
    """由 GF(2^8) 逆元 + 仿射变换现场生成 S-box（避免抄 256 个常量抄错）。"""
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inv[a] = b
                break
    out = []
    for a in range(256):
        b = inv[a]
        s = b ^ _rotl8(b, 1) ^ _rotl8(b, 2) ^ _rotl8(b, 3) ^ _rotl8(b, 4) ^ 0x63
        out.append(s & 0xFF)
    return out


_SBOX = _build_sbox()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _expand_key_128(key: bytes):
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes, got %d" % len(key))
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[x] for x in t]
            t[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    rounds = []
    for r in range(11):
        flat = []
        for k in range(4):
            flat.extend(w[4 * r + k])
        rounds.append(flat)
    return rounds


def _add_round_key(s, rk):
    for i in range(16):
        s[i] ^= rk[i]


def _sub_bytes(s):
    for i in range(16):
        s[i] = _SBOX[s[i]]


def _shift_rows(s):
    # state 按列主序：s[r + 4c]
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out


def _mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
        out[4 * c + 0] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        out[4 * c + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        out[4 * c + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        out[4 * c + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)
    return out


def aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes, got %d" % len(block))
    rk = _expand_key_128(key)
    s = list(block)
    _add_round_key(s, rk[0])
    for r in range(1, 10):
        _sub_bytes(s)
        s = _shift_rows(s)
        s = _mix_columns(s)
        _add_round_key(s, rk[r])
    _sub_bytes(s)
    s = _shift_rows(s)
    _add_round_key(s, rk[10])
    return bytes(s)


_RB = 0x87


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _shift_left1(b: bytes) -> bytes:
    out = bytearray(len(b))
    carry = 0
    for i in range(len(b) - 1, -1, -1):
        out[i] = ((b[i] << 1) | carry) & 0xFF
        carry = (b[i] >> 7) & 1
    return bytes(out)


def _cmac_subkeys(key: bytes):
    big_l = aes128_encrypt_block(key, b"\x00" * 16)
    k1 = _shift_left1(big_l)
    if big_l[0] & 0x80:
        k1 = _xor(k1, b"\x00" * 15 + bytes([_RB]))
    k2 = _shift_left1(k1)
    if k1[0] & 0x80:
        k2 = _xor(k2, b"\x00" * 15 + bytes([_RB]))
    return k1, k2


def aes_cmac(key: bytes, msg: bytes) -> bytes:
    """RFC 4493 AES-CMAC（AES-128，key 16 字节）。"""
    if len(key) != 16:
        raise ValueError("CMAC key must be 16 bytes (AES-128), got %d" % len(key))
    k1, k2 = _cmac_subkeys(key)
    n = (len(msg) + 15) // 16
    if n == 0:
        n = 1
        complete = False
    else:
        complete = (len(msg) % 16 == 0)
    if complete:
        last = _xor(msg[(n - 1) * 16:n * 16], k1)
    else:
        tail = msg[(n - 1) * 16:]
        last = _xor(tail + b"\x80" + b"\x00" * (15 - len(tail)), k2)
    x = b"\x00" * 16
    for i in range(n - 1):
        x = aes128_encrypt_block(key, _xor(x, msg[i * 16:(i + 1) * 16]))
    return aes128_encrypt_block(key, _xor(x, last))


# --------------------------------------------------------------------------- #
# HKDF-SHA256（RFC 5869，严格实现）
# --------------------------------------------------------------------------- #

def hkdf_extract(salt, ikm: bytes) -> bytes:
    if salt is None:
        salt = b"\x00" * HASH_LEN
    return hmac.new(salt, ikm, HASH).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length < 0:
        raise ValueError("negative L")
    if length > 255 * HASH_LEN:
        raise ValueError("L too large (max 255*HashLen = %d)" % (255 * HASH_LEN))
    okm = b""
    t = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), HASH).digest()
        okm += t
        i += 1
    return okm[:length]


def hkdf(ikm: bytes, salt, info: bytes, length: int) -> bytes:
    """HKDF-SHA256(ikm, salt, info, L)。salt=None 按 RFC 5869 视作 HashLen 个零。"""
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


# --------------------------------------------------------------------------- #
# 熵 / 常量搜索
# --------------------------------------------------------------------------- #

def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in Counter(data).values())


def max_entropy(size: int) -> float:
    return math.log2(min(size, 256))


def is_high_entropy(win: bytes, ratio: float = 0.90, allow_printable: bool = False) -> bool:
    if not win:
        return False
    if shannon(win) < ratio * max_entropy(len(win)):
        return False
    if len(set(win)) < max(2, int(len(win) * 0.60)):
        return False
    if not allow_printable:
        printable = sum(1 for b in win if 0x20 <= b < 0x7F)
        if printable == len(win):
            return False
    return True


def find_constants(data: bytes, size: int, ratio: float = 0.90,
                   step: int = 4, limit=None, allow_printable: bool = False):
    """贪心找高熵定长常量：命中后跳过整个窗口，避免同一常量滚出上百个副本。"""
    res = []
    n = len(data)
    i = 0
    while i + size <= n:
        win = data[i:i + size]
        if is_high_entropy(win, ratio, allow_printable):
            res.append({"offset": i, "value": win, "entropy": shannon(win)})
            i += size
            if limit and len(res) >= limit:
                break
        else:
            i += step
    return res


def grow_constant(data: bytes, pos: int, ratio: float = 0.90,
                  sizes=(16, 20, 24, 28, 32, 40, 48, 56, 64)) -> int:
    best = 0
    for length in sizes:
        if pos + length <= len(data) and is_high_entropy(data[pos:pos + length], ratio):
            best = length
    return best or sizes[0]


# --------------------------------------------------------------------------- #
# 固件结构探测："完整镜像" vs "payload" 的分界
# --------------------------------------------------------------------------- #

def probe_structure(data: bytes) -> dict:
    """探测 magic / length 字段 / 签名尾块。

    识别不出结构就返回 header_len=None 并说明原因，**不编造**切分点。
    打分规则（关键）：一个 (header_len, len_value) 解释如果能自洽地铺满整个文件，
    才是可信的 —— 即 len 字段描述的 payload 紧接 header 之后，且余下部分要么为空、
    要么正好等于探测到的签名尾块长度。仅靠"最小 header_len"会在带 reserved 填充的
    header 上把填充算进 payload（self-test 用例 B 就是钉这一点）。
    """
    n = len(data)
    out = {
        "magic": None, "magic_len": 0, "header_len": None, "trailer_len": 0,
        "header": None, "payload": None, "structs": [], "notes": [],
    }

    # --- 1) 先探签名/摘要尾块（header 打分要用到它） ---
    for tlen in (256, 128, 64):
        if n - tlen > 64 and is_high_entropy(data[-tlen:], 0.88, True):
            out["trailer_len"] = tlen
            out["notes"].append("尾部 %d 字节高熵（%.2f bit/B）→ 疑似签名/摘要尾块"
                                % (tlen, shannon(data[-tlen:])))
            break

    # --- 2) leading magic ---
    i = 0
    while i < min(n, 16) and 0x20 <= data[i] < 0x7F:
        i += 1
    magic_len = i if 4 <= i <= 16 else 0
    if not magic_len:
        out["notes"].append(
            "未识别到 leading magic（前 16 字节内没有 4..16 字节可打印 ASCII 头）"
            "→ S2/S3 不做结构切分，改用 [spec] 猜测候选")
        return out

    out["magic"] = data[:magic_len]
    out["magic_len"] = magic_len
    found = []
    for off in (magic_len, magic_len + 2, magic_len + 4, magic_len + 8, magic_len + 12):
        if off + 4 > n:
            continue
        for endian, tag in (("<I", "LE"), (">I", "BE")):
            val = struct.unpack_from(endian, data, off)[0]
            if 16 <= val <= n:
                hl = off + 4
                if hl < n:
                    found.append({"header_len": hl, "len_off": off,
                                  "len_value": val, "endian": tag})
    seen = set()
    uniq = []
    for f in found:
        key = (f["header_len"], f["len_value"], f["endian"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    out["notes"].append("leading magic=%r (len=%d)，可解释的 length 字段 %d 个"
                        % (out["magic"], magic_len, len(uniq)))
    if not uniq:
        out["notes"].append("length 字段不可解释 → 不做结构切分")
        return out

    tl = out["trailer_len"]

    def score(f):
        hl, val = f["header_len"], f["len_value"]
        if hl + val == n:
            return 2
        if tl and hl + val + tl == n:
            return 1
        return 0

    for f in uniq:
        f["score"] = score(f)
    out["structs"] = uniq
    best = max(f["score"] for f in uniq)
    if best > 0:
        pool = [f for f in uniq if f["score"] == best]
        prim = min(pool, key=lambda f: f["header_len"])
    else:
        out["notes"].append("没有任何 length 解释能铺满文件 → 退回最小 header_len（保守，可能偏低）")
        prim = min(uniq, key=lambda f: (f["header_len"],
                                        abs(f["len_value"] - (n - f["header_len"]))))
    out["header_len"] = prim["header_len"]
    out["header"] = data[:prim["header_len"]]
    out["payload"] = data[prim["header_len"]:]
    out["notes"].append(
        "主解：header_len=%d（length 字段 @0x%x = %d %s，score=%d）"
        % (prim["header_len"], prim["len_off"], prim["len_value"],
           prim["endian"], prim["score"]))
    return out


# --------------------------------------------------------------------------- #
# 四层候选
# --------------------------------------------------------------------------- #

def rootkey_candidates(data: bytes, explicit=None, limit: int = 3):
    cands = []
    if explicit:
        note = "用户显式给定"
        if len(explicit) not in (16, 32):
            note += "（长度 %d，HKDF 允许任意长度但通常 16/32）" % len(explicit)
        cands.append({"name": "RK1", "value": explicit,
                      "src": "--rootkey", "note": note})

    wins = find_constants(data, 16, ratio=0.90, step=4, limit=1)
    if wins:
        w = wins[0]
        length = grow_constant(data, w["offset"])
        val = data[w["offset"]:w["offset"] + length]
        cands.append({
            "name": "RK2", "value": val,
            "src": "首个高熵常量 @0x%x，自动延伸至 %d 字节（熵 %.2f/%.2f bit/B）"
                   % (w["offset"], length, shannon(val), max_entropy(length)),
            "note": "first >=16B high-entropy constant"})

    if len(data) >= 32:
        tail = data[-32:]
        cands.append({"name": "RK3", "value": tail,
                      "src": "固件尾部 32 字节",
                      "note": "若尾部是签名/摘要，则这是错误候选（熵 %.2f）" % shannon(tail)})

    cands.append({"name": "RK4", "value": HASH(data).digest(),
                  "src": "SHA256(entire firmware)",
                  "note": "自指候选：镜像摘要即 root key 的不寻常设计"})

    needles = [b"ROOT_KEY", b"root_key", b"RootKey", b"rootkey", b"ROOTKEY", b"RK"]
    hits = 0
    seen_vals = set()
    for nd in needles:
        start = 0
        while True:
            p = data.find(nd, start)
            if p < 0:
                break
            s = p + len(nd)
            if s + 32 <= len(data):
                val = data[s:s + 32]
                if val != b"\x00" * 32 and val not in seen_vals:
                    seen_vals.add(val)
                    nm = "RK5" if hits == 0 else "RK5" + chr(ord("a") + hits)
                    cands.append({"name": nm, "value": val,
                                  "src": "%r @0x%x 之后 32 字节" % (nd.decode(), p),
                                  "note": "字符串邻近常量"})
                    hits += 1
                    if hits >= limit:
                        return cands
            start = p + 1
    return cands


def salt_candidates(data: bytes, struct_info: dict, wide: bool = False):
    out = [{"name": "S1", "value": HASH(data).digest(),
            "src": "SHA256(entire file)",
            "note": "首选：含 header 与签名尾块（\"完整镜像摘要\"字面）", "spec": False}]
    hl = struct_info.get("header_len")
    tl = struct_info.get("trailer_len") or 0
    if hl:
        out.append({"name": "S2", "value": HASH(data[hl:]).digest(),
                    "src": "SHA256(payload) = SHA256(data[%d:])" % hl,
                    "note": "剥掉 header 后的全部内容（仍含尾块）", "spec": False})
        if tl and hl < len(data) - tl:
            out.append({"name": "S2b", "value": HASH(data[hl:len(data) - tl]).digest(),
                        "src": "SHA256(data[%d:%d])" % (hl, len(data) - tl),
                        "note": "payload 去掉 %d 字节签名尾块 → 纯 payload 摘要" % tl,
                        "spec": False})
        # 若 header 在 length 字段之后还有 reserved/对齐填充，length 字段无法把它和
        # payload 前导零区分开（结构探测会保守地把填充算进 payload）。此时用 S2z 补位。
        payload = data[hl:]
        zrun = 0
        while zrun < min(len(payload), 64) and payload[zrun] == 0:
            zrun += 1
        if zrun >= 4:
            end = len(data) - tl if tl else len(data)
            if hl + zrun < end:
                out.append({"name": "S2z", "value": HASH(data[hl + zrun:end]).digest(),
                            "src": "SHA256(data[%d:%d])" % (hl + zrun, end),
                            "note": "payload 前置 %d 字节 0（疑似 header reserved 被算进 "
                                    "payload）→ 剥掉再摘要" % zrun,
                            "spec": True})
        out.append({"name": "S3", "value": HASH(data[:hl]).digest(),
                    "src": "SHA256(header) = SHA256(data[:%d])" % hl,
                    "note": "header 摘要", "spec": False})
    else:
        picks = (16, 32, 64, 128, 256) if wide else (64, 256)
        for k in picks:
            if k < len(data):
                out.append({"name": "S4_%d" % k, "value": HASH(data[k:]).digest(),
                            "src": "SHA256(data[%d:])" % k,
                            "note": "未识别 header，按常见 header 长度猜测剥离",
                            "spec": True})
    return out


def info_candidates(vin: str, wide: bool = False):
    v = vin.encode("ascii", "replace")
    mixed = (vin[:9] + vin[9].lower() + vin[10:]) if len(vin) > 9 else vin.lower()
    out = [
        {"name": "I1", "value": v, "src": "VIN ASCII %r" % vin, "spec": False,
         "note": "线上实测字节（DoIP 0x0001 + UDS 22 F1 90 双证）"},
        {"name": "I2", "value": mixed.encode("ascii", "replace"),
         "src": "VIN 第 10 位小写 %r" % mixed, "spec": False,
         "note": ("与 I1 相同（VIN 该位本来就是小写）" if mixed == vin
                  else "题述混合大小写变体；线上证据不支持，但保留以便逐条试")},
        {"name": "I3", "value": vin.strip("\x00 ").encode("ascii", "replace"),
         "src": "VIN 去尾部 NUL/空格", "spec": False,
         "note": "通常等同 I1"},
        {"name": "I4", "value": b"VCU", "src": "模块名 b\"VCU\"", "spec": False,
         "note": "若 info 是模块标识"},
        {"name": "I5", "value": b"", "src": "空 info", "spec": False,
         "note": "RFC 5869 允许 info 为空串"},
    ]
    if wide:
        for nm, hexval, src in KNOWN_IDENTIFIERS:
            if nm == "VIN":
                continue
            raw = bytes.fromhex(hexval)
            out.append({"name": "I_%s_hex" % nm, "value": raw,
                        "src": "%s 原始字节 (%s)" % (nm, src), "spec": True,
                        "note": "非 VIN 标识符，仅 --wide 时枚举"})
            out.append({"name": "I_%s_ascii" % nm, "value": hexval.encode(),
                        "src": "%s ASCII" % nm, "spec": True,
                        "note": "非 VIN 标识符，仅 --wide 时枚举"})
    return out


def key_candidates(dv32: bytes, seed: bytes):
    dv16 = dv32[:16]
    k1 = hmac.new(dv32, seed, HASH).digest()
    k2 = hmac.new(dv32, seed + b"\x00\x00", HASH).digest()
    k3 = aes_cmac(dv16, seed)
    return [
        {"name": "K1", "value": k1, "src": "HMAC-SHA256(dv32, seed)",
         "note": "首选：\"二级 SecurityAccess HMAC\"字面"},
        {"name": "K1_16", "value": k1[:16], "src": "K1[:16]", "note": "16B seed 场景"},
        {"name": "K1_8", "value": k1[:8], "src": "K1[:8]", "note": "8B seed 场景"},
        {"name": "K1_4", "value": k1[:4], "src": "K1[:4]", "note": "4B seed 场景（最常见）"},
        {"name": "K2", "value": k2, "src": "HMAC-SHA256(dv32, seed||0x0000)",
         "note": "带 2 字节 0 后缀变体"},
        {"name": "K2_4", "value": k2[:4], "src": "K2[:4]", "note": ""},
        {"name": "K3", "value": k3, "src": "AES-CMAC(dv16, seed)",
         "note": "UDS 经典实现"},
        {"name": "K3_4", "value": k3[:4], "src": "K3[:4]", "note": ""},
        {"name": "K4", "value": k1[:len(seed)],
         "src": "K1[:%d]（截断到 seed 长度）" % len(seed),
         "note": "标准 UDS：key_len == seed_len ← 首选（4B seed 时等同 K1_4）"},
    ]


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #

class TestFail(AssertionError):
    pass


def _eq(name, got, want):
    if got != want:
        raise TestFail("%s 不符\n  got  = %s\n  want = %s" % (name, got, want))


def run_self_test() -> int:
    results = []

    def check(label, fn):
        try:
            fn()
            results.append((label, "PASS", ""))
        except TestFail as e:
            results.append((label, "FAIL", str(e)))
        except Exception as e:  # noqa: BLE001
            results.append((label, "ERROR", "%s: %s" % (type(e).__name__, e)))

    # ---- 1. FIPS-197 AES-128 ----
    def t_aes():
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        want = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        _eq("FIPS-197 AES-128", aes128_encrypt_block(key, pt).hex(), want.hex())
    check("AES-128 encrypt (FIPS-197 C.1)", t_aes)

    # ---- 2. RFC 4493 AES-CMAC 四个向量 ----
    def t_cmac():
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        msg = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710")
        vec = [
            (0, "bb1d6929e95937287fa37d129b756746"),
            (16, "070a16b46b4d4144f79bdd9dd04a287c"),
            (40, "dfa66747de9ae63030ca32611497c827"),
            (64, "51f0bebf7e3b9d92fc49741779363cfe"),
        ]
        for n, want in vec:
            _eq("RFC 4493 CMAC len=%d" % n, aes_cmac(key, msg[:n]).hex(), want)
    check("AES-CMAC (RFC 4493)", t_cmac)

    # ---- 3. RFC 5869 Test Case 1（题面要求的硬闸门）----
    def t_hkdf1():
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        prk = hkdf_extract(salt, ikm)
        _eq("TC1 PRK", prk.hex(),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        okm = hkdf_expand(prk, info, 42)
        _eq("TC1 OKM", okm.hex(),
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865")
    check("HKDF-SHA256 (RFC 5869 TC1)", t_hkdf1)

    # ---- 4. RFC 5869 Test Case 2（长输入，覆盖多轮 expand）----
    def t_hkdf2():
        ikm = bytes(range(0x00, 0x50))
        salt = bytes(range(0x60, 0xB0))
        info = bytes(range(0xB0, 0x100))
        prk = hkdf_extract(salt, ikm)
        _eq("TC2 PRK", prk.hex(),
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
        okm = hkdf_expand(prk, info, 82)
        _eq("TC2 OKM", okm.hex(),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f1d87")
    check("HKDF-SHA256 (RFC 5869 TC2)", t_hkdf2)

    # ---- 5. RFC 5869 Test Case 3（零长 salt/info）----
    def t_hkdf3():
        ikm = bytes.fromhex("0b" * 22)
        prk = hkdf_extract(b"", ikm)
        _eq("TC3 PRK", prk.hex(),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
        okm = hkdf_expand(prk, b"", 42)
        _eq("TC3 OKM", okm.hex(),
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8")
        # salt=None 必须与 32 字节零 salt 等价（RFC 5869 §2.2）
        _eq("salt=None == 32x00", hkdf_extract(None, ikm).hex(), prk.hex())
    check("HKDF-SHA256 (RFC 5869 TC3 + salt=None 等价性)", t_hkdf3)

    # ---- 6. 前缀性质：L=16 是 L=32 的前缀（防止当两个自由度用）----
    def t_prefix():
        for ikm, salt, info in [
            (b"secret" * 4, b"saltsalt", b"CV6FF52FEE9EDDD86"),
            (b"\x00" * 32, b"", b""),
            (bytes(range(32)), os.urandom(8), b"VCU"),
        ]:
            a = hkdf(ikm, salt, info, 32)
            b = hkdf(ikm, salt, info, 16)
            _eq("prefix", b.hex(), a[:16].hex())
    check("HKDF-Expand 前缀性质 (L=16 == L=32[:16])", t_prefix)

    # ---- 7. 边界：L=0 / L=255*32 / 超界报错 ----
    def t_bounds():
        prk = hkdf_extract(b"s", b"i")
        _eq("L=0", hkdf_expand(prk, b"x", 0), b"")
        _eq("L=8160 len", len(hkdf_expand(prk, b"x", 255 * 32)), 255 * 32)
        try:
            hkdf_expand(prk, b"x", 255 * 32 + 1)
        except ValueError:
            pass
        else:
            raise TestFail("L 超界没有抛 ValueError")
    check("HKDF L 边界 (0 / 255*HashLen / 超界)", t_bounds)

    # ---- 8. 与 pycryptodome 交叉校验（若装了）----
    def t_cross():
        try:
            from Crypto.Cipher import AES as _AES
            from Crypto.Hash import CMAC as _CMAC
        except Exception:
            return  # 没装就跳过，不算失败
        key = bytes(range(16))
        blk = bytes(range(16, 32))
        c = _AES.new(key, _AES.MODE_ECB)
        _eq("AES vs pycryptodome", aes128_encrypt_block(key, blk).hex(),
            c.encrypt(blk).hex())
        for n in (0, 1, 15, 16, 17, 63, 64):
            msg = bytes((i * 7 + 3) & 0xFF for i in range(n))
            _eq("CMAC len=%d vs pycryptodome" % n, aes_cmac(key, msg).hex(),
                _CMAC.new(key, ciphermod=_AES).update(msg).hexdigest())
    check("交叉校验 pycryptodome (AES-128 + CMAC)", t_cross)

    # ---- 9. 端到端：合成固件 → 结构探测 → salt 分界必须精确 ----
    def t_pipeline():
        payload = bytes((i * 31 + 7) & 0xFF for i in range(4000))
        trailer = bytes((i * 97 + 11) & 0xFF for i in range(256))

        # 用例 A：header = magic(4) + len(4)，payload 紧接其后
        hdr = b"BMS1" + struct.pack("<I", len(payload))
        fw = hdr + payload + trailer
        st = probe_structure(fw)
        _eq("A.magic", st["magic"], b"BMS1")
        _eq("A.header_len", st["header_len"], 8)
        _eq("A.trailer_len", st["trailer_len"], 256)
        salts = {s["name"]: s["value"] for s in salt_candidates(fw, st)}
        _eq("A.S1", salts["S1"].hex(), hashlib.sha256(fw).hexdigest())
        _eq("A.S2b == SHA256(payload)", salts["S2b"].hex(),
            hashlib.sha256(payload).hexdigest())
        _eq("A.S2 == SHA256(payload+trailer)", salts["S2"].hex(),
            hashlib.sha256(payload + trailer).hexdigest())
        _eq("A.S3 == SHA256(header)", salts["S3"].hex(),
            hashlib.sha256(hdr).hexdigest())
        if "S2z" in salts:
            raise TestFail("用例 A 的 payload 无前导零，不该出现 S2z")

        # 用例 B：header 带 8 字节 reserved 填充。length 字段无法把它与 payload
        # 前导零区分（结构探测会保守地按 header_len=8），必须由 [spec] 候选 S2z 补位。
        hdr_b = b"BMS1" + struct.pack("<I", len(payload)) + b"\x00" * 8
        fw_b = hdr_b + payload + trailer
        st_b = probe_structure(fw_b)
        _eq("B.header_len（保守取 magic+len）", st_b["header_len"], 8)
        salts_b = {s["name"]: s["value"] for s in salt_candidates(fw_b, st_b)}
        if "S2z" not in salts_b:
            raise TestFail("用例 B 应产生 S2z 补位候选，实际 %r" % sorted(salts_b))
        _eq("B.S2z == SHA256(payload)", salts_b["S2z"].hex(),
            hashlib.sha256(payload).hexdigest())
        _eq("B.S2b != SHA256(payload)（证明保守切分确实偏了）",
            salts_b["S2b"].hex() != hashlib.sha256(payload).hexdigest(), True)

        # 候选生成不塌方
        rk = rootkey_candidates(fw, explicit=bytes.fromhex("11" * 32))
        names = [r["name"] for r in rk]
        _eq("RK1 存在且居首", names[0], "RK1")
        if "RK3" not in names:
            raise TestFail("RK3 缺失")
        for r in rk:
            if len(r["value"]) < 1:
                raise TestFail("候选 %s 值为空" % r["name"])
        # K4 必须与 seed 等长
        for seed_len in (4, 8, 16):
            seed = bytes(range(seed_len))
            dv32 = hkdf(b"k" * 32, b"s" * 32, b"CV6FF52FEE9EDDD86", 32)
            ks = {k["name"]: k["value"] for k in key_candidates(dv32, seed)}
            _eq("K4 len==seed len (%d)" % seed_len, len(ks["K4"]), seed_len)
            _eq("K1 恒 32B (%d)" % seed_len, len(ks["K1"]), 32)
            _eq("K3 恒 16B (%d)" % seed_len, len(ks["K3"]), 16)
    check("端到端 pipeline（合成固件 → salt 分界 → 候选生成）", t_pipeline)

    # ---- 10. 无结构固件不得凭空造出 S2/S3 ----
    def t_nostruct():
        fw = bytes((i * 13 + 5) & 0xFF for i in range(2048))
        st = probe_structure(fw)
        _eq("无 magic", st["magic"], None)
        _eq("无 header_len", st["header_len"], None)
        names = [s["name"] for s in salt_candidates(fw, st)]
        if "S2" in names or "S3" in names:
            raise TestFail("无结构时不应生成 S2/S3，实际 %r" % names)
        _eq("只有 S1 + spec", names[0], "S1")
        if not all(s["spec"] for s in salt_candidates(fw, st)[1:]):
            raise TestFail("无结构时除 S1 外必须标记 spec")
    check("无结构固件不臆造 S2/S3", t_nostruct)

    # ---- 输出 ----
    width = max(len(l) for l, _, _ in results)
    print("derive_key.py %s self-test" % VERSION)
    print("=" * (width + 12))
    bad = 0
    for label, status, detail in results:
        print("%-*s  %s" % (width, label, status))
        if status != "PASS":
            bad += 1
            for line in detail.splitlines():
                print("    " + line)
    print("-" * (width + 12))
    print("%d/%d passed" % (len(results) - bad, len(results)))
    if bad:
        print("RESULT: FAIL —— 不许交付")
        return 1
    print("RESULT: PASS")
    return 0


# --------------------------------------------------------------------------- #
# 报告
# --------------------------------------------------------------------------- #

def _print_table(headers, rows):
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("-" * len(line))
    for r in rows:
        print("  ".join(c.ljust(w) for c, w in zip(r, widths)))


def build_report(fw_path: str, data: bytes, vin: str, seed, rootkey, wide: bool):
    st = probe_structure(data)
    rks = rootkey_candidates(data, explicit=rootkey)
    salts = salt_candidates(data, st, wide=wide)
    infos = info_candidates(vin, wide=wide)

    derived = []
    for rk in rks:
        for s in salts:
            for inf in infos:
                try:
                    dv32 = hkdf(rk["value"], s["value"], inf["value"], 32)
                except Exception as e:  # noqa: BLE001
                    derived.append({"combo": "%s/%s/%s" % (rk["name"], s["name"], inf["name"]),
                                    "error": "%s: %s" % (type(e).__name__, e)})
                    continue
                entry = {
                    "combo": "%s/%s/%s" % (rk["name"], s["name"], inf["name"]),
                    "rk": rk["name"], "salt": s["name"], "info": inf["name"],
                    "dv32": dv32.hex(), "dv16": dv32[:16].hex(),
                }
                if seed is not None:
                    entry["keys"] = [
                        {"name": "%s/%s/%s/%s" % (rk["name"], s["name"], inf["name"], k["name"]),
                         "value": k["value"].hex(), "len": len(k["value"]),
                         "src": k["src"], "note": k["note"]}
                        for k in key_candidates(dv32, seed)
                    ]
                derived.append(entry)

    return {
        "tool": "derive_key.py", "version": VERSION,
        "firmware": {"path": fw_path, "size": len(data),
                     "sha256": HASH(data).hexdigest(),
                     "magic": (st["magic"].decode("latin-1") if st["magic"] else None),
                     "header_len": st["header_len"],
                     "trailer_len": st["trailer_len"],
                     "structs": st["structs"], "notes": st["notes"]},
        "vin": vin, "seed": seed.hex() if seed is not None else None,
        "rootkeys": [{"name": r["name"], "value": r["value"].hex(),
                      "len": len(r["value"]), "src": r["src"], "note": r["note"]}
                     for r in rks],
        "salts": [{"name": s["name"], "value": s["value"].hex(), "spec": s["spec"],
                   "src": s["src"], "note": s["note"]} for s in salts],
        "infos": [{"name": i["name"], "value": i["value"].hex(),
                   "ascii": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in i["value"]),
                   "spec": i["spec"], "src": i["src"], "note": i["note"]}
                  for i in infos],
        "derived": derived,
    }


def render_text(rep: dict, seed, brief: bool = False, uds: bool = False,
                limit_live: int = 0):
    fwm = rep["firmware"]
    print("=" * 78)
    print("derive_key.py %s —— 赛题08 VCU SecurityAccess key 候选枚举" % VERSION)
    print("=" * 78)
    print("firmware : %s" % fwm["path"])
    print("size     : %d bytes" % fwm["size"])
    print("sha256   : %s" % fwm["sha256"])
    print("magic    : %r   header_len=%s  trailer_len=%s"
          % (fwm["magic"], fwm["header_len"], fwm["trailer_len"]))
    for n in fwm["notes"]:
        print("  note   : %s" % n)
    print("vin      : %r" % rep["vin"])
    print("seed     : %s" % (rep["seed"] if rep["seed"] else "(未提供，只输出 derived)"))
    print()

    print("--- root key 候选 (%d) ---" % len(rep["rootkeys"]))
    _print_table(["name", "len", "value", "src"],
                 [[r["name"], str(r["len"]), r["value"], r["src"]]
                  for r in rep["rootkeys"]])
    print()

    print("--- salt 候选 (%d) ---" % len(rep["salts"]))
    _print_table(["name", "spec", "value", "src"],
                 [[s["name"], "spec" if s["spec"] else "", s["value"], s["src"]]
                  for s in rep["salts"]])
    print()

    print("--- info 候选 (%d) ---" % len(rep["infos"]))
    _print_table(["name", "spec", "ascii", "hex", "src"],
                 [[i["name"], "spec" if i["spec"] else "", i["ascii"] or "(empty)",
                   i["value"], i["src"]] for i in rep["infos"]])
    print()

    print("--- derived = HKDF-SHA256(ikm=RK, salt=S, info=I, L=32) 共 %d 组 ---"
          % len(rep["derived"]))
    _print_table(["combo", "dv32", "dv16(=dv32[:16])"],
                 [[d["combo"], d.get("dv32", "ERROR: " + d.get("error", "")),
                   d.get("dv16", "")] for d in rep["derived"]])

    if seed is None:
        print()
        print("下一步：从 VCU 发 27 01 拿 seed，然后")
        print("  python derive_key.py --firmware <bin> --vin %r --seed <seed_hex> --uds"
              % rep["vin"])
        return

    nkeys = sum(len(d.get("keys", [])) for d in rep["derived"])
    print()
    print("--- key 候选：每行  候选名 | key_hex | 长度   共 %d 条 ---" % nkeys)
    print("    （K1=首选字面 HMAC；K4=标准 UDS 等长截断；K3=AES-CMAC 经典实现）")
    print()
    shown = 0
    for d in rep["derived"]:
        for k in d.get("keys", []):
            if brief and not (k["name"].endswith("/K1") or k["name"].endswith("/K4")):
                continue
            print("%s | %s | %d" % (k["name"], k["value"], k["len"]))
            shown += 1
            if limit_live and shown >= limit_live:
                print("... (已截断到 %d 条，去掉 --limit 看全部)" % limit_live)
                return
    print()

    if uds:
        print("--- UDS 发送帧（27 02 <key>），按 长度==seed长度 过滤，前 20 条 ---")
        print("    只在收到 67 02 时才算公式命中；7F 27 35 = invalidKey 立刻换下一条")
        cnt = 0
        for d in rep["derived"]:
            for k in d.get("keys", []):
                if k["len"] != len(seed):
                    continue
                frame = "27 02 " + " ".join(k["value"][i:i + 2] for i in range(0, len(k["value"]), 2))
                print("%-28s  %s   # %s" % (k["name"], frame, k["src"]))
                cnt += 1
                if cnt >= 20:
                    print("... (共 %d 条等长候选)"
                          % sum(1 for d2 in rep["derived"] for k2 in d2.get("keys", [])
                                if k2["len"] == len(seed)))
                    return


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_hex(s: str, what: str) -> bytes:
    t = s.strip().lower().replace("0x", "").replace(" ", "").replace(":", "").replace("-", "")
    t = t.replace("_", "")
    if len(t) % 2:
        raise SystemExit("%s 十六进制长度必须是偶数：%r" % (what, s))
    try:
        return bytes.fromhex(t)
    except ValueError:
        raise SystemExit("%s 不是合法十六进制：%r" % (what, s))


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass

    ap = argparse.ArgumentParser(
        description="赛题08 派生 VCU SecurityAccess key 候选（离线，纯 stdlib）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--firmware", help="BMS 固件文件路径")
    ap.add_argument("--vin", help="VIN（17 字符）")
    ap.add_argument("--seed", help="27 01 收到的 seed，十六进制（可带 0x/空格/冒号）")
    ap.add_argument("--rootkey", help="显式 root key，十六进制")
    ap.add_argument("--out", help="把完整报告写成 JSON 到该路径")
    ap.add_argument("--fmt", choices=["table", "json"], default="table",
                    help="stdout 格式（默认 table）")
    ap.add_argument("--uds", action="store_true", help="额外打印 27 02 帧")
    ap.add_argument("--brief", action="store_true", help="key 表只留 K1/K4")
    ap.add_argument("--wide", action="store_true",
                    help="打开猜测型候选（S4_* 全尺寸、非 VIN 标识符 info）")
    ap.add_argument("--limit", type=int, default=0, help="key 表最多打印多少条（0=全部）")
    ap.add_argument("--self-test", action="store_true", help="用已知向量自校验后退出")
    ap.add_argument("--version", action="version", version="derive_key.py " + VERSION)
    args = ap.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if not args.firmware:
        ap.error("需要 --firmware（或 --self-test）")
    if not args.vin:
        ap.error("需要 --vin")

    if not os.path.isfile(args.firmware):
        print("ERROR: 固件不存在: %s" % args.firmware, file=sys.stderr)
        print("       当前状态：待固件。拿到 BMS 镜像后重跑本命令即可。", file=sys.stderr)
        return 2

    with open(args.firmware, "rb") as f:
        data = f.read()
    if not data:
        print("ERROR: 固件为空: %s" % args.firmware, file=sys.stderr)
        return 2

    vin = args.vin.strip()
    if len(vin) != 17:
        print("WARN: VIN 长度 %d != 17，仍继续（info 可以是任意串）" % len(vin),
              file=sys.stderr)

    seed = parse_hex(args.seed, "--seed") if args.seed else None
    if seed is not None and len(seed) == 0:
        print("ERROR: --seed 解析为空", file=sys.stderr)
        return 2
    rootkey = parse_hex(args.rootkey, "--rootkey") if args.rootkey else None

    rep = build_report(args.firmware, data, vin, seed, rootkey, args.wide)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=1)
        print("JSON 报告写入 %s" % args.out, file=sys.stderr)

    if args.fmt == "json":
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    else:
        render_text(rep, seed, brief=args.brief, uds=args.uds, limit_live=args.limit)
    return 0


if __name__ == "__main__":
    sys.exit(main())

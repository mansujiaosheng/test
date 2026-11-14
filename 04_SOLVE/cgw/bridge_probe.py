#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bridge_probe.py —— 开桥之后的一次性交互探针（现在桥是关的，先把工具备好）。

用途：`watch_bridge.py` 报 `STATE_CHANGE` 之后立刻运行本脚本，用**每连接一帧**的方式
探"桥到底讲什么"：先看有没有服务端先发的帧，再依次试 CAN FD / classic CAN / ASCII /
UDS-over-CAN 的候选首帧，任何 >=1 字节回包都完整落盘并打印。

纪律：每个候选一个连接、间隔 0.3 s，全套 <= 24 连接；只读语义（UDS 只用 22 读 DID 与 3E）。
输出：03_EVIDENCE/cgw/0524_bridge_probe.jsonl

用法：
  python 04_SOLVE/cgw/bridge_probe.py [host]
"""
import socket, struct, time, json, sys, binascii
from datetime import datetime

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.226.193.2"
PORT = 13401
OUT = "03_EVIDENCE/cgw/0524_bridge_probe.jsonl"
GAP = 0.3

def iso():
    return datetime.now().astimezone().isoformat(timespec="milliseconds")

def conn(on_data):
    s = socket.socket(); s.settimeout(3)
    s.connect((HOST, PORT)); s.settimeout(1.5)
    try:
        while True:
            try:
                c = s.recv(4096)
            except socket.timeout:
                break
            except ConnectionResetError:
                on_data(b"", "RST"); break
            if c == b"":
                on_data(b"", "FIN"); break
            on_data(c, "DATA")
            if not c: break
    finally:
        s.close()

def probe(tag, payload, wait=1.5):
    r = {"ts": iso(), "tag": tag, "tx": payload.hex()}
    s = socket.socket(); s.settimeout(3)
    try:
        s.connect((HOST, PORT)); s.settimeout(wait)
        if payload: s.sendall(payload)
        buf = b""; outcome = "TIMEOUT"
        while True:
            try:
                c = s.recv(4096)
            except socket.timeout:
                outcome = "NO_DATA"; break
            except ConnectionResetError:
                outcome = "RST"; break
            if c == b"":
                outcome = "FIN"; break
            buf += c
        r.update(rx=buf.hex(), outcome=outcome)
    except Exception as e:
        r.update(outcome="ERR", err=type(e).__name__ + ":" + str(e))
    finally:
        s.close()
    print(json.dumps(r, ensure_ascii=False), flush=True)
    with open(OUT, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    time.sleep(GAP)
    return r

# socketCAN 结构（little-endian）
def canfd(can_id, data, flags=0):
    data = data.ljust(64, b"\x00")
    return struct.pack("<IBBBB", can_id, len(data), flags, 0, 0) + data
def can_classic(can_id, data):
    data = data.ljust(8, b"\x00")
    return struct.pack("<IBBBB", can_id, len(data), 0, 0, 0) + data

UDS_VIN = bytes.fromhex("0322F190")          # ISO-TP 单帧：22 F1 90（读 VIN）
FRAMES = [
    ("server_first", b""),
    ("socketcan_classic_7e0", can_classic(0x7E0, UDS_VIN)),
    ("socketcan_fd_7e0", canfd(0x7E0, UDS_VIN)),
    ("socketcan_fd_7e1", canfd(0x7E1, UDS_VIN)),
    ("be_canid_7e0", struct.pack(">I", 0x7E0) + UDS_VIN),
    ("ascii_can_7e0", ("can0 7E0#%s\n" % UDS_VIN.hex()).encode()),
    ("candump_7e0", ("(%.6f) can0 7E0#%s\n" % (time.time(), UDS_VIN.hex())).encode()),
    ("json_frame", json.dumps({"id": 0x7E0, "data": UDS_VIN.hex(), "fd": True}).encode() + b"\n"),
    ("len2be_canfd", struct.pack(">H", 64) + canfd(0x7E0, UDS_VIN)),
    ("len4le_canfd", struct.pack("<I", 64) + canfd(0x7E0, UDS_VIN)),
    ("slcan_open", b"O\r"),
    ("slcan_frame", b"t7E08" + UDS_VIN.hex().upper().encode() + b"\r"),
    ("socketcand_open", b"< open can0 >\n"),
    ("subscribe", b"< subscribe can0 >\n"),
    ("doip_uds_on_can", bytes.fromhex("02FD80010000") + bytes.fromhex("0E001000") + UDS_VIN),
]

if __name__ == "__main__":
    print(json.dumps({"ts": iso(), "step": "start", "host": HOST, "port": PORT,
                      "n": len(FRAMES)}), flush=True)
    for tag, payload in FRAMES:
        r = probe(tag, payload)
        if r.get("rx"):
            print(json.dumps({"STOP": "got bytes", "tag": tag, "rx": r["rx"]}, ensure_ascii=False), flush=True)
            break
    print(json.dumps({"ts": iso(), "step": "done"}), flush=True)

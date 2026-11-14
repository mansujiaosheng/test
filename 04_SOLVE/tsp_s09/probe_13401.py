#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""13401 协议识别 —— 与 DoIP 13400 相邻, 疑似 VCU programming/诊断第二通道
判据: 服务端是否先发言 / 关闭时机是否随输入长度变化 / 是否对特定魔数有响应
"""
import socket, time, sys, os

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.230.164.4"
PORT = 13401
OUT = sys.argv[2] if len(sys.argv) > 2 else r"D:\qwb\03_EVIDENCE\tsp_s09"
os.makedirs(OUT, exist_ok=True)

def probe(name, payload, wait=1.5, note=""):
    t0 = time.time()
    s = socket.socket(); s.settimeout(wait)
    result = {"name": name, "sent": (len(payload) if payload else 0), "note": note}
    try:
        s.connect((HOST, PORT))
        result["t_connect"] = round((time.time() - t0) * 1000, 1)
        # 先看看服务端是否主动发言
        if payload is None:
            data = b""
            try:
                data = s.recv(4096)
                result["server_first"] = data[:200].hex()
            except socket.timeout:
                result["server_first"] = "TIMEOUT(no data)"
        else:
            s.sendall(payload)
            t1 = time.time()
            buf = b""
            try:
                while True:
                    c = s.recv(4096)
                    if not c:
                        result["closed_by_peer"] = True
                        break
                    buf += c
                    if len(buf) > 8192: break
            except socket.timeout:
                result["closed_by_peer"] = False
                result["recv_timeout"] = True
            result["t_after_send_ms"] = round((time.time() - t1) * 1000, 1)
            result["resp_hex"] = buf[:400].hex()
            result["resp_len"] = len(buf)
    except Exception as e:
        result["error"] = repr(e)
    finally:
        try: s.close()
        except Exception: pass
    result["t_total_ms"] = round((time.time() - t0) * 1000, 1)
    return result

TLS_CH = bytes.fromhex(
    "16030100c4010000c00303" + "00" * 32 + "00" +
    "0004002f000a00080006001d00170018" +
    "001600000013001100000e00000d0000" +
    "000b00020100" + "002b0003020304" +
    "002d00020101" + "003300260024001d0020" + "00" * 32)

CASES = [
    ("no_send", None, 2.0, "只看服务端是否先发言"),
    ("1byte", b"\x00", 1.5, ""),
    ("4x00", b"\x00\x00\x00\x00", 1.5, "4字节0"),
    ("8x00", b"\x00" * 8, 1.5, ""),
    ("16x00", b"\x00" * 16, 1.5, ""),
    ("64x00", b"\x00" * 64, 1.5, ""),
    ("256x00", b"\x00" * 256, 1.5, ""),
    ("0xff*8", b"\xff" * 8, 1.5, ""),
    ("len_le_1", (1).to_bytes(4, "little"), 1.5, "小端长度=1"),
    ("len_le_4", (4).to_bytes(4, "little") + b"PING", 1.5, "小端长度=4 + PING"),
    ("len_be_4", (4).to_bytes(4, "big") + b"PING", 1.5, "大端长度=4 + PING"),
    ("ascii_ping", b"PING\r\n", 1.5, ""),
    ("http_get", b"GET / HTTP/1.1\r\nHost: 10.230.164.4\r\nConnection: close\r\n\r\n", 1.5, "HTTP 探测"),
    ("tls_clienthello", TLS_CH, 1.5, "TLS 1.2 ClientHello"),
    ("doip_ident", bytes.fromhex("0201" "00000000" "01" "00" "00" "00" "00" "00" "00"), 1.5,
     "DoIP 0x0001 vehicle identification"),
    ("doip_routing", bytes.fromhex("02fd" "00000005" "0e00" "00" "00" "00" "00" "00"), 1.5,
     "DoIP 0x0005 routing activation (SA 0x0E00)"),
    ("uds_10_02", b"\x10\x02", 1.5, "裸 UDS programming session"),
    ("uds_raw_22f190", b"\x22\xf1\x90", 1.5, "裸 UDS VIN"),
    ("text_prog", b"programming session\r\n", 1.5, ""),
]

def main():
    path = os.path.join(OUT, f"20_13401_probe_{HOST.replace('.','_')}.txt")
    f = open(path, "w", encoding="utf-8")
    f.write(f"# 13401 probe  {time.strftime('%Y-%m-%dT%H:%M:%S')}  {HOST}:{PORT}\n")
    print(f"# 13401 probe  {HOST}:{PORT}")
    for name, payload, wait, note in CASES:
        r = probe(name, payload, wait, note)
        line = (f"{name:18s} sent={r['sent']:4d} "
                f"t_after_send={r.get('t_after_send_ms','-')}ms "
                f"peer_closed={r.get('closed_by_peer','-')} resp_len={r.get('resp_len','-')} "
                f"resp={r.get('resp_hex','')[:120]} note={note}")
        print(line)
        f.write(line + "\n")
        f.flush()
    f.close()
    print("saved:", path)

main()

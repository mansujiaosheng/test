#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Probe 10.229.221.2:13401 protocol identification.

Every probe = a FRESH TCP connection (never reused), so one probe's state
cannot contaminate the next.

Per probe we record:
  - t_connect_ms      : connect() -> ESTABLISHED
  - sent              : bytes written
  - t_first_recv_ms   : connect -> first readable byte / EOF
  - t_close_ms        : connect -> connection torn down (EOF or reset)
  - recv_bytes        : exact byte count received before EOF
  - close_kind        : FIN (orderly shutdown) | RST (reset) | TIMEOUT | SEND_ERR
  - so_error          : SO_ERROR value at close time (0 = clean, 10054 = RST)
  - data_hex          : first 64 bytes received, hex

Usage: python probe13401.py <phase>
  phase = baseline | protocols | lengths | udp | all
"""
import socket
import sys
import time
import os
import json
import struct

HOST = "10.229.221.2"
PORT = 13401
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs")
os.makedirs(OUT, exist_ok=True)

RESULTS = []


def probe(name, payload=b"", wait_s=10.0, note=""):
    """One fresh connection. Send payload (if any), then read until EOF/timeout."""
    rec = {"probe": name, "note": note, "sent_len": len(payload),
           "payload_hex": payload[:64].hex(), "wait_s": wait_s}

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(wait_s)
    t0 = time.time()
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        rec.update(connect="FAIL", err=repr(e),
                   t_connect_ms=round((time.time() - t0) * 1000, 2))
        s.close()
        RESULTS.append(rec)
        return rec
    t_conn = time.time()
    rec["t_connect_ms"] = round((t_conn - t0) * 1000, 2)

    # Small settle delay before sending so we can observe "does it close just
    # from an idle connection?" independently in the baseline probe.
    if payload:
        try:
            s.sendall(payload)
            rec["send"] = "ok"
        except Exception as e:
            rec["send"] = "FAIL:" + repr(e)
            rec["t_send_err_ms"] = round((time.time() - t0) * 1000, 2)

    # Drain until EOF or timeout.
    buf = b""
    close_kind = "TIMEOUT"
    t_first = None
    try:
        while True:
            chunk = s.recv(4096)
            if t_first is None:
                t_first = time.time()
            if not chunk:
                close_kind = "FIN"
                break
            buf += chunk
            if len(buf) > 65536:
                break
    except socket.timeout:
        close_kind = "TIMEOUT"
    except ConnectionResetError:
        close_kind = "RST"
    except Exception as e:
        close_kind = "ERR:" + repr(e)

    rec["t_first_recv_ms"] = (round((t_first - t0) * 1000, 2)
                              if t_first else None)
    rec["t_close_ms"] = round((time.time() - t0) * 1000, 2)
    rec["recv_len"] = len(buf)
    rec["recv_hex"] = buf[:256].hex()
    rec["recv_repr"] = repr(buf[:256])
    rec["close_kind"] = close_kind

    # SO_ERROR tells us definitively whether the peer sent RST (10054 on Win).
    try:
        rec["so_error"] = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    except Exception as e:
        rec["so_error"] = "ERR:" + repr(e)

    # Try one more recv after FIN to surface a deferred RST.
    try:
        s.settimeout(0.5)
        extra = s.recv(4096)
        rec["post_fin_recv"] = len(extra)
    except Exception as e:
        rec["post_fin_recv"] = type(e).__name__

    s.close()
    RESULTS.append(rec)
    print(json.dumps(rec, ensure_ascii=False))
    return rec


def flush(tag):
    p = os.path.join(OUT, "13401_%s.jsonl" % tag)
    with open(p, "w", encoding="utf-8") as f:
        for r in RESULTS:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("\n[written] %s (%d records)" % (p, len(RESULTS)))


def phase_baseline():
    print("### PHASE baseline: idle connection, no bytes sent")
    # 10s idle. If it closes instantly => active refusal. If it waits the full
    # 10s => it is waiting for a request.
    probe("baseline_idle_10s", b"", wait_s=10.0,
          note="connect, send nothing, wait for peer close up to 10s")
    # Second baseline with a longer wait, to catch a 'server-side idle timeout'.
    probe("baseline_idle_20s", b"", wait_s=20.0,
          note="connect, send nothing, wait up to 20s for a server idle timeout")
    flush("baseline")


def phase_protocols():
    print("### PHASE protocols: candidate protocol handshakes, one conn each")
    probes = [
        ("doip_ident_vehicle",
         bytes.fromhex("02fd000100000000"),
         "DoIP vehicle identification request, 8 bytes"),
        ("doip_ident_entity",
         bytes.fromhex("02fd0004000000000000"),
         "DoIP entity identification request"),
        ("doip_routing_activation",
         bytes.fromhex("02fd00050000000e00" + "0000000000"),
         "DoIP routing activation SA=0x0E00"),
        ("doip_diag_10_03",
         bytes.fromhex("02fd8001" + "00000014" "0e00" "" "1003"),
         "DoIP diag message 10 03 to TA 0x14"),
        ("http_get",
         b"GET / HTTP/1.1\r\nHost: 10.229.221.2:13401\r\n\r\n",
         "plain HTTP/1.1 GET"),
        ("http_get_healthz",
         b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n",
         "plain HTTP/1.1 GET /healthz"),
        ("h2_preface",
         b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
         "HTTP/2 connection preface"),
        ("text_VCU", b"VCU\n", "plain text VCU"),
        ("text_ta_e442", b"0xE442\n", "plain text TA 0xE442"),
        ("text_ta_assign", b"TA=0xE442\n", "plain text TA=0xE442"),
        ("text_healthz", b"healthz\n", "plain text healthz"),
        ("text_vcu_e442", b"VCU 0xE442\n", "plain text VCU 0xE442"),
        ("bin_zeros_1", b"\x00", "1 zero byte"),
        ("bin_zeros_2", b"\x00\x00", "2 zero bytes"),
        ("bin_zeros_4", b"\x00\x00\x00\x00", "4 zero bytes"),
        ("bin_zeros_8", b"\x00" * 8, "8 zero bytes"),
    ]
    for nm, pl, nt in probes:
        probe(nm, pl, wait_s=6.0, note=nt)

    # TLS ClientHello: build a real TLS1.3 ClientHello via ssl, but we want to
    # see the raw bytes. Use a hand-built minimal ClientHello.
    # A TLS record: type=0x16, version=0x0301, then handshake ClientHello.
    ch = build_client_hello("10.229.221.2")
    probe("tls13_clienthello", ch, wait_s=6.0,
          note="hand-built TLS1.3 ClientHello, SNI=10.229.221.2")
    flush("protocols")


def build_client_hello(sni):
    """Minimal TLS1.2/1.3 ClientHello with SNI, for raw-byte probing."""
    # ClientHello body
    rnd = os.urandom(32)
    sid = os.urandom(32)
    # cipher suites: TLS1.3 + some 1.2
    suites = bytes.fromhex("130113021303c02bc02fc02cc030009e009c")
    # extensions
    def ext(t, body):
        return struct.pack(">HH", t, len(body)) + body
    sni_body = struct.pack(">H", len(sni) + 3) + b"\x00" + \
        struct.pack(">H", len(sni)) + sni.encode()
    exts = b""
    exts += ext(0x0000, sni_body)                     # server_name
    exts += ext(0x000a, bytes.fromhex("0004001d0017"))  # supported_groups
    exts += ext(0x000b, bytes.fromhex("020100"))      # ec_point_formats
    exts += ext(0x000d, bytes.fromhex("000408040201"))  # sig_algs
    exts += ext(0x0010, bytes.fromhex("000b0a08040805080604030201"))  # ALPN-wrap
    exts += ext(0x002b, bytes.fromhex("04030a0a0304"))  # supported_versions
    exts += ext(0x0033, bytes.fromhex("00260024001d0020" + "00" * 32))  # key_share
    body = (b"\x03\x03" + rnd + bytes([len(sid)]) + sid +
            struct.pack(">H", len(suites)) + suites +
            b"\x01\x00" + struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def phase_lengths():
    print("### PHASE lengths: is close-delay a function of bytes sent?")
    for n in (1, 2, 4, 8, 16, 64, 256, 1024, 4096):
        probe("len_%d" % n, os.urandom(n), wait_s=6.0,
              note="%d random bytes, look for length-dependent close delay" % n)
    flush("lengths")


def phase_udp():
    print("### PHASE udp: UDP 13401 (DoIP also has UDP discovery)")
    out = []
    for nm, pl in [("doip_ident_udp", bytes.fromhex("02fd000100000000")),
                   ("empty_udp", b""),
                   ("zeros_udp", b"\x00" * 8)]:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(4.0)
        rec = {"probe": nm, "payload_hex": pl.hex()}
        t0 = time.time()
        try:
            s.sendto(pl, (HOST, 13401))
            data, addr = s.recvfrom(4096)
            rec.update(reply_hex=data.hex(), reply_repr=repr(data),
                       t_ms=round((time.time() - t0) * 1000, 2), addr=str(addr))
        except socket.timeout:
            rec.update(reply="TIMEOUT", t_ms=round((time.time() - t0) * 1000, 2))
        except Exception as e:
            rec.update(reply="ERR:" + repr(e))
        s.close()
        out.append(rec)
        print(json.dumps(rec, ensure_ascii=False))
        RESULTS.append(rec)
    flush("udp")


if __name__ == "__main__":
    phase = sys.argv[1] if len(sys.argv) > 1 else "all"
    if phase in ("baseline", "all"):
        phase_baseline()
    if phase in ("protocols", "all"):
        phase_protocols()
    if phase in ("lengths", "all"):
        phase_lengths()
    if phase in ("udp", "all"):
        phase_udp()

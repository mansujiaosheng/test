#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""p4_13401.py - 13401 protocol identification, timing-first.

Hypothesis H-13401-a: the listener accepts and then waits only ~200 ms for the FIRST
byte; anything later meets a closed socket (=> RST on write). Prior probes logged
"FIN before send after 266 ms", which is exactly that shape.
Therefore: connect() and sendall() must not be separated by any delay.

For each candidate framing we record:
  t_accept_to_fin  (server closed on its own before we wrote?)
  first_bytes      (server speaks first?)
  reply / result   (data / EOF / RST / timeout)
"""
import socket, time, binascii, json, os, sys, struct, ssl

EV = r"D:\qwb\03_EVIDENCE\cgw"
OUT = os.path.join(EV, "p4_13401.jsonl")
TARGETS = [("10.229.221.2", 13401), ("10.230.164.4", 13401)]


def hx(b):
    return binascii.hexlify(b).decode().upper()


def probe(host, port, name, payload, wait=3.0, pre_read=0.0, keep_open=0.0):
    """pre_read: seconds to listen *before* sending (to see if server speaks first)."""
    t0 = time.time()
    rec = {"name": name, "host": host, "port": port, "sent": hx(payload) if payload else "",
           "len": len(payload) if payload else 0}
    s = None
    try:
        s = socket.socket()
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(wait)
        s.connect((host, port))
        rec["connect_ms"] = round((time.time() - t0) * 1000, 1)

        # 1) does the server speak first?
        if pre_read > 0:
            s.settimeout(pre_read)
            try:
                d = s.recv(4096)
                rec["server_first"] = hx(d) if d else "EOF@%.0fms" % ((time.time() - t0) * 1000)
            except socket.timeout:
                rec["server_first"] = "silent@%.0fms" % ((time.time() - t0) * 1000)
            except ConnectionResetError:
                rec["server_first"] = "RST@%.0fms" % ((time.time() - t0) * 1000)

        # 2) write immediately
        if payload:
            s.settimeout(wait)
            try:
                s.sendall(payload)
                rec["sent_ok"] = True
            except Exception as e:
                rec["sent_ok"] = False
                rec["send_err"] = repr(e)
                rec["result"] = "SEND-FAIL"
                return rec

        # 3) read reply
        s.settimeout(wait)
        buf = b""
        try:
            while True:
                d = s.recv(4096)
                if not d:
                    rec["result"] = "EOF"
                    break
                buf += d
                if keep_open and len(buf) < 65536:
                    continue
                break
        except socket.timeout:
            rec["result"] = "TIMEOUT"
        except ConnectionResetError:
            rec["result"] = "RST"
        rec["reply"] = hx(buf) if buf else ""
        rec["reply_len"] = len(buf)
        rec["total_ms"] = round((time.time() - t0) * 1000, 1)
    except Exception as e:
        rec["result"] = "CONNECT-FAIL"
        rec["err"] = repr(e)
    finally:
        try:
            s and s.close()
        except Exception:
            pass
    return rec


def tls_client_hello(sni=None):
    """Build a minimal TLS1.2 ClientHello with SNI, so we don't depend on openssl."""
    def ext(t, body):
        return struct.pack(">HH", t, len(body)) + body
    sni_b = sni.encode() if sni else b""
    sni_list = struct.pack(">H", len(sni_b) + 3) + b"\x00" + struct.pack(">H", len(sni_b)) + sni_b
    exts = ext(0x0000, sni_list) + ext(0x000A, b"\x00\x04\x00\x1d\x00\x17") + \
           ext(0x000B, b"\x01\x00") + ext(0x000D, b"\x00\x04\x04\x03\x08\x04")
    client_ver = b"\x03\x03"
    rnd = os.urandom(32)
    sid = b"\x20" + os.urandom(32)
    ciphers = struct.pack(">H", 4) + b"\x13\x01\x13\x02"
    comp = b"\x01\x00"
    body = client_ver + rnd + sid + ciphers + comp + struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
    return rec


def doip_ident(ver=0x02, ptype=0x0001):
    return bytes([ver, 0xFF - ver]) + struct.pack(">H", ptype) + struct.pack(">I", 0)


def main():
    recs = []
    for host, port in TARGETS:
        H = host
        # --- timing: listen first, see when the server gives up on us ---
        r = probe(H, port, "accept_only_no_send_w5", b"", wait=5.0)
        recs.append(r); print(json.dumps(r, ensure_ascii=False), flush=True)

        # --- immediate-send candidates ---
        cands = [
            ("tls12_clienthello_sni", tls_client_hello("cgw.cybercar")),
            ("tls12_clienthello_nosni", tls_client_hello(None)),
            ("http_get_healthz", b"GET /healthz HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % H.encode()),
            ("http_options", b"OPTIONS * HTTP/1.1\r\nHost: %s\r\n\r\n" % H.encode()),
            ("doip_ident_v2", doip_ident(0x02)),
            ("doip_ident_v1", doip_ident(0x01)),
            ("doip_status_4001", bytes([0x02, 0xFD, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00])),
            ("uds_3E00", bytes.fromhex("3E00")),
            ("uds_22F190", bytes.fromhex("22F190")),
            ("canfd_7E0_3E00", struct.pack(">I", 0x7E0) + b"\x02\x02\x3E\x00".ljust(64, b"\x00")),
            ("canfd_le_7E0_3E00", struct.pack("<I", 0x7E0) + b"\x02\x02\x3E\x00".ljust(64, b"\x00")),
            ("banner_newline", b"\n"),
            ("nul8", b"\x00" * 8),
        ]
        for name, pl in cands:
            r = probe(H, port, name, pl, wait=3.0)
            recs.append(r)
            print("[%s] %-26s %-10s connect=%sms reply=%s" % (
                H, name, r.get("result"), r.get("connect_ms"), (r.get("reply") or "")[:80]), flush=True)

    with open(OUT, "a", encoding="utf-8") as f:
        for r in recs:
            r["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("# wrote", OUT, len(recs))


if __name__ == "__main__":
    main()

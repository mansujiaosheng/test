#!/usr/bin/env python3
"""Probe 13401: determine whether it speaks a protocol or is a closed/dead port.

Records, per attempt: connect time, when the peer closes (FIN vs RST), how many
bytes came back, and the exact error. Everything is dumped to
03_EVIDENCE/cgw/2NNN_13401_<label>.json by the caller.
"""
import socket, ssl, time, binascii, struct, json, os, sys

HOST = "10.229.221.2"
PORT = 13401


def attempt(label, payload=b"", *, wait_after=3.0, half_close=False,
            chunked=None, gap=0.15, do_connect_delay=0.0):
    """Return a dict describing the interaction."""
    rec = {"label": label, "payload_hex": binascii.hexlify(payload).decode(),
           "payload_len": len(payload), "half_close": half_close}
    t0 = time.time()
    s = socket.socket()
    s.settimeout(wait_after)
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        rec.update(connect_error=repr(e))
        return rec
    rec["connect_ms"] = round((time.time() - t0) * 1000, 1)
    if do_connect_delay:
        time.sleep(do_connect_delay)

    rx = b""
    closed_at = None
    close_kind = None

    try:
        if chunked:
            for i, ch in enumerate(chunked):
                s.sendall(ch)
                time.sleep(gap)
        elif payload:
            s.sendall(payload)

        if half_close:
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError as e:
                rec["shutdown_wr_error"] = repr(e)

        # read until close or timeout
        s.settimeout(wait_after)
        while True:
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            except ConnectionResetError as e:
                close_kind = "RST"
                rec["read_error"] = repr(e)
                break
            except OSError as e:
                close_kind = "ERR"
                rec["read_error"] = repr(e)
                break
            if not b:
                close_kind = close_kind or "FIN"
                closed_at = time.time()
                break
            rx += b
            if len(rx) > 65536:
                break
    except (BrokenPipeError, ConnectionResetError) as e:
        close_kind = "RST-on-write"
        rec["write_error"] = repr(e)
    except OSError as e:
        rec["write_error"] = repr(e)

    rec["rx_len"] = len(rx)
    rec["rx_hex"] = binascii.hexlify(rx[:512]).decode()
    if closed_at is not None:
        rec["closed_after_ms"] = round((closed_at - t0) * 1000, 1)
    rec["total_ms"] = round((time.time() - t0) * 1000, 1)
    rec["close_kind"] = close_kind
    try:
        s.close()
    except Exception:
        pass
    return rec


def tls_hello(sni=None):
    """Minimal but valid TLS1.2/1.3 ClientHello via the stdlib (record layer)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def tls_attempt(label, wait=3.0):
    rec = {"label": label}
    t0 = time.time()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    try:
        raw = socket.create_connection((HOST, PORT), timeout=wait)
    except Exception as e:
        rec["connect_error"] = repr(e)
        return rec
    try:
        ss = ctx.wrap_socket(raw, server_hostname=None)
        rec["handshake"] = "OK"
        rec["version"] = ss.version()
        rec["cipher"] = str(ss.cipher())
        rec["cert"] = ss.getpeercert(binary_form=True).hex() if ss.getpeercert(binary_form=True) else None
        ss.close()
    except Exception as e:
        rec["handshake"] = "FAIL"
        rec["error"] = repr(e)
        try:
            raw.close()
        except Exception:
            pass
    rec["total_ms"] = round((time.time() - t0) * 1000, 1)
    return rec


def main():
    out = []
    cases = [
        ("idle_no_bytes", dict(payload=b"", wait_after=3.0)),
        ("one_zero_byte", dict(payload=b"\x00")),
        ("four_zero_bytes", dict(payload=b"\x00" * 4)),
        ("http_get", dict(payload=b"GET / HTTP/1.1\r\nHost: cgw\r\n\r\n")),
        ("http2_preface", dict(payload=b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")),
        ("h2c_settings", dict(payload=b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")),
        ("http_get_halfclose", dict(payload=b"GET / HTTP/1.1\r\nHost: cgw\r\n\r\n", half_close=True)),
        ("doip_ident", dict(payload=bytes([0x02, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]))),
        ("doip_ra", dict(payload=bytes([0x02, 0xFD, 0x00, 0x05, 0x00, 0x00, 0x00, 0x07,
                                        0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))),
        ("len32_prefix_empty", dict(payload=struct.pack(">I", 0))),
        ("len32_prefix_2", dict(payload=struct.pack(">I", 2) + b"\x00\x00")),
        ("len16_prefix_0", dict(payload=struct.pack(">H", 0))),
        ("len8_prefix_0", dict(payload=b"\x00" * 1)),
        ("newline", dict(payload=b"\r\n")),
        ("json_newline", dict(payload=b'{"cmd":"sign"}\n')),
        ("big_zeros_4096", dict(payload=b"\x00" * 4096)),
        ("chunked_split_ident", dict(payload=b"", chunked=[b"\x02", b"\xFD", b"\x00\x01", b"\x00\x00\x00\x00"])),
        ("candump_golf_style", dict(payload=b"golf\r\n")),
        ("ascii_hello", dict(payload=b"hello\r\n")),
        ("tls12_clienthello", {}),
    ]
    for label, kw in cases:
        if label == "tls12_clienthello":
            rec = tls_attempt(label)
        else:
            rec = attempt(label, **kw)
        print("%-24s close=%-12s closed_after=%sms rx=%dB total=%sms" % (
            rec["label"], rec.get("close_kind"), rec.get("closed_after_ms"),
            rec.get("rx_len"), rec.get("total_ms")), flush=True)
        if rec.get("rx_len"):
            print("      RX:", rec["rx_hex"][:200])
        if rec.get("read_error") or rec.get("write_error"):
            print("      ERR:", rec.get("read_error") or rec.get("write_error"))
        out.append(rec)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "13401_probe.json"), "w") as f:
        json.dump(out, f, indent=2)


if __name__ == "__main__":
    main()

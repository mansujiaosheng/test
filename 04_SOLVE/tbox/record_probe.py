#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Record-level TLS probe of 10.230.164.3:8443.

Goal (evidence-grade): decide whether the server ever emits TLS application_data
(record type 0x17) -- i.e. any HTTP bytes -- before it aborts the handshake with
`certificate_required (116)`. That is the only way "mTLS bypass by reading before
auth" could be real.

Method: drive the handshake manually with ssl.MemoryBIO so every TLS record the
server sends is visible with its content type, length and arrival time, instead
of hiding behind s_client's summary output.
"""
import socket
import ssl
import sys
import time

HOST = "10.230.164.3"
PORT = 8443
REQ = (
    b"GET / HTTP/1.1\r\nHost: tbox\r\nUser-Agent: tbox-record-probe\r\n"
    b"Connection: close\r\n\r\n"
)

CT = {
    0x14: "change_cipher_spec",
    0x15: "alert",
    0x16: "handshake",
    0x17: "application_data",
    0x18: "heartbeat",
}


def parse_records(buf):
    """Yield (type, version, length, raw) for each complete TLS record."""
    out = []
    i = 0
    while i + 5 <= len(buf):
        rtype = buf[i]
        ver = buf[i + 1:i + 3]
        ln = int.from_bytes(buf[i + 3:i + 5], "big")
        if i + 5 + ln > len(buf):
            break
        out.append((rtype, ver, ln, buf[i + 5:i + 5 + ln]))
        i += 5 + ln
    return out, buf[i:]


def run(label, send_app_after_error=False, sni="tbox"):
    print(f"########## {label}")
    inb = ssl.MemoryBIO()
    outb = ssl.MemoryBIO()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    obj = ctx.wrap_bio(inb, outb, server_hostname=sni)

    raw = socket.create_connection((HOST, PORT), timeout=8)
    t0 = time.time()
    rec_index = 0
    app_data = b""
    pending = b""
    handshake_done = False
    err = None

    def flush():
        nonlocal rec_index
        data = outb.read()
        if data:
            raw.sendall(data)
            print(f"  [t={time.time()-t0:6.3f}] -> sent {len(data)} bytes "
                  f"({data[0]:#04x} {CT.get(data[0],'?')})")
        return data

    for step in range(40):
        try:
            obj.do_handshake()
            handshake_done = True
            break
        except ssl.SSLWantReadError:
            flush()
        except ssl.SSLError as e:
            err = f"SSLError: {e}"
            flush()
            break
        # read whatever is available
        try:
            chunk = raw.recv(65536)
        except socket.timeout:
            print(f"  [t={time.time()-t0:6.3f}] recv timeout")
            break
        if not chunk:
            print(f"  [t={time.time()-t0:6.3f}] EOF from server")
            break
        dt = time.time() - t0
        inb.write(chunk)
        pending += chunk
        recs, pending = parse_records(pending)
        for rtype, ver, ln, body in recs:
            rec_index += 1
            extra = ""
            if rtype == 0x15 and ln >= 2:
                extra = f" alert_level={body[0]} alert_desc={body[1]}"
            if rtype == 0x17:
                app_data += body
                extra = f" <<< APPLICATION DATA {len(body)} bytes"
            print(f"  [t={dt:6.3f}] <- rec#{rec_index} type={rtype:#04x} "
                  f"({CT.get(rtype,'?')}) ver={ver.hex()} len={ln}{extra}")

    print(f"  handshake_completed={handshake_done} error={err}")
    print(f"  total_application_data_bytes={len(app_data)}")
    if app_data:
        print("  APP_DATA_HEX=" + app_data.hex())
        print("  APP_DATA_REPR=" + repr(app_data[:2000]))
    print(f"  peer_cert_present={obj.getpeercert(binary_form=True) is not None}")

    if send_app_after_error:
        # Best-effort: some stacks let the client write app data that the server
        # buffers; check if anything comes back after we push bytes + close.
        try:
            sent = obj.write(REQ)
            out = outb.read()
            if out:
                raw.sendall(out)
            print(f"  post_error_write accepted={sent} bytes, flushed={len(out or b'')}")
        except Exception as e:
            print(f"  post_error_write refused: {type(e).__name__}: {e}")
        try:
            raw.settimeout(3)
            while True:
                more = raw.recv(65536)
                if not more:
                    break
                recs2, _ = parse_records(more)
                for rtype, ver, ln, body in recs2:
                    print(f"  [post] <- type={rtype:#04x} "
                          f"({CT.get(rtype,'?')}) len={ln}")
                    if rtype == 0x17:
                        app_data += body
        except socket.timeout:
            print("  [post] no further records within 3s")
        except Exception as e:
            print(f"  [post] {type(e).__name__}: {e}")

    raw.close()
    print()
    return app_data, handshake_done


def main():
    print(f"###### T-BOX 8443 record-level probe  "
          f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ######")
    print(f"## target {HOST}:{PORT}, python ssl {ssl.OPENSSL_VERSION}")
    print()
    total = b""
    a, _ = run("R01 no client cert, SNI=tbox", send_app_after_error=True)
    total += a
    a, _ = run("R02 no client cert, SNI=(empty)", sni=None)
    total += a
    a, _ = run("R03 no client cert, SNI=localhost", sni="localhost")
    total += a
    print("###### VERDICT ######")
    print(f"application_data bytes observed across all runs: {len(total)}")
    print("RESULT: " + ("APP DATA LEAKED" if total else
                        "no application data before/after alert -- mTLS wall is total"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

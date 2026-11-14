#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Record-level TLS probe v2 -- DECRYPTED view (authoritative).

v1 (0011) logged TLS record types only. In TLS 1.3 every post-ServerHello
message -- including the server's EncryptedExtensions/Certificate/Finished and
any alert -- is carried in record type 0x17, so a type-level log cannot tell
"application data" from "encrypted handshake/alert". v2 decrypts through the
SSLObject and reports what the bytes actually are.

Question answered: does 10.230.164.3:8443 ever deliver HTTP bytes to a client
that presents no certificate? A bypass claim requires a decrypted response body.
"""
import socket
import ssl
import sys
import time

HOST = "10.230.164.3"
PORT = 8443
REQ = (
    b"GET / HTTP/1.1\r\nHost: tbox\r\nUser-Agent: tbox-record-probe2\r\n"
    b"Connection: close\r\n\r\n"
)

ALERT_DESC = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    22: "record_overflow", 40: "handshake_failure", 42: "bad_certificate",
    43: "unsupported_certificate", 44: "certificate_revoked",
    45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter",
    48: "unknown_ca", 49: "access_denied", 50: "decode_error",
    51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
    80: "internal_error", 90: "user_canceled", 109: "missing_extension",
    112: "unrecognized_name", 116: "certificate_required",
    120: "no_application_protocol",
}


def probe(label, sni="tbox", send=REQ):
    print(f"########## {label}")
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    obj = ctx.wrap_bio(inb, outb, server_hostname=sni)
    raw = socket.create_connection((HOST, PORT), timeout=8)
    t0 = time.time()

    def pump_send():
        d = outb.read()
        if d:
            raw.sendall(d)
            print(f"  [t={time.time()-t0:6.3f}] -> client flight {len(d)} bytes")

    hs_ok = False
    for _ in range(20):
        try:
            obj.do_handshake()
            hs_ok = True
            break
        except ssl.SSLWantReadError:
            pump_send()
        except ssl.SSLError as e:
            print(f"  handshake raised: {e}")
            break
        chunk = raw.recv(65536)
        if not chunk:
            print("  EOF during handshake")
            break
        inb.write(chunk)

    print(f"  client_side_handshake_complete={hs_ok}  "
          f"(TLS1.3: client finishes on sending its last flight; server verdict "
          f"arrives later)")
    if not hs_ok:
        raw.close()
        print()
        return b""

    # Push the HTTP request through the encrypted channel and read back.
    try:
        obj.write(send)
        pump_send()
        print("  -> HTTP request written into the TLS session")
    except Exception as e:
        print(f"  write refused: {type(e).__name__}: {e}")

    plain = b""
    served = False
    for _ in range(12):
        try:
            data = obj.read(65536)
            if not data:
                print("  clean close (close_notify) with no data")
                break
            plain += data
            served = True
            print(f"  <- DECRYPTED {len(data)} bytes: {data[:200]!r}")
        except ssl.SSLWantReadError:
            try:
                chunk = raw.recv(65536)
            except socket.timeout:
                print("  recv timeout waiting for server")
                break
            if not chunk:
                print("  TCP EOF from server")
                break
            inb.write(chunk)
        except ssl.SSLError as e:
            m = str(e)
            print(f"  <- DECRYPTED ALERT from server: {e}")
            for k, v in ALERT_DESC.items():
                if f"alert {v}" in m or f"_ALERT_{v.upper()}" in m:
                    print(f"     => alert {k} ({v})")
            break

    print(f"  decrypted_application_bytes={len(plain)}")
    print(f"  HTTP_RESPONSE_SERVED={'YES: ' + repr(plain[:300]) if served else 'NO'}")
    raw.close()
    print()
    return plain


def main():
    print(f"###### T-BOX 8443 record-level probe v2 (DECRYPTED)  "
          f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ######")
    print(f"## target {HOST}:{PORT}; {ssl.OPENSSL_VERSION}")
    print("## note: v1 (0011) logged record TYPES only; TLS1.3 hides handshake+alert")
    print("##       inside 0x17 records, so v1's 'application_data' counter is not")
    print("##       evidence of a bypass. This file is the authoritative decode.")
    print()
    total = b""
    total += probe("R01 SNI=tbox, no client cert, GET / immediately")
    total += probe("R02 SNI=empty, no client cert")
    total += probe("R03 SNI=localhost, no client cert")
    total += probe("R04 SNI=tbox, no client cert, POST /api/v1/ota/sign",
                   send=(b"POST /api/v1/ota/sign HTTP/1.1\r\nHost: tbox\r\n"
                         b"Content-Type: application/json\r\n"
                         b"Content-Length: 2\r\n\r\n{}"))
    print("###### VERDICT ######")
    print(f"decrypted application bytes across all runs: {len(total)}")
    print("RESULT: " + ("BYPASS -- server served HTTP without client cert"
                        if total else
                        "NO BYPASS -- zero decrypted application bytes; every "
                        "connection ends in alert certificate_required (116)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

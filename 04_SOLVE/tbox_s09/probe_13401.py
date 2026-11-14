#!/usr/bin/env python3
"""T-09 / tbox: probe the gateway's second DoIP-adjacent port (13401) for the
T-BOX certificate material it is supposed to hand out.

13400 is plain DoIP.  ISO 13400-2 permits TLS on the DoIP socket, and vendors
commonly put it on 13401.  If 13401 is TLS we can at least read its certificate
chain -- and a gateway chain often includes the diagnostics root we need for
10.230.164.3:8443.  Read-only: handshake + one vehicle-identification request.
"""
import socket, ssl, sys, json

HOSTS = ["10.230.164.4", "10.229.221.2"]
PORT = 13401
OUT = []


def note(s):
    print(s, flush=True)
    OUT.append(s)


def doip_vir(host, port, timeout=4):
    """DoIP vehicle identification request (payload type 0x0001, no VIN)."""
    pkt = bytes([0x02, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(pkt)
        data = s.recv(4096)
        return f"plain-DoIP VIR -> {data.hex()} ({len(data)}B)"
    except Exception as e:
        return f"plain-DoIP VIR -> {type(e).__name__}: {e}"
    finally:
        try: s.close()
        except Exception: pass


def tls_probe(host, port, timeout=5):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1", "doip", "13400"])
    except Exception:
        pass
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        w = ctx.wrap_socket(s, server_hostname="tbox")
        der = w.getpeercert(binary_form=True)
        info = {
            "tls": w.version(), "cipher": w.cipher()[0],
            "alpn": w.selected_alpn_protocol(),
            "peer_der_len": len(der) if der else 0,
        }
        import hashlib
        info["peer_sha256"] = hashlib.sha256(der).hexdigest() if der else None
        info["cert"] = ssl.DER_cert_to_PEM_cert(der) if der else None
        try:
            w.settimeout(2)
            w.sendall(bytes([0x02, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]))
            info["after_doip"] = w.recv(4096).hex()
        except Exception as e:
            info["after_doip"] = f"{type(e).__name__}: {e}"
        w.close()
        return info
    except Exception as e:
        return {"tls_error": f"{type(e).__name__}: {e}"}
    finally:
        try: s.close()
        except Exception: pass


def main():
    note("###### 13401 probe: is the second gateway port TLS / does it leak a cert chain? ######")
    for h in HOSTS:
        note(f"\n=== {h}:{PORT} ===")
        note("  " + doip_vir(h, PORT))
        r = tls_probe(h, PORT)
        note("  TLS: " + json.dumps({k: v for k, v in r.items() if k != "cert"}, ensure_ascii=False))
        if r.get("cert"):
            note("  --- peer cert (PEM) ---")
            note(r["cert"])
    with open(sys.argv[1], "w", encoding="utf-8") as f:
        f.write("\n".join(OUT) + "\n")


if __name__ == "__main__":
    main()

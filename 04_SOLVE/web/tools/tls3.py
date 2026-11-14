#!/usr/bin/env python3
"""8443 TLS-layer deep probe, v2 -- decisive.

The v1 run reported handshake success for every SNI, which is a measurement
artifact: in TLS 1.3 the server's post-Finished `alert certificate_required`
(116) can arrive *after* the client's wrap_socket() returns.  A successful
wrap_socket therefore proves nothing.  This version always performs an
application-data round trip after the handshake and reports what actually
comes back.
"""
import hashlib, json, os, socket, ssl, subprocess, sys

HOST, PORT = "10.230.164.3", 8443
EVID = os.path.join(os.path.dirname(__file__), "..", "..", "..", "03_EVIDENCE", "web")
REQB = b"GET / HTTP/1.0\r\nHost: tbox\r\n\r\n"

SNIS = [None, "", "tbox", "tsp", "cv6", "ota", "fleet", "update", "diagnostics",
        "localhost", "tbox.cv6", "ota.cv6.local", "cv6-fleet.local", "admin",
        "a" * 40 + ".com", "10.230.164.3"]
ALPNS = [None, ["h2"], ["http/1.1"], ["doip"], ["doip-v1"], ["h2", "http/1.1"], ["tls"]]

def attempt(sni, alpn=None, send_req=True, timeout=6.0):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.maximum_version = ssl.TLSVersion.TLSv1_3
    if alpn:
        c.set_alpn_protocols(alpn)
    raw = socket.socket(); raw.settimeout(timeout)
    r = {"sni": sni, "alpn_req": alpn, "handshake": None, "hs_err": None,
         "alpn": None, "cipher": None, "cert_sha": None, "subject": None,
         "issuer": None, "serial": None, "san": None,
         "app_write_ok": None, "app_read": None, "app_err": None}
    s = None
    try:
        raw.connect((HOST, PORT))
        kw = {"server_hostname": sni if sni else None}
        s = c.wrap_socket(raw, **kw)
        r["handshake"] = "completed"
        r["alpn"] = s.selected_alpn_protocol()
        r["cipher"] = s.cipher()[0] if s.cipher() else None
        der = s.getpeercert(binary_form=True)
        if der:
            r["cert_sha"] = hashlib.sha256(der).hexdigest()[:32]
            pd = s.getpeercert()
            r["subject"] = str(pd.get("subject")); r["issuer"] = str(pd.get("issuer"))
            r["serial"] = pd.get("serialNumber"); r["san"] = str(pd.get("subjectAltName"))
        if send_req:
            try:
                s.sendall(REQB)
                r["app_write_ok"] = True
            except Exception as e:
                r["app_write_ok"] = False
                r["app_err"] = f"write {type(e).__name__}: {e}"
            try:
                d = s.recv(4096)
                r["app_read"] = (d[:200].decode("latin1", "replace") if d
                                 else "<EOF>")
            except ssl.SSLError as e:
                r["app_err"] = f"read SSLError: {e}"
            except Exception as e:
                r["app_err"] = f"read {type(e).__name__}: {e}"
    except ssl.SSLError as e:
        r["handshake"] = "failed"; r["hs_err"] = f"SSLError: {e}"
    except Exception as e:
        r["handshake"] = "failed"; r["hs_err"] = f"{type(e).__name__}: {e}"
    finally:
        for x in (s, raw):
            try:
                if x: x.close()
            except Exception:
                pass
    return r

def show(r, tag=""):
    hs = r["handshake"]
    verdict = "BLOCKED" if (r["app_read"] in (None, "<EOF>") or
                             (r["app_err"] or "").find("alert") >= 0) else "DATA"
    print(f"[{verdict:7s}] {tag:26s} hs={hs:9s} cert={r['cert_sha']} "
          f"subj={r['subject']} alpn={r['alpn']} "
          f"read={(r['app_read'] or '')!r} err={(r['app_err'] or r['hs_err'] or '')[:90]}",
          flush=True)
    return verdict

def main():
    os.makedirs(EVID, exist_ok=True)
    rows = []
    print("=== 1. SNI matrix, TLS1.3, application round-trip after handshake ===", flush=True)
    for sni in SNIS:
        r = attempt(sni); rows.append(r); show(r, f"sni={str(sni)[:22]}")

    certs = {}
    for r in rows:
        if r["cert_sha"]:
            certs.setdefault(r["cert_sha"], []).append(r["sni"])
    print(f"\ndistinct server certs across {len(rows)} SNIs: {len(certs)}")
    for k, v in certs.items():
        print(f"  {k} <- {v}")

    print("\n=== 2. ALPN matrix (SNI=tbox) ===", flush=True)
    alpn_rows = []
    for alpn in ALPNS:
        r = attempt("tbox", alpn); alpn_rows.append(r); show(r, f"alpn={alpn}")

    print("\n=== 3. TLS version pinning ===", flush=True)
    ver_rows = []
    for label, v in [("1.3", ssl.TLSVersion.TLSv1_3), ("1.2", ssl.TLSVersion.TLSv1_2)]:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
        c.minimum_version = v; c.maximum_version = v
        raw = socket.socket(); raw.settimeout(6)
        try:
            raw.connect((HOST, PORT))
            s = c.wrap_socket(raw, server_hostname="tbox")
            info = f"hs=completed ver={s.version()} cipher={s.cipher()[0] if s.cipher() else None}"
            s.close()
        except Exception as e:
            info = f"hs=failed {type(e).__name__}: {e}"
        finally:
            try: raw.close()
            except Exception: pass
        ver_rows.append({"pin": label, "result": info})
        print(f"  pin TLS{label}: {info}", flush=True)

    print("\n=== 4. openssl cross-checks (stdin=DEVNULL, no shell redirect) ===", flush=True)
    sessdir = os.path.join(EVID, "tls_probe")
    os.makedirs(sessdir, exist_ok=True)
    sess = os.path.join(sessdir, "w2_sess.pem")
    cmds = [
        ("sess_out_on_failing_handshake",
         ["s_client", "-connect", "10.230.164.3:8443", "-tls1_3", "-servername", "tbox",
          "-sess_out", sess]),
        ("sess_in_reuse",
         ["s_client", "-connect", "10.230.164.3:8443", "-tls1_3", "-servername", "tbox",
          "-sess_in", sess]),
        ("alpn_h2", ["s_client", "-connect", "10.230.164.3:8443", "-tls1_3",
                     "-servername", "tbox", "-alpn", "h2"]),
        ("alpn_doip", ["s_client", "-connect", "10.230.164.3:8443", "-tls1_3",
                       "-servername", "tbox", "-alpn", "doip"]),
        ("ciphersuite_ccm", ["s_client", "-connect", "10.230.164.3:8443", "-tls1_3",
                             "-ciphersuites", "TLS_AES_128_CCM_SHA256"]),
        ("ciphersuite_ccm8", ["s_client", "-connect", "10.230.164.3:8443", "-tls1_3",
                              "-ciphersuites", "TLS_AES_128_CCM_8_SHA256"]),
        ("group_x25519mlkem768", ["s_client", "-connect", "10.230.164.3:8443", "-tls1_3",
                                  "-groups", "X25519MLKEM768"]),
        ("early_data", ["s_client", "-connect", "10.230.164.3:8443", "-tls1_3",
                        "-servername", "tbox", "-early_data"]),
        ("no_sni", ["s_client", "-connect", "10.230.164.3:8443", "-tls1_3", "-noservername"]),
        ("status_request_ocsp", ["s_client", "-connect", "10.230.164.3:8443", "-tls1_3",
                                 "-servername", "tbox", "-status"]),
    ]
    out = []
    for name, argv in cmds:
        line = f"\n##### {name}\n$ openssl {' '.join(argv)}\n"
        try:
            p = subprocess.run(["openssl"] + argv, capture_output=True, timeout=25,
                               stdin=subprocess.DEVNULL, text=True, errors="replace")
            body = (p.stdout or "") + (p.stderr or "")
        except Exception as e:
            body = f"<run failed: {e}>"
        keep = [ln for ln in body.splitlines()
                if any(k in ln for k in ("ALPN", "New, TLS", "Early data", "Cipher is",
                                         "alert", "error", "Session-ID", "SSL-Session",
                                         "Verify return", "Server Temp Key", "OCSP",
                                         "Peer signature", "no peer certificate",
                                         "NotBefore", "not found", "unsupported",
                                         "no protocols", "unable"))]
        line += "\n".join(keep[:25]) if keep else "\n".join(body.splitlines()[:20])
        print(line, flush=True)
        out.append(line)
    open(os.path.join(EVID, "8443_tls2_openssl.txt"), "w", encoding="utf-8").write("\n".join(out))

    open(os.path.join(EVID, "tls2_8443_matrix.json"), "w", encoding="utf-8").write(
        json.dumps({"sni": rows, "alpn": alpn_rows, "version": ver_rows}, indent=1))
    blocked = sum(1 for r in rows if (r["app_read"] in (None, "<EOF>")))
    print(f"\nSNI rows={len(rows)} blocked_after_hs={blocked} "
          f"distinct_certs={len(certs)}")

if __name__ == "__main__":
    main()

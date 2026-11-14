#!/usr/bin/env python3
"""8443 TLS-layer deep probe.

New angles vs the prior round (which only tried SNI empty + one wrong name):
  1. SNI matrix (17 names).  If the leaf certificate or the client-cert
     requirement changes per SNI, tls.Config is being selected per-name
     (GetConfigForClient) -> possibly a non-mTLS endpoint exists.
  2. ALPN matrix per interesting SNI (h2 / http/1.1 / doip / doip-v1 / tls).
  3. TLS 1.2 forced, TLS 1.3 forced, and a naive TLS1.1 probe.
  4. Session resumption: attempt sess_out on a handshake that *fails* at the
     client-cert step, then reuse -> proves whether a ticket can ever be issued
     before authentication.
  5. 0-RTT early data attempt.
  6. Named group / key-share observation (Go >= 1.24 offers X25519MLKEM768).
"""
import hashlib, json, os, socket, ssl, base64, sys, time

HOST, PORT = "10.230.164.3", 8443
EVID = os.path.join(os.path.dirname(__file__), "..", "..", "..", "03_EVIDENCE", "web")

SNIS = [None, "", "tbox", "tsp", "cv6", "ota", "fleet", "update", "diagnostics",
        "localhost", "tbox.cv6", "ota.cv6.local", "cv6-fleet.local", "admin",
        "a" * 40 + ".com", "10.230.164.3", "tbox." + "a" * 40]

ALPNS = [None, ["h2"], ["http/1.1"], ["doip"], ["doip-v1"], ["h2", "http/1.1"],
         ["tls"], ["coap"], ["mqtt"]]

def ctx_for(alpn=None, minv=None, maxv=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    if minv:
        c.minimum_version = minv
    if maxv:
        c.maximum_version = maxv
    if alpn:
        c.set_alpn_protocols(alpn)
    return c

def attempt(sni, alpn=None, minv=None, maxv=None, timeout=6.0, sess=None,
            early_data=False):
    c = ctx_for(alpn, minv, maxv)
    raw = socket.socket()
    raw.settimeout(timeout)
    res = {"sni": sni, "alpn_req": alpn, "ok": False, "err": None,
           "alpn": None, "cipher": None, "version": None,
           "peer_subject": None, "peer_issuer": None, "peer_serial": None,
           "peer_san": None, "peer_sha256": None, "ticket": None,
           "shared_ciphers": None}
    try:
        raw.connect((HOST, PORT))
        kw = {}
        if sni is not None and sni != "":
            kw["server_hostname"] = sni
        else:
            # explicit empty SNI: python sends SNI only if server_hostname set
            kw["server_hostname"] = None
        s = c.wrap_socket(raw, **kw)
        res["ok"] = True
        res["alpn"] = s.selected_alpn_protocol()
        res["cipher"] = s.cipher()[0] if s.cipher() else None
        res["version"] = s.version()
        der = s.getpeercert(binary_form=True)
        if der:
            res["peer_sha256"] = hashlib.sha256(der).hexdigest()[:32]
            pd = s.getpeercert()
            res["peer_subject"] = str(pd.get("subject"))
            res["peer_issuer"] = str(pd.get("issuer"))
            res["peer_serial"] = pd.get("serialNumber")
            res["peer_san"] = str(pd.get("subjectAltName"))
        try:
            res["shared_ciphers"] = [x[0] for x in (s.shared_ciphers() or [])][:6]
        except Exception:
            pass
        s.close()
    except ssl.SSLError as e:
        res["err"] = f"SSLError: {e}"
    except Exception as e:
        res["err"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            raw.close()
        except Exception:
            pass
    return res

def first_line(s):
    return (s or "").split("\n")[0][:200]

def main():
    os.makedirs(EVID, exist_ok=True)
    rows = []
    certs = {}

    print("=== 1. SNI matrix (TLS1.3, no ALPN, no client cert) ===", flush=True)
    for sni in SNIS:
        r = attempt(sni)
        rows.append(r)
        tag = "OK " if r["ok"] else "ERR"
        print(f"[{tag}] sni={str(sni)[:46]:46s} ver={r['version']} cipher={r['cipher']} "
              f"cert={r['peer_sha256']} subj={r['peer_subject']}", flush=True)
        if not r["ok"]:
            print(f"       err={first_line(r['err'])}", flush=True)
        if r["peer_sha256"]:
            certs.setdefault(r["peer_sha256"], []).append(sni)

    print(f"\n=== distinct server certs across SNIs: {len(certs)} ===", flush=True)
    for k, v in certs.items():
        print(f"  {k} <- {v}", flush=True)

    print("\n=== 2. ALPN matrix (SNI=tbox) ===", flush=True)
    for alpn in ALPNS:
        r = attempt("tbox", alpn)
        rows.append(r)
        print(f"[{'OK ' if r['ok'] else 'ERR'}] alpn_req={str(alpn):26s} -> selected={r['alpn']} "
              f"ver={r['version']} err={first_line(r['err'])}", flush=True)

    print("\n=== 3. TLS version pinning ===", flush=True)
    for label, kwargs in [
        ("TLS1.3 only", dict(minv=ssl.TLSVersion.TLSv1_3, maxv=ssl.TLSVersion.TLSv1_3)),
        ("TLS1.2 only", dict(minv=ssl.TLSVersion.TLSv1_2, maxv=ssl.TLSVersion.TLSv1_2)),
        ("TLS1.1 only", dict(minv=ssl.TLSVersion.TLSv1_1, maxv=ssl.TLSVersion.TLSv1_1)),
        ("TLS1.0 only", dict(minv=ssl.TLSVersion.TLSv1, maxv=ssl.TLSVersion.TLSv1)),
    ]:
        r = attempt("tbox", None, **kwargs)
        rows.append(dict(r, note=label))
        print(f"[{'OK ' if r['ok'] else 'ERR'}] {label:14s} ver={r['version']} "
              f"cipher={r['cipher']} err={first_line(r['err'])}", flush=True)

    print("\n=== 4. session ticket on an unauthenticated handshake ===", flush=True)
    # An unauthenticated handshake dies at the client-cert step; if the server
    # ever hands out a ticket before that, resumption could skip client auth.
    # python's ssl exposes session only via wrap_socket(..., session=...) on client
    r = attempt("tbox")
    print(f"  first attempt ok={r['ok']} err={first_line(r['err'])}", flush=True)
    print("  (python ssl does not surface a session object unless the handshake "
          "completed, so a ticket cannot exist -- see openssl cross-check below)")

    # openssl cross-check: -sess_out on a handshake that will fail
    print("\n=== 5. openssl cross-checks ===", flush=True)
    import subprocess
    oo = os.path.join(EVID, "8443_tls2_openssl.txt")
    cmds = [
        ("sess_out_on_failing_handshake",
         "openssl s_client -connect 10.230.164.3:8443 -tls1_3 -servername tbox "
         f"-sess_out {os.path.join(EVID,'tls_probe','w2_sess.pem')} </dev/null"),
        ("sess_in_reuse",
         f"openssl s_client -connect 10.230.164.3:8443 -tls1_3 -servername tbox "
         f"-sess_in {os.path.join(EVID,'tls_probe','w2_sess.pem')} </dev/null"),
        ("alpn_h2", "openssl s_client -connect 10.230.164.3:8443 -tls1_3 -servername tbox -alpn h2 </dev/null"),
        ("alpn_doip", "openssl s_client -connect 10.230.164.3:8443 -tls1_3 -servername tbox -alpn doip </dev/null"),
        ("ciphersuite_ccm", "openssl s_client -connect 10.230.164.3:8443 -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 </dev/null"),
        ("ciphersuite_ccm8", "openssl s_client -connect 10.230.164.3:8443 -tls1_3 -ciphersuites TLS_AES_128_CCM_8_SHA256 </dev/null"),
        ("group_mlkem", "openssl s_client -connect 10.230.164.3:8443 -tls1_3 -groups X25519MLKEM768 </dev/null"),
        ("early_data", "openssl s_client -connect 10.230.164.3:8443 -tls1_3 -early_data </dev/null"),
        ("no_sni", "openssl s_client -connect 10.230.164.3:8443 -tls1_3 -noservername </dev/null"),
    ]
    out = []
    for name, cmd in cmds:
        line = f"\n##### {name}\n$ {cmd}\n"
        try:
            p = subprocess.run(cmd, shell=True, capture_output=True, timeout=20,
                               text=True, errors="replace")
            body = (p.stdout or "") + (p.stderr or "")
        except Exception as e:
            body = f"<timeout/fail {e}>"
        keep = []
        for ln in body.splitlines():
            if any(k in ln for k in ("ALPN", "New, TLS", "Early data", "Cipher is",
                                     "alert", "error", "Session-ID", "TLS session",
                                     "Verify return", "Server Temp Key", "sess",
                                     "no peer certificate", "Peer signature",
                                     "CN =", "not found", "unsupported", "no protocols")):
                keep.append(ln)
        if not keep:
            keep = body.splitlines()[:12]
        line += "\n".join(keep)
        print(line, flush=True)
        out.append(line)
    open(oo, "w", encoding="utf-8").write("\n".join(out))

    p = os.path.join(EVID, "tls2_8443_matrix.json")
    open(p, "w", encoding="utf-8").write(json.dumps(rows, indent=1))
    print(f"\nwrote {p} and {oo}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Static-artifact hunt: directory/file cartesian product against .2:8080 and .3:8080.

Rationale for doing this at all (prior round only tried exact words):
  http.FileServer mounted at /pki/ returns "404 page not found" for missing
  children -- indistinguishable from the mux's own 404.  But it answers
  GET /pki/  (trailing slash) with either an HTML directory listing (200) or
  403 / 301.  So directory-slash probes are the discriminator, and only after a
  directory answers do child filenames become meaningful.

Rate limited to <= 20 req/s.  Read-only GET/HEAD only.
"""
import json, os, socket, sys, time

EVID = os.path.join(os.path.dirname(__file__), "..", "..", "..", "03_EVIDENCE", "web")
TARGETS = [("10.230.164.2", 8080), ("10.230.164.3", 8080)]

DIRS = ["", "static", "assets", "files", "file", "download", "downloads", "dl",
        "ota", "updates", "update", "firmware", "fw", "pki", "certs", "cert",
        "certificates", "keys", "crypto", "crypt", "private", "secrets", "secure",
        "public", "www", "html", "data", "share", "packages", "package", "releases",
        "release", "artifacts", "artifact", "blob", "store", "storage", "repo",
        "dist", "media", "var", "opt", "srv", "backup", "backups", "config",
        "conf", "etc", "mnt", "root", "api", "v1", "v2", "internal", "admin",
        "debug", "meta", "manifest", "manifests", "trust", "provisioning",
        "bootstrap", "enroll", "ca", "x509", "tls", "ssl", ".well-known"]

BASES = ["ca", "root", "rootca", "root-ca", "ca-root", "client", "client-cert",
         "server", "server-cert", "tbox", "device", "fleet", "cv6", "cv6-root",
         "cv6-ca", "tsp", "ota", "intermediate", "inter", "leaf", "trust",
         "truststore", "keystore", "signing", "signer", "upload", "private",
         "provisioning", "diagnostics", "bootstrap", "fleet-diagnostics-root",
         "cv6-fleet-diagnostics-root", "chain", "bundle", "fullchain"]
EXTS = [".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".jks", ".b64",
        ".txt", ".json", ""]

FIRMWARE = ["firmware.bin", "firmware.img", "firmware.zip", "firmware.tar.gz",
            "firmware.tar", "fw.bin", "fw.img", "ota.bin", "ota.img", "ota.zip",
            "update.bin", "update.zip", "update.img", "tbox.bin", "tbox.img",
            "tbox.zip", "cv6.bin", "cv6.img", "cv6.zip", "bms.bin", "bms.img",
            "vcu.bin", "vcu.img", "cgw.bin", "cgw.img", "rootfs.img", "rootfs.bin",
            "system.img", "boot.img", "app.bin", "app.img", "app.apk",
            "latest.json", "index.json", "manifest.json", "manifest.txt",
            "checksums.txt", "sha256sums", "sha256sums.txt", "SHA256SUMS",
            "signature.bin", "signature.sig", "firmware.sig", "ota.sig",
            "release.json", "version.json", "version.txt", "VERSION"]

def raw_req(ip, port, method, path, timeout=5.0):
    req = (f"{method} {path} HTTP/1.1\r\nHost: {ip}:{port}\r\n"
           f"Connection: close\r\n\r\n").encode()
    s = socket.socket()
    s.settimeout(timeout)
    buf = b""
    err = None
    try:
        s.connect((ip, port))
        s.sendall(req)
        while len(buf) < 524288:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    finally:
        try:
            s.close()
        except Exception:
            pass
    i = buf.find(b"\r\n\r\n")
    head, body = (buf[:i], buf[i + 4:]) if i >= 0 else (buf, b"")
    status = head.split(b"\r\n")[0].decode("latin1") if head else ""
    return status, body, err

def main():
    os.makedirs(EVID, exist_ok=True)
    rows = []
    t0 = time.time()
    n = 0

    def tick():
        nonlocal n
        n += 1
        dt = time.time() - t0
        if dt < n / 20.0:
            time.sleep(n / 20.0 - dt)

    def probe(ip, port, path, method="GET", phase=""):
        tick()
        st, body, err = raw_req(ip, port, method, path)
        is404 = "404" in st
        row = {"target": f"{ip}:{port}", "path": path, "method": method,
               "phase": phase, "status": st, "len": len(body),
               "preview": body[:200].decode("latin1", "replace"), "err": err}
        rows.append(row)
        if not is404:
            print(f"[!] {ip}:{port} {method} {path:52s} {st} len={len(body)} "
                  f"{body[:100]!r}", flush=True)
        return row

    # ---- Phase 1: directory-slash probes (the discriminator)
    print("=== phase1: directory slash probes ===", flush=True)
    for ip, port in TARGETS:
        for d in DIRS:
            if not d:
                continue
            probe(ip, port, f"/{d}/", phase="dir")
            probe(ip, port, f"/{d}", phase="dir-noslash")

    # ---- Phase 2: cert material
    print("=== phase2: cert/key material cartesian ===", flush=True)
    for ip, port in TARGETS:
        for d in ["", "pki", "certs", "keys", "crypto", "secrets", "ca", "tls",
                  "static", "files", "downloads", "ota", "firmware", ".well-known"]:
            pfx = f"/{d}" if d else ""
            for b in BASES:
                for e in EXTS:
                    probe(ip, port, f"{pfx}/{b}{e}", phase="cert")

    # ---- Phase 3: firmware artifacts
    print("=== phase3: firmware artifacts ===", flush=True)
    for ip, port in TARGETS:
        for d in ["", "firmware", "ota", "updates", "downloads", "files",
                  "static", "releases", "packages", "artifacts", "dist"]:
            pfx = f"/{d}" if d else ""
            for f in FIRMWARE:
                probe(ip, port, f"{pfx}/{f}", phase="firmware")

    hits = [r for r in rows if "404" not in r["status"] and r["status"]]
    out = {"total": len(rows), "non404": hits, "all": rows}
    p = os.path.join(EVID, "static_hunt_w2.json")
    open(p, "w", encoding="utf-8").write(json.dumps(out, indent=1))
    print(f"\ntotal={len(rows)} non404={len(hits)} -> {p}")
    for h in hits:
        print(f"  {h['target']} {h['path']} {h['status']} {h['preview'][:120]!r}")

if __name__ == "__main__":
    main()

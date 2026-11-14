#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Second-stage probes that a path dictionary cannot cover.

  1. retry the paths that timed out during the scans (close the hole)
  2. virtual-host sweep: same path, different Host header
  3. h2c prior-knowledge / Upgrade: h2c
  4. does 8080 speak TLS at all?
  5. latency sweep (is the server periodically stalling?)
  6. content-negotiation / odd-header probes on /healthz
"""
import socket
import ssl
import sys
import time
import json

import requests

HOSTS = ["10.230.164.4", "10.229.221.2"]
PORT = 8080
OUT = {}

ERR_PATHS = ["/__admin/target", "/__admin/tx", "/__admin/trace",
             "/__admin/uds", "/__admin/up", "/__admin/vehicle",
             "/obd/activate/zzq7x", "/raw/connect/zzq7x", "/raw/control/zzq7x"]

VHOSTS = ["localhost", "127.0.0.1", "cgw", "cgw.local", "gateway", "gateway.local",
          "diag.local", "admin.local", "internal", "vehicle", "car",
          "CV6FF52FEE9EDDD86", "cv6.local", "tbox", "tbox.local", "ecu",
          "fleet", "fleet.local", "secoc.local", "can.local", "canfd.local"]
VHOST_PATHS = ["/", "/healthz", "/diag", "/api", "/bridge"]


def raw(host, payload, read_for=3.0):
    try:
        s = socket.create_connection((host, PORT), timeout=6)
        s.settimeout(read_for)
        s.sendall(payload)
        buf = b""
        t0 = time.time()
        while time.time() - t0 < read_for:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
            if len(buf) > 200000:
                break
        s.close()
        return buf
    except Exception as e:
        return ("<<%s: %s>>" % (type(e).__name__, e)).encode()


def brief(rawbytes):
    head, _, body = rawbytes.partition(b"\r\n\r\n")
    first = head.split(b"\r\n")[0].decode("latin-1") if head else ""
    return {"status": first, "len": len(body),
            "body": body[:200].decode("latin-1")}


def stage(who, fn):
    print("\n########## %s ##########" % who)
    OUT[who] = fn()


def run():
    host = HOSTS[0]

    # ---- 1. retry previously timed-out paths, both hosts
    def s1():
        res = {}
        for h in HOSTS:
            res[h] = {}
            s = requests.Session()
            for p in ERR_PATHS:
                try:
                    r = s.get("http://%s:%d%s" % (h, PORT, p), timeout=15,
                              allow_redirects=False)
                    res[h][p] = [r.status_code, len(r.content)]
                except Exception as e:
                    res[h][p] = ["ERR", str(e)[:60]]
            s.close()
        for h in HOSTS:
            for p, v in res[h].items():
                print("  %-24s %-22s %s" % (h, p, v))
        return res

    # ---- 2. vhost sweep
    def s2():
        res = {}
        s = requests.Session()
        for vh in VHOSTS:
            row = {}
            for p in VHOST_PATHS:
                try:
                    r = s.get("http://%s:%d%s" % (host, PORT, p), timeout=8,
                              headers={"Host": vh}, allow_redirects=False)
                    row[p] = [r.status_code, len(r.content)]
                except Exception as e:
                    row[p] = ["ERR", str(e)[:40]]
            res[vh] = row
            sig = sorted(set(tuple(v) for v in row.values()))
            print("  Host: %-20s -> %s" % (vh, sig))
        s.close()
        return res

    # ---- 3. h2c prior knowledge + Upgrade
    def s3():
        res = {}
        r1 = raw(host, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        res["h2c_prior"] = brief(r1)
        print("  h2c prior-knowledge : %r" % (r1[:120]))
        r2 = raw(host,
                 b"GET /healthz HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade, HTTP2-Settings\r\n"
                 b"Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n" % host.encode())
        res["h2c_upgrade"] = brief(r2)
        print("  h2c upgrade         : %r" % (r2[:200]))
        return res

    # ---- 4. TLS on 8080?
    def s4():
        res = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, PORT), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ts:
                    res["tls"] = {"version": ts.version(),
                                  "cipher": ts.cipher()[0] if ts.cipher() else None,
                                  "cert": str(ts.getpeercert())}
                    print("  TLS OK?! %s" % res["tls"])
        except Exception as e:
            res["tls"] = "no: %s: %s" % (type(e).__name__, str(e)[:80])
            print("  TLS on 8080         : %s" % res["tls"])
        return res

    # ---- 5. latency sweep: 120 sequential requests, log outliers
    def s5():
        s = requests.Session()
        lat = []
        t_start = time.time()
        for i in range(120):
            p = "/healthz" if i % 2 == 0 else "/nope%d" % i
            t0 = time.time()
            try:
                r = s.get("http://%s:%d%s" % (host, PORT, p), timeout=20,
                          allow_redirects=False)
                ms = (time.time() - t0) * 1000
                lat.append((i, p, r.status_code, round(ms)))
            except Exception as e:
                lat.append((i, p, "ERR", str(e)[:40]))
        s.close()
        nums = [x[3] for x in lat if isinstance(x[3], int)]
        print("  n=%d elapsed=%.1fs min=%d p50=%d max=%d"
              % (len(lat), time.time() - t_start, min(nums),
                 sorted(nums)[len(nums) // 2], max(nums)))
        for x in lat:
            if not isinstance(x[3], int) or x[3] > 500:
                print("  OUTLIER %s" % (x,))
        return lat

    # ---- 6. header / negotiation oddities on /healthz
    def s6():
        s = requests.Session()
        res = {}
        cases = {
            "accept-json": {"Accept": "application/json"},
            "accept-xml": {"Accept": "application/xml"},
            "accept-any-none": {"Accept": ""},
            "x-forwarded-for": {"X-Forwarded-For": "127.0.0.1"},
            "x-real-ip": {"X-Real-IP": "127.0.0.1"},
            "x-api-key": {"X-Api-Key": "test"},
            "authorization": {"Authorization": "Bearer test"},
            "x-diag": {"X-Diag": "1"},
            "content-type-json": {"Content-Type": "application/json"},
            "range": {"Range": "bytes=0-4"},
            "expect100": {"Expect": "100-continue"},
        }
        for k, hh in cases.items():
            try:
                r = s.get("http://%s:%d/healthz" % (host, PORT), headers=hh,
                          timeout=8, allow_redirects=False)
                res[k] = [r.status_code, r.headers.get("Content-Type"), r.text[:40]]
            except Exception as e:
                res[k] = ["ERR", str(e)[:50]]
            print("  %-18s %s" % (k, res[k]))
        s.close()
        return res

    for name, fn in [("retry_timeouts", s1), ("vhost_sweep", s2),
                     ("h2c", s3), ("tls_8080", s4),
                     ("latency", s5), ("healthz_headers", s6)]:
        stage(name, fn)

    with open(sys.argv[1] if len(sys.argv) > 1 else "probe2.json", "w",
              encoding="utf-8") as f:
        json.dump(OUT, f, indent=2, default=str)
    print("\nwritten.")


if __name__ == "__main__":
    run()

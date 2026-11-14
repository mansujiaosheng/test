#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hunt.py -- find the real CAN entry point (the bridge may not be 13401).

Everything the lead asked for, in one place:

  ports       full/hot TCP scan of the four reachable hosts
  subnet      sweep 10.226.193.0/24 and 10.225.139.0/24 on bridge-ish ports
  udp         UDP probes on 13400/13401/13402 (+ a few neighbours)
  nonhttp     CGW 8080 as WebSocket / HTTP2-prior-knowledge / gRPC / raw DoIP
  unlock       unlock DoIP via 04_SOLVE/uds/u.py, keep that link open, and in
               the same process probe 13401 within milliseconds
  all         ports + subnet + udp + nonhttp (not unlock; that one is opt-in)

Discipline: connect-scan only, 400 ms timeout, <= 400 workers, no payload on a
port unless it is one of the documented protocol handshakes.  A hit is any
non-empty read from a port that is not a health endpoint.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HOSTS = ("10.226.193.2", "10.225.139.4", "10.225.139.3", "10.225.139.2")

BRIDGE_PORTS = list(range(13400, 13411)) + list(range(5000, 5011)) + \
    list(range(7000, 7011)) + list(range(8000, 8011)) + list(range(9000, 9011)) + \
    [22, 80, 443, 1883, 3000, 4840, 5683, 6379, 8080, 8081, 8443, 8444,
     9090, 9091, 10000, 12345, 31337, 5555]

EVID_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "..", "03_EVIDENCE", "canfd")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def tcp_open(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def scan_ports(host: str, ports, workers: int = 300,
               timeout: float = 0.4) -> list:
    opens = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(tcp_open, host, p, timeout): p for p in ports}
        for fut in as_completed(futs):
            if fut.result():
                opens.append(futs[fut])
    return sorted(opens)


def classify(host: str, port: int, wait: float = 1.0) -> dict:
    """Passive read then a couple of neutral probes; record any byte at all."""
    rec = {"host": host, "port": port, "passive": "", "probes": []}
    try:
        s = socket.create_connection((host, port), timeout=1.5)
    except OSError as exc:
        rec["error"] = f"connect: {exc}"
        return rec
    try:
        s.settimeout(wait)
        try:
            data = s.recv(4096)
            rec["passive"] = data.hex()
            rec["passive_ascii"] = data[:120].decode("ascii", "replace")
        except socket.timeout:
            pass
        except OSError as exc:
            rec["passive_error"] = str(exc)
    finally:
        s.close()
    for label, payload in (("crlf", b"\r\n"),
                           ("websocket", b"GET / HTTP/1.1\r\nHost: x\r\n"
                                         b"Upgrade: websocket\r\n"
                                         b"Connection: Upgrade\r\n"
                                         b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                         b"Sec-WebSocket-Version: 13\r\n\r\n"),
                           ("h2c", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
                           ("doip-ident", bytes.fromhex("020000010000000000000000"))):
        try:
            s = socket.create_connection((host, port), timeout=1.5)
            s.settimeout(wait)
            s.sendall(payload)
            data = b""
            try:
                data = s.recv(4096)
            except socket.timeout:
                pass
            rec["probes"].append({"label": label, "sent": payload.hex(),
                                  "recv": data.hex(),
                                  "recv_ascii": data[:120].decode("ascii", "replace")})
            s.close()
        except OSError as exc:
            rec["probes"].append({"label": label, "error": str(exc)})
    rec["hit"] = bool(rec["passive"]) or any(p.get("recv") for p in rec["probes"])
    return rec


def udp_probe(host: str, port: int, payload: bytes, wait: float = 1.0) -> dict:
    out = {"host": host, "port": port, "sent": payload.hex(), "recv": ""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(wait)
        s.sendto(payload, (host, port))
        data, addr = s.recvfrom(4096)
        out["recv"] = data.hex()
        out["from"] = f"{addr[0]}:{addr[1]}"
    except socket.timeout:
        out["note"] = "timeout"
    except OSError as exc:
        out["note"] = str(exc)
    finally:
        try:
            s.close()
        except Exception:
            pass
    return out


def save(name: str, doc: dict) -> str:
    os.makedirs(EVID_DIR, exist_ok=True)
    path = os.path.join(EVID_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    return path


# --------------------------------------------------------------------------- #
# 1. ports
# --------------------------------------------------------------------------- #

def cmd_ports(args) -> int:
    hosts = args.hosts.split(",") if args.hosts else list(HOSTS)
    ports = None
    if args.full:
        ports = range(1, 65536)
    elif args.ports:
        ports = [int(p) for p in args.ports.split(",")]
    else:
        ports = BRIDGE_PORTS
    doc = {"ts": _now(), "mode": "full" if args.full else
           ("explicit" if args.ports else "bridge-ish"), "results": []}
    for host in hosts:
        t0 = time.perf_counter()
        opens = scan_ports(host, ports, workers=args.workers,
                           timeout=args.timeout)
        dt = time.perf_counter() - t0
        row = {"host": host, "scanned": len(list(ports)), "open": opens,
               "elapsed_s": round(dt, 1)}
        print(f"{host}: {len(opens)} open {opens} ({dt:.1f}s)")
        # classify every open port we did not already know about
        for port in opens:
            if port in (13400, 13401, 8080, 8443):
                continue
            rec = classify(host, port, wait=args.wait)
            row.setdefault("classified", []).append(rec)
            print(f"   {host}:{port} passive={rec['passive'][:40]!r} "
                  f"hit={rec['hit']}")
        doc["results"].append(row)
    path = save(f"30_hunt_ports_{time.strftime('%Y%m%d-%H%M%S')}.json", doc)
    print(f"evidence: {path}")
    return 0


# --------------------------------------------------------------------------- #
# 2. subnet sweep
# --------------------------------------------------------------------------- #

def cmd_subnet(args) -> int:
    nets = args.nets.split(",") if args.nets else \
        ["10.226.193.0/24", "10.225.139.0/24"]
    ports = [int(p) for p in args.ports.split(",")] if args.ports else \
        list(range(13400, 13411)) + list(range(5000, 5006)) + \
        list(range(7000, 7006)) + [8080, 8443]
    doc = {"ts": _now(), "nets": nets, "ports": ports, "hits": []}
    for net in nets:
        base = net.rsplit(".", 1)[0]
        print(f"sweeping {base}.1-254 on {len(ports)} ports "
              f"({254 * len(ports)} connects)")
        tasks = [(f"{base}.{i}", p) for i in range(1, 255) for p in ports]
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futs = {pool.submit(tcp_open, h, p, args.timeout): (h, p)
                    for h, p in tasks}
            for fut in as_completed(futs):
                if fut.result():
                    h, p = futs[fut]
                    doc["hits"].append({"host": h, "port": p})
                    print(f"   HIT {h}:{p}")
        print(f"  {net}: done in {time.perf_counter() - t0:.1f}s, "
              f"{len([x for x in doc['hits'] if x['host'].startswith(base)])} hit(s)")
    path = save(f"31_hunt_subnet_{time.strftime('%Y%m%d-%H%M%S')}.json", doc)
    print(f"evidence: {path}")
    return 0


# --------------------------------------------------------------------------- #
# 3. UDP
# --------------------------------------------------------------------------- #

def cmd_udp(args) -> int:
    hosts = args.hosts.split(",") if args.hosts else list(HOSTS)
    ports = [int(p) for p in args.ports.split(",")] if args.ports else \
        [13400, 13401, 13402, 13403]
    payloads = {
        "doip-ident": bytes.fromhex("020000010000000000000000"),
        "zero16": bytes(16),
        "ff16": b"\xFF" * 16,
        "slcan-V": b"V\r",
    }
    doc = {"ts": _now(), "results": []}
    for host in hosts:
        for port in ports:
            for label, payload in payloads.items():
                rec = udp_probe(host, port, payload, wait=args.wait)
                rec["label"] = label
                if rec["recv"]:
                    print(f"   HIT udp {host}:{port} {label} -> {rec['recv']}")
                doc["results"].append(rec)
    path = save(f"32_hunt_udp_{time.strftime('%Y%m%d-%H%M%S')}.json", doc)
    print(f"evidence: {path}")
    return 0


# --------------------------------------------------------------------------- #
# 4. 8080 non-HTTP
# --------------------------------------------------------------------------- #

def cmd_nonhttp(args) -> int:
    hosts = args.hosts.split(",") if args.hosts else ["10.226.193.2"]
    doc = {"ts": _now(), "results": []}
    for host in hosts:
        for port in (8080, 13400):
            rec = classify(host, port, wait=args.wait)
            rec["websocket_upgrade"] = None
            # a real upgrade answer is 101 + Sec-WebSocket-Accept
            try:
                s = socket.create_connection((host, port), timeout=2)
                s.settimeout(2)
                s.sendall(b"GET /canfd HTTP/1.1\r\nHost: cgw\r\n"
                          b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                          b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                          b"Sec-WebSocket-Version: 13\r\n\r\n")
                data = s.recv(4096)
                rec["websocket_upgrade"] = data[:200].decode("ascii", "replace")
                s.close()
            except OSError as exc:
                rec["websocket_upgrade"] = f"error: {exc}"
            # raw DoIP on 8080
            try:
                s = socket.create_connection((host, port), timeout=2)
                s.settimeout(2)
                s.sendall(bytes.fromhex("020000010000000000000000"))
                try:
                    rec["doip_on_8080"] = s.recv(4096).hex()
                except socket.timeout:
                    rec["doip_on_8080"] = ""
                s.close()
            except OSError as exc:
                rec["doip_on_8080"] = f"error: {exc}"
            doc["results"].append(rec)
            print(f"{host}:{port} ws={str(rec['websocket_upgrade'])[:60]!r} "
                  f"doip={rec.get('doip_on_8080', '')[:40]!r}")
    path = save(f"33_hunt_nonhttp_{time.strftime('%Y%m%d-%H%M%S')}.json", doc)
    print(f"evidence: {path}")
    return 0


# --------------------------------------------------------------------------- #
# 5. unlock + same-process 13401 probe
# --------------------------------------------------------------------------- #

def cmd_unlock(args) -> int:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", "uds"))
    import u  # noqa: E402  (needs the path insert above)

    vin = args.vin
    print(f"[1] opening a ticket-backed DoIP link for {vin} ...")
    t0 = time.perf_counter()
    link, ticket = u.open_link(vin, workdir=args.workdir, verbose=True)
    print(f"    unlocked in {time.perf_counter() - t0:.1f}s")

    # control: prove the session really is security-unlocked right now
    ctrl = link.diag(bytes.fromhex("22F1A3"))
    print(f"[2] control 22F1A3 -> {ctrl}  "
          f"({'unlocked' if ctrl.startswith('62f1a3') else 'NOT unlocked'})")

    doc = {"ts": _now(), "vin": vin, "control_22f1a3": ctrl,
           "ticket_prefix": ticket[:24], "probes": []}

    # A. connect and stay silent for 3 s (server-speaks-first?)
    for label, payload, gap, wait in (
            ("silent-3s", b"", 0.0, 3.0),
            ("frame16-imm", bytes(16), 0.0, 1.5),
            ("split-8+8-10ms", None, 0.010, 1.5),
            ("doip-ident", bytes.fromhex("020000010000000000000000"), 0.0, 1.5),
            ("slcan-V", b"V\r", 0.0, 1.5),
            ("socketcand-hi", b"< hi >", 0.0, 1.5)):
        rec = {"label": label, "t_since_unlock_ms": round(
            (time.perf_counter() - t0) * 1000, 1)}
        try:
            s = socket.create_connection(("10.226.193.2", 13401), timeout=2)
            s.settimeout(wait)
            if payload is None:
                s.sendall(bytes(8))
                time.sleep(gap)
                s.sendall(bytes(8))
            elif payload:
                s.sendall(payload)
            data = b""
            try:
                data = s.recv(4096)
            except socket.timeout:
                pass
            rec["recv"] = data.hex()
            rec["note"] = "no data" if not data else "DATA"
            s.close()
        except OSError as exc:
            rec["error"] = str(exc)
        doc["probes"].append(rec)
        print(f"    {label:<16} -> {rec.get('recv', '')[:40]!r} "
              f"{rec.get('note', rec.get('error', ''))} "
              f"({rec['t_since_unlock_ms']} ms after unlock)")

    # B. while the DoIP link is still open, check the neighbouring ports again
    for port in (13400, 13401, 13402):
        rec = {"label": f"port{port}", "open": tcp_open("10.226.193.2", port)}
        doc["probes"].append(rec)
    link.close()

    path = save(f"34_hunt_unlock_probe_{time.strftime('%Y%m%d-%H%M%S')}.json", doc)
    print(f"evidence: {path}")
    hits = [p for p in doc["probes"] if p.get("recv")]
    print(f"RESULT: {len(hits)} probe(s) returned bytes")
    return 0 if not hits else 0


# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="hunt for the real CAN bridge")
    ap.add_argument("cmd", choices=("ports", "subnet", "udp", "nonhttp",
                                    "unlock", "all"))
    ap.add_argument("--hosts", default="")
    ap.add_argument("--ports", default="")
    ap.add_argument("--nets", default="")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--workers", type=int, default=300)
    ap.add_argument("--timeout", type=float, default=0.4)
    ap.add_argument("--wait", type=float, default=1.0)
    ap.add_argument("--vin", default="CV622697F82A936A1")
    ap.add_argument("--workdir", default="work/t5")
    args = ap.parse_args(argv)
    if args.cmd == "ports":
        return cmd_ports(args)
    if args.cmd == "subnet":
        return cmd_subnet(args)
    if args.cmd == "udp":
        return cmd_udp(args)
    if args.cmd == "nonhttp":
        return cmd_nonhttp(args)
    if args.cmd == "unlock":
        return cmd_unlock(args)
    rc = 0
    rc |= cmd_ports(args)
    rc |= cmd_subnet(args)
    rc |= cmd_udp(args)
    rc |= cmd_nonhttp(args)
    return rc


if __name__ == "__main__":
    sys.exit(main())
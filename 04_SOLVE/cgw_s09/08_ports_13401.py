#!/usr/bin/env python3
"""CGW host: full TCP port scan + precise 13401 behaviour characterisation.

Question: is there a service on the CGW host that actually speaks a real
flash/programming protocol (i.e. where "Programming Session" lives)?
Also: 13401 -- when exactly does it close? on connect, on first byte, or after N?
"""
import asyncio, socket, ssl, struct, time, json, os, sys, binascii

HOST = "10.229.221.2"
OUT = r"D:\qwb\03_EVIDENCE\cgw_s09"
os.makedirs(OUT, exist_ok=True)
rec = {}


def hx(b):
    return binascii.hexlify(b).decode().upper() if b else ""


# ---------------- 1. full port scan ----------------
async def probe_port(port, sem, results, timeout=1.2):
    async with sem:
        try:
            fut = asyncio.open_connection(HOST, port)
            r, w = await asyncio.wait_for(fut, timeout)
            banner = b""
            try:
                banner = await asyncio.wait_for(r.read(64), 1.0)
            except Exception:
                pass
            results.append((port, "OPEN", hx(banner)))
            w.close()
        except Exception as e:
            pass


async def scan():
    sem = asyncio.Semaphore(400)
    results = []
    t0 = time.time()
    tasks = [probe_port(p, sem, results) for p in range(1, 65536)]
    await asyncio.gather(*tasks)
    results.sort()
    print("=== full TCP scan %s (%.1fs) ===" % (HOST, time.time() - t0))
    for p, st, b in results:
        print("  %5d OPEN  banner=%s" % (p, b or "(none)"))
    return results


# ---------------- 2. 13401 behaviour ----------------
def t13401():
    print("\n=== 13401 precise behaviour ===")
    out = []

    # (a) connect, send nothing, wait
    s = socket.socket(); s.settimeout(8)
    t0 = time.time()
    s.connect((HOST, 13401))
    closed_at = None
    try:
        while True:
            d = s.recv(4096)
            if not d:
                closed_at = (time.time() - t0) * 1000
                break
    except socket.timeout:
        closed_at = None
    print("  (a) connect+silent 8s: closed_after=%s ms" % (closed_at,))
    out.append({"test": "silent", "closed_after_ms": closed_at})
    s.close()

    payloads = {
        "doip_ident": bytes.fromhex("02FD000100000000"),
        "doip_ra": bytes.fromhex("02FD000500000007") + bytes.fromhex("0E000000000000"),
        "doip_diag": bytes.fromhex("02FD800100000006") + bytes.fromhex("0E00") + bytes.fromhex("E442") + bytes.fromhex("1003"),
        "http_get": b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        "tls_hello": bytes.fromhex("160301"),  # partial, just to see reaction
        "nul": b"\x00",
        "long": b"A" * 1024,
    }
    for name, p in payloads.items():
        s = socket.socket(); s.settimeout(6)
        t0 = time.time()
        try:
            s.connect((HOST, 13401))
            s.sendall(p)
            rx = b""
            closed = None
            while True:
                d = s.recv(4096)
                if not d:
                    closed = (time.time() - t0) * 1000
                    break
                rx += d
            print("  (%s) sent=%dB rx=%r closed_after=%.0fms"
                  % (name, len(p), rx[:80], closed or -1))
            out.append({"test": name, "sent": hx(p), "rx": hx(rx),
                        "closed_after_ms": closed})
        except socket.timeout:
            print("  (%s) sent=%dB -> still open after 6s" % (name, len(p)))
            out.append({"test": name, "sent": hx(p), "rx": "", "closed_after_ms": None})
        except Exception as e:
            print("  (%s) ERROR %s" % (name, e))
            out.append({"test": name, "error": str(e)})
        try:
            s.close()
        except Exception:
            pass

    # (c) UDP
    print("  --- UDP ---")
    for port in (13400, 13401):
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(2.5)
        try:
            u.sendto(bytes.fromhex("02FD000100000000"), (HOST, port))
            d, a = u.recvfrom(4096)
            print("  UDP %d -> %s" % (port, hx(d)))
            out.append({"test": "udp_%d" % port, "rx": hx(d)})
        except socket.timeout:
            print("  UDP %d -> timeout (no response)" % port)
            out.append({"test": "udp_%d" % port, "rx": None})
        u.close()
    return out


async def main():
    res = await scan()
    rec["port_scan"] = [{"port": p, "banner": b} for p, st, b in res]
    rec["port_13401"] = t13401()
    json.dump(rec, open(os.path.join(OUT, "0009_cgw_ports_13401.json"), "w"), indent=1)
    print("\nwrote 0009_cgw_ports_13401.json")


asyncio.run(main())

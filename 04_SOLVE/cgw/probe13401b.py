#!/usr/bin/env python3
"""13401 deep probe: does any first byte / short frame keep the connection alive
or produce a reply? Also records whether closes are FIN (graceful) or RST.

Findings so far: idle conn is closed after ~1054 ms; any single byte triggers a
close ~1 RTT later (54 ms). This script sweeps all 256 first-byte values and a
set of 2-4 byte framed variants to look for a protocol magic.
"""
import socket, time, binascii, struct, json, os, sys

HOST = "10.229.221.2"
PORT = 13401


def one(payload, wait=1.6, gap=0.0, pre_delay=0.0, half_close=False, recv_first=False):
    rec = {"payload_hex": binascii.hexlify(payload).decode(), "len": len(payload),
           "half_close": half_close}
    t0 = time.time()
    s = socket.socket()
    s.settimeout(wait)
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        rec["err"] = "connect " + repr(e)
        return rec
    rec["connect_ms"] = round((time.time() - t0) * 1000, 1)
    rx = b""
    try:
        if pre_delay:
            time.sleep(pre_delay)
        if recv_first:
            s.settimeout(0.35)
            try:
                rx += s.recv(4096)
            except socket.timeout:
                pass
            s.settimeout(wait)
        if payload:
            s.sendall(payload)
        if half_close:
            s.shutdown(socket.SHUT_WR)
        t_send = time.time()
        kind = None
        while True:
            try:
                b = s.recv(65536)
            except socket.timeout:
                kind = "OPEN(still open after %.1fs)" % wait
                break
            except ConnectionResetError:
                kind = "RST"
                break
            except OSError as e:
                kind = "ERR:" + repr(e)
                break
            if not b:
                kind = "FIN"
                break
            rx += b
            if len(rx) > 8192:
                break
        rec["close_kind"] = kind
        rec["closed_after_ms"] = round((time.time() - t_send) * 1000, 1)
    except (BrokenPipeError, ConnectionResetError) as e:
        rec["close_kind"] = "RST-on-write"
        rec["closed_after_ms"] = round((time.time() - t0) * 1000, 1)
    except OSError as e:
        rec["err"] = repr(e)
    rec["rx_len"] = len(rx)
    rec["rx_hex"] = binascii.hexlify(rx[:256]).decode()
    try:
        s.close()
    except Exception:
        pass
    return rec


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "bytes"
    out = []
    here = os.path.dirname(os.path.abspath(__file__))

    if mode == "baseline":
        cases = {
            "idle": (b"", dict(wait=2.0)),
            "one_zero": (b"\x00", {}),
            "one_A": (b"A", {}),
            "idle_then_zero": (b"\x00", dict(pre_delay=0.5)),
            "idle_then_A": (b"A", dict(pre_delay=0.5)),
            "halfclose_zero": (b"\x00", dict(half_close=True)),
        }
        for k, (p, kw) in cases.items():
            r = one(p, **kw)
            r["label"] = k
            print("%-18s %-12s after=%sms rx=%d" % (k, r.get("close_kind"), r.get("closed_after_ms"), r["rx_len"]), flush=True)
            out.append(r)

    elif mode == "bytes":
        # sweep all 256 single-byte values; anything that is NOT a fast FIN/RST is interesting
        alive = []
        for b in range(256):
            r = one(bytes([b]), wait=1.3)
            r["label"] = "byte_%02X" % b
            k = r.get("close_kind", "")
            if r.get("rx_len") or "OPEN" in str(k):
                alive.append(r)
                print("  *** byte 0x%02X -> %s rx=%d %s" % (b, k, r.get("rx_len",0), r.get("rx_hex","")[:60]), flush=True)
            out.append(r)
        print("=== 256 single-byte probes done; interesting: %d" % len(alive))
        lat = [r.get("closed_after_ms") for r in out if r.get("closed_after_ms")]
        if lat:
            print("    close latency min/med/max = %.0f / %.0f / %.0f ms" % (
                min(lat), sorted(lat)[len(lat) // 2], max(lat)))
        kinds = {}
        for r in out:
            kinds[r.get("close_kind")] = kinds.get(r.get("close_kind"), 0) + 1
        print("    close kinds:", kinds)

    with open(os.path.join(here, "13401_%s.json" % mode), "w") as f:
        json.dump(out, f, indent=2)


if __name__ == "__main__":
    main()

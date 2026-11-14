#!/usr/bin/env python3
"""Settle the ONE question that decides whether 13401 is worth more effort:

    Does the peer close the connection BEFORE we send any byte?

If yes -> the service is not "waiting for a magic first packet"; protocol payloads
are irrelevant and 13401 cannot be a transport into 10.224.139.0/24.

Method: for each trial we record t_connect, t_first_rx_or_eof, and (in the "send"
arm) t_send. `close_before_send` is True when EOF was observed while t_send had
not yet happened. We also probe a 6 s quiet window to rule out a delayed banner.
"""
import socket, time, json, sys, os, binascii

HOSTS = ["10.229.221.2", "10.230.164.4"]
PORT = 13401
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "..", "03_EVIDENCE", "cgw-web", "0602_13401_close_timing.jsonl")
OUT = os.path.abspath(OUT)


def trial(host, *, send_after=None, payload=b"", quiet=6.0):
    rec = {"host": host, "send_after_s": send_after,
           "payload_hex": binascii.hexlify(payload).decode()}
    s = socket.socket()
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    t0 = time.perf_counter()
    try:
        s.connect((host, PORT))
    except Exception as e:
        rec["connect_error"] = repr(e)
        return rec
    t_conn = time.perf_counter()
    rec["connect_ms"] = round((t_conn - t0) * 1000, 2)

    # We do NOT send anything yet unless the arm asks for it later.
    s.settimeout(quiet)
    t_send = None
    rx = b""
    eof_at = None
    err = None
    timeout_at = None

    # If an arm wants to send after a delay, do it from here by polling.
    deadline = t_conn + quiet
    while True:
        now = time.perf_counter()
        if send_after is not None and t_send is None and (now - t_conn) >= send_after:
            try:
                s.sendall(payload)
                t_send = time.perf_counter()
            except OSError as e:
                rec["send_error"] = repr(e)
                t_send = time.perf_counter()
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            timeout_at = time.perf_counter()
            break
        s.settimeout(min(0.05, remaining))
        try:
            b = s.recv(4096)
        except socket.timeout:
            continue
        except ConnectionResetError as e:
            err = "RST:" + repr(e)
            eof_at = time.perf_counter()
            break
        except OSError as e:
            err = "ERR:" + repr(e)
            eof_at = time.perf_counter()
            break
        if not b:
            eof_at = time.perf_counter()
            break
        rx += b

    if eof_at is not None:
        rec["eof_ms"] = round((eof_at - t_conn) * 1000, 2)
        rec["eof_reason"] = err or "FIN"
    if timeout_at is not None:
        rec["alive_after_ms"] = round((timeout_at - t_conn) * 1000, 2)
    if t_send is not None:
        rec["send_ms"] = round((t_send - t_conn) * 1000, 2)
        rec["close_before_send"] = bool(eof_at is not None and eof_at < t_send)
    else:
        rec["close_before_send"] = (eof_at is not None)  # nothing was ever sent
    rec["rx_len"] = len(rx)
    rec["rx_hex"] = binascii.hexlify(rx[:256]).decode()
    try:
        s.close()
    except Exception:
        pass
    return rec


def main():
    recs = []
    arms = []
    for host in HOSTS:
        # 3 repeats of "say nothing, just watch"
        for i in range(3):
            arms.append((host, dict(send_after=None)))
    # delayed sends: prove independence from payload content
    arms += [
        ("10.229.221.2", dict(send_after=0.300, payload=b"\x00")),
        ("10.229.221.2", dict(send_after=0.300, payload=b"GET / HTTP/1.1\r\n\r\n")),
        ("10.229.221.2", dict(send_after=0.300, payload=bytes.fromhex("02fd000100000000"))),
        ("10.229.221.2", dict(send_after=1.500, payload=b"\x01\x02\x03\x04")),
    ]

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for host, kw in arms:
            r = trial(host, **kw)
            recs.append(r)
            f.write(json.dumps(r) + "\n")
            f.flush()
            print(json.dumps(r), flush=True)

    print("\n=== SUMMARY ===")
    for r in recs:
        print("%-14s send_after=%-6s eof_ms=%-9s send_ms=%-9s close_before_send=%s rx=%dB %s"
              % (r["host"], r.get("send_after_s"), r.get("eof_ms"), r.get("send_ms"),
                 r.get("close_before_send"), r.get("rx_len", -1),
                 r.get("eof_reason") or r.get("alive_after_ms")))
    print("\nevidence:", OUT)


if __name__ == "__main__":
    main()

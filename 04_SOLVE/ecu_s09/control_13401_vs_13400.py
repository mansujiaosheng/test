#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
13401 control experiment + timing distribution.

KEY QUESTION: does 13400 (known-working DoIP) behave like 13401, or differently?
If 13400 keeps an idle connection open while 13401 closes it in ~1 RTT,
then 13401's close is accept-triggered rejection, not a protocol expectation.

Also measures the distribution of (connect -> FIN) delay over N trials so the
"~0.03s close" can be attributed to RTT rather than to payload.
"""
import socket
import time
import json
import os
import statistics

HOST = "10.229.221.2"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs")
os.makedirs(OUT, exist_ok=True)


def idle_trial(port, wait_s=6.0):
    """Connect, send NOTHING, wait. Record when/if the peer closes."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(wait_s)
    t0 = time.time()
    try:
        s.connect((HOST, port))
    except Exception as e:
        s.close()
        return {"port": port, "result": "CONNECT_FAIL", "err": repr(e)}
    t_conn = time.time()
    kind = "TIMEOUT"
    t_close = None
    got = b""
    try:
        while True:
            c = s.recv(4096)
            if not c:
                kind = "FIN"
                break
            got += c
    except socket.timeout:
        kind = "TIMEOUT"
    except ConnectionResetError:
        kind = "RST"
    except Exception as e:
        kind = "ERR:" + repr(e)
    t_close = time.time()
    soerr = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    s.close()
    return {
        "port": port,
        "connect_ms": round((t_conn - t0) * 1000, 2),
        "after_connect_ms": (round((t_close - t_conn) * 1000, 2)
                             if kind != "TIMEOUT" else None),
        "close_kind": kind,
        "recv_len": len(got),
        "so_error": soerr,
    }


def main():
    res = {"idle_trials": [], "summary": {}}

    print("### A. IDLE behaviour: 13400 (known DoIP) vs 13401, send nothing")
    for port in (13400, 13401):
        trials = []
        n = 12 if port == 13401 else 3
        for i in range(n):
            r = idle_trial(port, wait_s=6.0)
            trials.append(r)
            print(json.dumps(r))
        res["idle_trials"].append({"port": port, "trials": trials})
        closed = [t for t in trials if t.get("close_kind") == "FIN"]
        timeouts = [t for t in trials if t.get("close_kind") == "TIMEOUT"]
        d = [t["after_connect_ms"] for t in closed if t["after_connect_ms"]]
        res["summary"][str(port)] = {
            "n": n,
            "fin": len(closed),
            "timeout": len(timeouts),
            "delay_ms_min": min(d) if d else None,
            "delay_ms_max": max(d) if d else None,
            "delay_ms_median": round(statistics.median(d), 2) if d else None,
            "recv_bytes_any": sum(t.get("recv_len", 0) for t in trials),
        }
        print("--- port %d summary: %s" % (port, json.dumps(res["summary"][str(port)])))

    p = os.path.join(OUT, "13401_idle_vs_doip.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    print("\n[written]", p)


main()

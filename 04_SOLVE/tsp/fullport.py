#!/usr/bin/env python3
"""Full 1-65535 TCP connect scan of a single host (TSP 10.230.164.2).
Writes: one line per open port + timing. RST-closed ports cost ~RTT.
"""
import socket, sys, time, json
from concurrent.futures import ThreadPoolExecutor

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.230.164.2"
TIMEOUT = float(sys.argv[2]) if len(sys.argv) > 2 else 0.6
WORKERS = int(sys.argv[3]) if len(sys.argv) > 3 else 300

def probe(port):
    s = socket.socket()
    s.settimeout(TIMEOUT)
    try:
        s.connect((HOST, port))
        return port, "open"
    except socket.timeout:
        return port, "timeout"
    except ConnectionRefusedError:
        return port, "closed"
    except OSError as e:
        return port, "err:" + type(e).__name__
    finally:
        try: s.close()
        except Exception: pass

t0 = time.time()
open_ports, timeouts, other = [], [], []
with ThreadPoolExecutor(max_workers=WORKERS) as ex:
    for port, st in ex.map(probe, range(1, 65536)):
        if st == "open":
            open_ports.append(port); print("OPEN  %d" % port, flush=True)
        elif st == "timeout":
            timeouts.append(port)
        elif st.startswith("err"):
            other.append((port, st))
print("---", flush=True)
print("host=%s workers=%d timeout=%.2f elapsed=%.1fs" % (HOST, WORKERS, TIMEOUT, time.time()-t0))
print("OPEN_PORTS=%s" % open_ports)
print("TIMEOUT_COUNT=%d %s" % (len(timeouts), timeouts[:200]))
print("OTHER=%s" % other[:100])
json.dump({"host": HOST, "open": open_ports, "timeouts": len(timeouts),
           "elapsed": round(time.time()-t0, 1)},
          open("D:/qwb/03_EVIDENCE/tsp/0300_fullport_open.json", "w"), indent=1)

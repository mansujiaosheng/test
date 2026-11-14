import socket, json, sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
PORTS = [22, 80, 443, 8080, 8443, 13400, 13401, 1883, 5000, 8000]
def probe(host, port, t=0.7):
    s = socket.socket(); s.settimeout(t)
    try:
        s.connect((host, port)); return host, port, "open"
    except ConnectionRefusedError: return host, port, "closed"
    except Exception: return host, port, None
    finally: s.close()
def scan(net):
    tasks = [(f"{net}.{i}", p) for i in range(1, 255) for p in PORTS]
    out = []
    with ThreadPoolExecutor(max_workers=200) as ex:
        for h, p, st in ex.map(lambda a: probe(*a), tasks):
            if st == "open": out.append({"host": h, "port": p}); print("OPEN", h, p, flush=True)
    return out
res = {}
for net in sys.argv[1:]:
    res[net] = scan(net)
Path(ROOT/"03_EVIDENCE/cgwweb/4130_sweep24.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
print("done", {k: len(v) for k, v in res.items()})

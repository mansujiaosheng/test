import socket, sys, time, json
from concurrent.futures import ThreadPoolExecutor
HOSTS = ["10.230.164.3", "10.230.164.4"]
PORTS = list(range(1, 65536))
res = {h: [] for h in HOSTS}
def probe(a):
    h, p = a
    s = socket.socket(); s.settimeout(0.55)
    try:
        if s.connect_ex((h, p)) == 0:
            return (h, p, "OPEN", "")
        return (h, p, "CLOSED", "")
    except Exception as e:
        return (h, p, "ERR", str(e)[:40])
    finally:
        s.close()
tasks = [(h, p) for h in HOSTS for p in PORTS]
t0 = time.time(); done = 0
with ThreadPoolExecutor(max_workers=400) as ex:
    for (h, p, st, info) in ex.map(probe, tasks, chunksize=64):
        done += 1
        if st == "OPEN":
            res[h].append(p); print(f"OPEN {h}:{p}", flush=True)
        if done % 20000 == 0:
            print(f"# {done}/{len(tasks)} {time.time()-t0:.0f}s", flush=True)
print("="*60)
for h in HOSTS:
    print(f"{h} OPEN={sorted(res[h])}")
json.dump({h: sorted(res[h]) for h in HOSTS}, open("03_EVIDENCE/tsp/0404_fullport_3_4.json", "w"), indent=1)
print(f"elapsed {time.time()-t0:.1f}s")

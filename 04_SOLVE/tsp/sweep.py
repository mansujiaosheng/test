"""有界网段扫描：只做 TCP connect，不发任何应用层数据。
用法: python sweep.py 10.230.0.0/16 8080 8443 13400 --conc 2000 --timeout 1.0
输出: 仅开放端口，落 03_EVIDENCE/tsp/NNNN_sweep_<cidr>.json
"""
import asyncio, ipaddress, json, sys, time

async def probe(host, port, timeout, sem, hits):
    async with sem:
        try:
            fut = asyncio.open_connection(host, port)
            r, w = await asyncio.wait_for(fut, timeout=timeout)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            hits.append({"host": host, "port": port})
            print(f"OPEN {host}:{port}", flush=True)
        except Exception:
            pass

async def main(cidr, ports, conc, timeout):
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    sem = asyncio.Semaphore(conc)
    hits = []
    t0 = time.time()
    tasks = [probe(h, p, timeout, sem, hits) for h in hosts for p in ports]
    print(f"target={cidr} hosts={len(hosts)} ports={ports} conc={conc} timeout={timeout} tasks={len(tasks)}", flush=True)
    # 分批提交，避免一次性构造百万 task
    for i in range(0, len(tasks), 200000):
        await asyncio.gather(*tasks[i:i + 200000])
    print(f"done in {time.time()-t0:.1f}s hits={len(hits)}")
    out = {"cidr": cidr, "ports": ports, "elapsed_s": round(time.time() - t0, 1), "hits": hits}
    fn = rf"D:\qwb\03_EVIDENCE\tsp\0208_sweep_{cidr.replace('/', '_')}.json"
    json.dump(out, open(fn, "w", encoding="utf-8"), indent=1)
    print("saved", fn)
    return hits

if __name__ == "__main__":
    cidr = sys.argv[1]
    args = sys.argv[2:]
    conc, timeout = 2000, 1.0
    ports = []
    it = iter(args)
    for a in it:
        if a == "--conc":
            conc = int(next(it))
        elif a == "--timeout":
            timeout = float(next(it))
        else:
            ports.append(int(a))
    asyncio.run(main(cidr, ports or [8080], conc, timeout))

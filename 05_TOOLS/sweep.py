#!/usr/bin/env python3
"""sweep.py -- CIDR 主机/端口快速普查。纯标准库。
用法: python sweep.py 10.230.164.0/24 -p 8080,443,8443,13400,13401,22 -t 0.6
"""
import argparse, ipaddress, socket, sys
from concurrent.futures import ThreadPoolExecutor

def probe(host, port, timeout):
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((host, port)); return (host, port, "open")
    except socket.timeout:
        return (host, port, "filtered")
    except ConnectionRefusedError:
        return (host, port, "closed")
    except OSError as e:
        return (host, port, f"err:{e.errno}")
    finally:
        s.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cidr"); ap.add_argument("-p", default="8080")
    ap.add_argument("-t", type=float, default=0.6)
    ap.add_argument("-w", type=int, default=128)
    a = ap.parse_args()
    ports = [int(x) for x in a.p.split(",") if x.strip()]
    hosts = [str(h) for h in ipaddress.ip_network(a.cidr, strict=False).hosts()]
    jobs = [(h, p) for p in ports for h in hosts]
    openp, closed_any = [], set()
    with ThreadPoolExecutor(max_workers=a.w) as ex:
        for h, p, st in ex.map(lambda x: probe(x[0], x[1], a.t), jobs):
            if st == "open":
                openp.append((h, p))
            elif st == "closed":
                closed_any.add(h)
    for h, p in sorted(openp):
        print(f"OPEN {h}:{p}")
    print(f"--- hosts with any RST(closed) = {len(closed_any)}; open pairs={len(openp)}")
    for h in sorted(closed_any):
        print(f"ALIVE {h}")

main()

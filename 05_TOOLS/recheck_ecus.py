#!/usr/bin/env python3
"""recheck_ecus.py -- BCM/BMS/VCU 上线探测（靶场中途上线时用）

背景：2026-11-14 01:15Z 首次侦察时 10.224.139.5/6/7 三台全不可达
（ICMP 100% loss、1-10000 端口全 filtered、同 /24 全空）。
赛事期间若这三台被拉起，用本脚本快速确认，避免重跑完整扫描。

用法：
  python recheck_ecus.py                # 默认三台 + 8080，2s 超时
  python recheck_ecus.py --full         # 上线后跑 1-10000 全扫
  python recheck_ecus.py --loop 300     # 每 300 秒轮询一次，直到有响应

退出码：0 至少一台有响应；1 全部无响应
"""
import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

TARGETS = {
    "BCM": "10.224.139.5",
    "BMS": "10.224.139.6",
    "VCU": "10.224.139.7",
}
QUICK_PORTS = [22, 80, 443, 8080, 8081, 8443, 13400]


def tcp(host, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return port
    except Exception:
        return None
    finally:
        s.close()


def check(timeout=2.0):
    """返回 {name: [open ports]}，只含活着的。"""
    alive = {}
    for name, ip in TARGETS.items():
        with ThreadPoolExecutor(max_workers=16) as ex:
            hits = [p for p in ex.map(lambda p: tcp(ip, p, timeout), QUICK_PORTS)
                    if p]
        if hits:
            alive[name] = (ip, sorted(hits))
            print(f"[ALIVE] {name:<4} {ip}  open={sorted(hits)}", flush=True)
        else:
            print(f"[dead ] {name:<4} {ip}  (all {len(QUICK_PORTS)} ports timeout)",
                  flush=True)
    return alive


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true",
                    help="有响应则跑 1-10000 全扫（调用 portscan.py）")
    ap.add_argument("--loop", type=int, default=0,
                    help="轮询间隔秒数；0=只跑一次")
    ap.add_argument("--timeout", type=float, default=2.0)
    a = ap.parse_args()

    while True:
        print(f"\n=== recheck {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ===")
        alive = check(a.timeout)
        if alive:
            print(f"\n[+] {len(alive)} 台已上线")
            if a.full:
                import subprocess
                for name, (ip, _) in alive.items():
                    print(f"\n--- full scan {name} {ip} ---")
                    subprocess.run([sys.executable, "05_TOOLS/portscan.py", ip,
                                    "-p", "1-10000", "-t", "0.7", "-w", "100",
                                    "--json", f"03_EVIDENCE/fleet/scan_{ip}.json"])
            return 0
        if a.loop <= 0:
            print("\n[-] 全部无响应")
            return 1
        time.sleep(a.loop)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Full-port TCP connect scan of the three ECU hosts.

Purpose: exclude the hypothesis "the host is alive, only 8080 is closed".
A live host answers with RST (fast, connect_ex rc=111/10061-equivalent) on
every closed port; a non-existent host answers nothing at all (timeout).

Rate-limited to <=450 pps, concurrency 600, per-connect timeout 0.6 s.

Usage: python fullscan.py <outprefix> [host ...]
"""
import asyncio
import json
import sys
import time

TARGETS = [("10.224.139.5", "BCM"), ("10.224.139.6", "BMS"), ("10.224.139.7", "VCU")]
PORTS = range(1, 65536)
CONCURRENCY = 600
TIMEOUT = 0.6
MAX_PPS = 450.0

RST_CODES = {10061, 111, 10054, 104}   # Windows / POSIX connection-refused


class RateLimiter:
    def __init__(self, pps):
        self.pps = pps
        self.tokens = pps
        self.last = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            now = time.monotonic()
            self.tokens = min(self.pps, self.tokens + (now - self.last) * self.pps)
            self.last = now
            if self.tokens < 1.0:
                wait = (1.0 - self.tokens) / self.pps
                await asyncio.sleep(wait)
                self.tokens = 0.0
                self.last = time.monotonic()
            else:
                self.tokens -= 1.0


async def probe(sem, lim, host, port, stats, log):
    await lim.acquire()
    async with sem:
        t0 = time.monotonic()
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=TIMEOUT)
            dt = time.monotonic() - t0
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            stats["open"] += 1
            log(f"OPEN  {host}:{port} dt={dt:.3f}")
            return
        except asyncio.TimeoutError:
            stats["timeout"] += 1
        except ConnectionRefusedError:
            dt = time.monotonic() - t0
            stats["refused"] += 1
            # first refusal proves the host is alive
            if stats["refused"] <= 3:
                log(f"RST   {host}:{port} dt={dt:.3f}  <- host ALIVE, port closed")
        except OSError as e:
            win = getattr(e, "winerror", None)
            if win in RST_CODES:
                stats["refused"] += 1
                if stats["refused"] <= 3:
                    log(f"RST   {host}:{port} winerr={win}  <- host ALIVE, port closed")
            elif win == 10065:  # WSAEHOSTUNREACH
                stats["unreach"] += 1
                if stats["unreach"] <= 3:
                    log(f"UNREACH {host}:{port} winerr=10065 <- ICMP host-unreachable")
            else:
                stats["other"] += 1
                if stats["other"] <= 10:
                    log(f"ERR   {host}:{port} {e!r}")


async def scan_host(host, label, lim, out_path):
    stats = {"open": 0, "refused": 0, "timeout": 0, "unreach": 0, "other": 0}
    lines = []

    def log(msg):
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        lines.append(line)
        print(line, flush=True)

    sem = asyncio.Semaphore(CONCURRENCY)
    t0 = time.monotonic()
    total = len(PORTS)
    tasks = []
    for port in PORTS:
        tasks.append(asyncio.create_task(probe(sem, lim, host, port, stats, log)))
        # keep the task list bounded
        if len(tasks) >= 20000:
            await asyncio.gather(*tasks)
            tasks.clear()
            el = time.monotonic() - t0
            print(f"[{label}] progress {stats} elapsed={el:.0f}s", flush=True)
    if tasks:
        await asyncio.gather(*tasks)
    elapsed = time.monotonic() - t0

    summary = {
        "host": host,
        "label": label,
        "ports_scanned": total,
        "elapsed_s": round(elapsed, 1),
        "pps": round(total / elapsed, 1) if elapsed else None,
        "timeout": TIMEOUT,
        "concurrency": CONCURRENCY,
        **stats,
        "verdict": ("REACHABLE-host-alive" if stats["refused"] > 0 or stats["open"] > 0
                    else "NO-RESPONSE-AT-ALL"),
    }
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
        f.write("\nSUMMARY " + json.dumps(summary) + "\n")
    print("SUMMARY " + json.dumps(summary), flush=True)
    return summary


async def main():
    prefix = sys.argv[1] if len(sys.argv) > 1 else "fullscan"
    targets = TARGETS
    if len(sys.argv) > 2:
        targets = [(a, a) for a in sys.argv[2:]]
    lim = RateLimiter(MAX_PPS)
    results = []
    for host, label in targets:
        out = f"_{prefix}_{host}.log"
        print(f"\n===== scanning {host} ({label}) ports 1-65535 =====", flush=True)
        results.append(await scan_host(host, label, lim, out))
    print("\n===== ALL DONE =====")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    asyncio.run(main())

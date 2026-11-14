#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""watch_bridge.py —— 低频监测 CGW 的 CAN FD 桥（13401）是否被"开桥例程"改变行为。

背景：13401 在"桥未开"状态下的稳定行为 = accept 后 ~1 RTT 内 FIN、0 字节、从不 read
      （包级证据见 03_EVIDENCE/cgw/0520_newenv_13401_packetlevel.txt）。
      若有人执行了正确的开桥例程，该 listener 应出现以下之一：
        DATA         —— 收到任意字节（服务端 write 了）
        STILL_OPEN   —— 1.2 s 内不 close（开始等待/处理客户端数据）
      本脚本就是这一判据的自动化监测器：默认 10 s 一次连接，命中即退出。

用法：
  python 04_SOLVE/cgw/watch_bridge.py [host] [--interval 10] [--duration 1800]
输出：03_EVIDENCE/cgw/0522_bridge_watch.jsonl（每行一个样本）；命中时打印 STATE_CHANGE。
注意：1 连接/10 s，远低于"每轮 ≤20 连接"的纪律上限。
"""
import socket, time, json, sys, argparse
from datetime import datetime

def now_iso():
    return datetime.now().astimezone().isoformat(timespec="milliseconds")

def sample(host, wait=1.2, connect_timeout=3.0):
    r = {"ts": now_iso(), "host": host, "port": 13401}
    s = socket.socket(); s.settimeout(connect_timeout)
    try:
        t0 = time.time(); s.connect((host, 13401)); r["connect_ms"] = round((time.time()-t0)*1000, 1)
        s.settimeout(wait); tc = time.time()
        try:
            c = s.recv(64); te = time.time()
            if c == b"":
                r.update(state="CLOSED", close_ms=round((te-tc)*1000, 1))
            else:
                r.update(state="DATA", rx=c.hex(), after_ms=round((te-tc)*1000, 1))
        except socket.timeout:
            r.update(state="STILL_OPEN", waited_ms=round((time.time()-tc)*1000, 1))
        except ConnectionResetError:
            r.update(state="CLOSED_RST", after_ms=round((time.time()-tc)*1000, 1))
    except Exception as e:
        r.update(state="UNREACHABLE", err=type(e).__name__)
    finally:
        try: s.close()
        except Exception: pass
    return r

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host", nargs="?", default="10.226.193.2")
    ap.add_argument("--interval", type=float, default=10.0)
    ap.add_argument("--duration", type=float, default=1800.0)
    ap.add_argument("--out", default="03_EVIDENCE/cgw/0522_bridge_watch.jsonl")
    a = ap.parse_args()
    t_end = time.time() + a.duration
    n = 0
    with open(a.out, "a", encoding="utf-8") as fh:
        while time.time() < t_end:
            r = sample(a.host); n += 1
            line = json.dumps(r, ensure_ascii=False)
            print(line, flush=True); fh.write(line + "\n"); fh.flush()
            if r["state"] in ("DATA", "STILL_OPEN"):
                print(json.dumps({"STATE_CHANGE": True, "sample": r}, ensure_ascii=False), flush=True)
                return 0
            time.sleep(a.interval)
    print(json.dumps({"step": "watch_end", "samples": n, "duration_s": a.duration}), flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())

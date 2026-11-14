#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""补两个覆盖缺口：
  A. Host 头维度对三条已知路由 + 一条随机路径的影响（vhost 分流？）
  B. UDP 面探测（此前端口普查只覆盖 TCP）——ISAKMP/NTP/DNS/8080/8443/13400
"""
import socket
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()
HOST, PORT = "10.230.164.2", 8080
BASE = f"http://{HOST}:{PORT}"
TIMEOUT = 3.0


def main():
    print("=" * 78)
    print(f"Host 矩阵 + UDP 面  {time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    print("=" * 78)

    hosts = ["", "tsp", "tsp.local", "localhost", "127.0.0.1", "internal",
             "admin", "api", "ota", "sign", "audit", "cybercar", "tsp.internal",
             "tsp.cybercar", "10.230.164.2", "10.230.164.2:8080",
             "example.com", "a" * 200]
    print("\n-- A. Host 头矩阵（每格打印 status/len/body 摘要）--")
    paths = [("/healthz", "GET"), ("/internal/audit", "GET"),
             ("/graphql", "POST"), ("/nope-xyz", "GET")]
    for h in hosts:
        label = h if h else "<default>"
        line = []
        for p, m in paths:
            hdrs = {"Host": h} if h else {}
            try:
                if m == "POST":
                    r = requests.post(BASE + p, data=b"{}",
                                      headers={**hdrs,
                                               "Content-Type": "application/json"},
                                      timeout=TIMEOUT, allow_redirects=False)
                else:
                    r = requests.get(BASE + p, headers=hdrs, timeout=TIMEOUT,
                                     allow_redirects=False)
                line.append(f"{p}={r.status_code}/{len(r.content)}")
            except Exception as e:
                line.append(f"{p}=EXC:{type(e).__name__}")
        print(f"  Host={label[:24]:24s} " + "  ".join(line), flush=True)

    print("\n-- B. UDP 探测（发送探针，等待 1.2s 回包/ICMP）--")
    probes = {
        53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
        123: b"\x1b" + b"\x00" * 47,
        500: b"\x00" * 28,
        4500: b"\x00" * 28,
        8080: b"GET /healthz HTTP/1.0\r\n\r\n",
        8443: b"\x16\x03\x01\x00\x00",
        13400: b"\x02\xfd\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    }
    for port, payload in probes.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.2)
        try:
            s.sendto(payload, (HOST, port))
            data, addr = s.recvfrom(2048)
            print(f"  UDP {port:6d} -> REPLY {len(data)} bytes {data[:40]!r}")
        except socket.timeout:
            print(f"  UDP {port:6d} -> timeout (no reply)")
        except ConnectionResetError:
            print(f"  UDP {port:6d} -> ICMP port unreachable (closed)")
        except OSError as e:
            print(f"  UDP {port:6d} -> oserr {getattr(e, 'winerror', e.errno)}")
        finally:
            s.close()

    print("\n[done]", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

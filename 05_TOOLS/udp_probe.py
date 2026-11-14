#!/usr/bin/env python3
"""udp_probe.py -- UDP 存活/协议探测（CTF 侦察用，纯标准库）

用法:
  python 05_TOOLS/udp_probe.py 10.229.221.2 [--ports 13400,5000,5353]
  python 05_TOOLS/udp_probe.py --self-test

局限: UDP 无连接，超时不等于关闭（可能只是服务不回该 payload）。
"""
import argparse
import socket
import sys
import threading

DEFAULT_PORTS = [13400, 13401, 3496, 5000, 5353, 123, 161, 162, 67, 68,
                 8080, 3000, 9000, 47808, 111, 137, 138, 139, 445,
                 623, 502, 102, 2404, 44818, 50000]


def payload_for(port):
    if port in (13400, 3496):
        return bytes.fromhex("02fd000100000000")   # DoIP vehicle identification request
    if port == 123:
        return b"\x1b" + b"\x00" * 47              # NTP v3 client
    if port == 161:
        return bytes.fromhex("302602010004067075626c6963a019020104020100020100300b300906052b0601020105 00".replace(" ", ""))
    return b"\x00" * 8


def probe(host, port, timeout=0.7):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload_for(port), (host, port))
        data, addr = s.recvfrom(4096)
        return port, "reply", data.hex()[:400]
    except socket.timeout:
        return port, "silent", ""
    except ConnectionResetError:
        return port, "icmp-unreach", ""
    except OSError as e:
        return port, "err", str(e)
    finally:
        s.close()


def self_test():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def echo():
        d, a = srv.recvfrom(2048)
        srv.sendto(b"PONG" + d, a)

    t = threading.Thread(target=echo, daemon=True)
    t.start()
    r = probe("127.0.0.1", port)
    print("self-test echo:", r)
    ok = r[1] == "reply" and r[2].startswith("504f4e47")
    srv.close()
    print("SELF-TEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host", nargs="?")
    ap.add_argument("--ports", default="")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.host:
        ap.print_help()
        return 2
    ports = [int(x) for x in a.ports.split(",")] if a.ports else DEFAULT_PORTS
    results = [probe(a.host, p) for p in ports]
    for p, st, d in results:
        if st != "silent":
            print(f"{a.host}:{p:<6} {st:<12} {d}")
    n = sum(1 for _, st, _ in results if st == "reply")
    print(f"-- {a.host}: {n} repl(ies) out of {len(ports)} probed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

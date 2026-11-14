#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VPN 恢复后的低频复核（总计 <=40 个 TCP 连接，间隔 >=0.5 s；不做全端口 blast）。

目的只有一个：确认 13401 的行为是否改变（是否开始 read/回包），以及是否出现新的候选端口。
判据：
  ACCEPT_CLOSE  = 建连后无数据、~1 RTT 内 FIN（与 09:20 结论一致，说明仍是空监听）
  DATA_READ     = 任何 >=1 字节回包 或 数据被读后 FIN（=> 重开 HYP-cgw-01）
  NEW_PORT      = 定向列表里出现除 8080/13400/13401 外的开放端口
"""
import socket, struct, time, json, sys

HOSTS = ["10.229.221.2", "10.230.164.4"]
PORTS = [8080, 8443, 13400, 13401, 13402, 13410, 29536, 20000, 5000, 5001,
         10000, 1883, 502, 2000, 4444, 5555, 9000, 23, 111, 21]
TIMEOUT = 2.0
GAP = 0.5

def tcp_check(host, port):
    s = socket.socket(); s.settimeout(TIMEOUT)
    r = {"host": host, "port": port}
    try:
        t0 = time.time(); s.connect((host, port)); r["connect_ms"] = round((time.time()-t0)*1000, 1)
        r["open"] = True
    except socket.timeout:
        r["open"] = False; r["err"] = "timeout"
    except ConnectionRefusedError:
        r["open"] = False; r["err"] = "refused"
    except OSError as e:
        r["open"] = False; r["err"] = "oserr:%s" % e.errno
    finally:
        s.close()
    return r

def probe_13401(host):
    """connect-only: ACCEPT_CLOSE 判据"""
    r = {"probe": "13401_connect_only", "host": host}
    try:
        s = socket.socket(); s.settimeout(3); s.connect((host, 13401)); tc = time.time()
        s.settimeout(2.0)
        try:
            c = s.recv(64); te = time.time()
            r.update(outcome=("FIN" if c == b"" else "DATA:" + c.hex()),
                     close_ms=round((te-tc)*1000, 1))
        except socket.timeout:
            r.update(outcome="STILL_OPEN(>2s)", note="behavior changed - investigate")
        except ConnectionResetError:
            r.update(outcome="RST", close_ms=round((time.time()-tc)*1000, 1))
        s.close()
    except Exception as e:
        r.update(err=type(e).__name__ + ":" + str(e))
    return r

def udp_probe(host, port, payload, wait=1.5):
    r = {"probe": "udp", "host": host, "port": port, "sent": payload.hex()}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(wait)
    try:
        s.sendto(payload, (host, port))
        try:
            d, a = s.recvfrom(2048); r.update(rx=d.hex(), note="RESPONSE")
        except socket.timeout:
            r.update(note="no-response")
        except ConnectionResetError:
            r.update(note="icmp-port-unreachable")
    except Exception as e:
        r.update(err=str(e))
    finally:
        s.close()
    return r

if __name__ == "__main__":
    print(json.dumps({"step": "start", "hosts": HOSTS, "n_ports": len(PORTS),
                      "max_conns": len(HOSTS) * (len(PORTS) + 3)}), flush=True)
    for host in HOSTS:
        for p in PORTS:
            r = tcp_check(host, p)
            print(json.dumps(r), flush=True)
            time.sleep(GAP)
        for i in range(2):
            print(json.dumps(probe_13401(host)), flush=True)
            time.sleep(GAP)
    # UDP：DoIP ident 到 13400、空包到 13401、外加关闭端口对照
    for host in HOSTS:
        print(json.dumps(udp_probe(host, 13400, bytes([2, 0xFD, 0, 1, 0, 0, 0, 0]))), flush=True)
        print(json.dumps(udp_probe(host, 13401, b"")), flush=True)
        print(json.dumps(udp_probe(host, 34999, b"")), flush=True)
        time.sleep(GAP)
    print(json.dumps({"step": "done"}), flush=True)

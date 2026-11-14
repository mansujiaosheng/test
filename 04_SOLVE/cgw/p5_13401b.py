#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""p5_13401b.py - what exactly does 13401 do to us?

Established: accept() succeeds, then the peer closes before we send a single byte
(58 ms end-to-end, no data in either direction). That rules out TLS/HTTP/DoIP at the
app layer: every one of those reads a first frame before deciding.

Remaining hypotheses:
  H-b  source-address ACL: accept-then-close for unauthorised peers
  H-c  knock / sequencing: N connections then it arms
  H-d  per-source-port binding: the 13401 session is tied to the port that RA'd on 13400
  H-e  it is not TCP at all in the app sense: check UDP 13401
  H-f  half-close behaviour: does it FIN or RST, and is the FIN time constant?
  H-g  13401 only arms while a DoIP session on 13400 is live (RA'd from the same source IP)
"""
import socket, time, json, os, binascii, statistics, struct

EV = r"D:\qwb\03_EVIDENCE\cgw"
OUT = os.path.join(EV, "p5_13401b.jsonl")
HOSTS = ["10.229.221.2", "10.230.164.4"]
PORT = 13401


def hx(b):
    return binascii.hexlify(b).decode().upper()


def measure_close(host, port=PORT, n=6, gap=0.05):
    """Connect, send nothing, measure ms until peer FIN/RST and whether any bytes came."""
    out = []
    for i in range(n):
        t0 = time.time()
        r = {"i": i}
        s = socket.socket()
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(3.0)
        try:
            s.connect((host, port))
            r["connect_ms"] = round((time.time() - t0) * 1000, 1)
            try:
                d = s.recv(4096)
                r["close_kind"] = "FIN" if d == b"" else "DATA"
                r["data"] = hx(d)
            except socket.timeout:
                r["close_kind"] = "STILL-OPEN"
            except ConnectionResetError:
                r["close_kind"] = "RST"
            r["close_ms"] = round((time.time() - t0) * 1000, 1)
        except Exception as e:
            r["close_kind"] = "CONNECT-FAIL"
            r["err"] = repr(e)
        finally:
            s.close()
        out.append(r)
        time.sleep(gap)
    return out


def udp_probe(host, port=PORT):
    res = []
    payloads = [("doip_ident", bytes.fromhex("02FD000100000000")),
                ("tls_hello_tiny", bytes.fromhex("1603010000")),
                ("q", b"\x00"),
                ("sockcan", struct.pack(">I", 0x7E0) + b"\x02\x02\x3E\x00".ljust(64, b"\x00"))]
    for name, pl in payloads:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        try:
            s.sendto(pl, (host, port))
            d, a = s.recvfrom(4096)
            res.append({"name": name, "reply": hx(d), "from": a})
        except socket.timeout:
            res.append({"name": name, "reply": "TIMEOUT"})
        except Exception as e:
            res.append({"name": name, "reply": "ERR " + repr(e)})
        finally:
            s.close()
    return res


def with_live_doip_session(host):
    """Hold an activated DoIP session on 13400, then try 13401 from the same source IP."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import dx
    d = dx.Link(host, 13400, timeout=4.0).connect()
    d.ra()
    print("[%s] 13400 RA activated=%s" % (host, d.activated))
    r = measure_close(host, n=3)
    # also try sending a TLS hello *while* the DoIP session is live
    hello = bytes.fromhex("160301002a010000260303") + os.urandom(32) + bytes.fromhex("0020") + os.urandom(32) + \
            bytes.fromhex("0004130113020100")
    s = socket.socket()
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(3.0)
    try:
        s.connect((host, PORT))
        s.sendall(hello)
        try:
            d2 = s.recv(4096)
            r.append({"while_ra": "reply", "hex": hx(d2)})
        except Exception as e:
            r.append({"while_ra": "no-reply", "err": repr(e)})
    except Exception as e:
        r.append({"while_ra": "connect-fail", "err": repr(e)})
    finally:
        s.close()
    d.close()
    return r


def knock(host, k=6):
    """Rapid sequential connects, then one final connect with a DoIP ident payload."""
    for i in range(k):
        s = socket.socket(); s.settimeout(2.0)
        try:
            s.connect((host, PORT))
            try:
                s.recv(64)
            except Exception:
                pass
        except Exception:
            pass
        finally:
            s.close()
    s = socket.socket(); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); s.settimeout(3.0)
    out = {}
    try:
        s.connect((host, PORT))
        s.sendall(bytes.fromhex("02FD000100000000"))
        try:
            d = s.recv(4096)
            out = {"after_knock": "data" if d else "EOF", "hex": hx(d)}
        except socket.timeout:
            out = {"after_knock": "TIMEOUT"}
        except ConnectionResetError:
            out = {"after_knock": "RST"}
    except Exception as e:
        out = {"after_knock": "connect-fail", "err": repr(e)}
    finally:
        s.close()
    return out


def main():
    recs = []
    for host in HOSTS:
        print("=== %s:%d ===" % (host, PORT), flush=True)
        m = measure_close(host)
        recs.append({"host": host, "test": "measure_close", "data": m})
        kinds = [x.get("close_kind") for x in m]
        ms = [x["close_ms"] for x in m if "close_ms" in x]
        print("  close_kind:", kinds)
        if ms:
            print("  close_ms: min=%.0f median=%.0f max=%.0f" % (min(ms), statistics.median(ms), max(ms)))

        u = udp_probe(host)
        recs.append({"host": host, "test": "udp_13401", "data": u})
        for x in u:
            print("  UDP %-16s -> %s" % (x["name"], x["reply"]))

        k = knock(host)
        recs.append({"host": host, "test": "knock6_then_ident", "data": k})
        print("  after 6 knocks + doip ident:", k)

        w = with_live_doip_session(host)
        recs.append({"host": host, "test": "while_13400_ra_live", "data": w})
        print("  13401 while 13400 RA live:", [x.get("close_kind") or x.get("while_ra") for x in w if isinstance(x, dict)])

    with open(OUT, "a", encoding="utf-8") as f:
        for r in recs:
            r["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("# wrote", OUT)


if __name__ == "__main__":
    main()

"""E8: 10.230.164.4:13401 协议指纹。
方法：fork 一个连接，每次只发 n 个字节，观察服务端是「继续等」还是「关闭/回包」。
若某 n 处行为突变（从等待变为关闭/响应），说明服务端在等 n 字节的定长头。
再用 UDP 探一次，确认是不是 UDP 服务。
"""
import socket, time, struct

H, P = "10.230.164.4", 13401

def probe(payload, wait=1.2, label=""):
    try:
        s = socket.create_connection((H, P), timeout=3)
        s.settimeout(wait)
        if payload:
            s.sendall(payload)
        t0 = time.time()
        try:
            d = s.recv(512)
            state = "CLOSED(0B)" if d == b"" else f"RESP {d[:64].hex()}"
        except socket.timeout:
            state = "WAITING"
        except ConnectionResetError:
            state = "RST"
        dt = time.time() - t0
        s.close()
        return state, round(dt, 2)
    except Exception as e:
        return f"ERR {type(e).__name__}", 0

print("=== 定长边界扫描（零字节）===")
prev = None
for n in list(range(0, 33)) + [40, 48, 64, 128, 256]:
    st, dt = probe(b"\x00" * n, wait=1.0)
    mark = ""
    if prev and st.split()[0] != prev.split()[0]:
        mark = "   <== 行为变化"
    print(f"  n={n:3} -> {st:24} ({dt}s){mark}")
    prev = st

print("\n=== 文本/分隔符 ===")
for pl, lbl in [(b"\n", "LF"), (b"\x00", "NUL"), (b"HELLO\n", "HELLO-LF"),
                (b"GET /\n\n", "GET-lnl"), (b"\x16\x03\x01\x00\x00", "TLS-hdr-partial"),
                (struct.pack(">I", 0), "len0-BE"), (struct.pack(">I", 4) + b"\x00" * 4, "len4-BE"),
                (struct.pack("<I", 4) + b"\x00" * 4, "len4-LE")]:
    st, dt = probe(pl, wait=1.2)
    print(f"  {lbl:18} {pl.hex():20} -> {st} ({dt}s)")

print("\n=== UDP 13401 ===")
try:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2)
    for pl in [b"", b"\x00", b"\x00" * 8, b"PING\n"]:
        u.sendto(pl, (H, P))
        try:
            d, _ = u.recvfrom(512)
            print(f"  UDP {pl[:8].hex():16} -> RESP {d[:64].hex()}")
        except socket.timeout:
            print(f"  UDP {pl[:8].hex():16} -> timeout")
except Exception as e:
    print("  UDP err", e)

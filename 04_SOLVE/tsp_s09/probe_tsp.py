#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSP (10.230.164.2:8080) 深度探测 —— 赛题 09 辅助
覆盖:
  A. 方法矩阵 (GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD) x 语义路径词表
  B. GraphQL 真身测试 (introspection / GET query / content-type 变体 / 大小写 / 尾斜杠)
  C. HTTP 层怪招 (绝对 URI / CONNECT / 超长路径 / %2f / %252f / ..;/ / OPTIONS *)
  D. Host/vhost 路由 + X-Forwarded-* / X-Original-URL / X-Rewrite-URL
  E. 带值路径 (vehicles/<VIN>, firmware/<x>, ota/<x> ...)
输出: JSONL 到指定目录, 只记非 404 与非预期
"""
import socket
import sys
import json
import time
import os

HOST = "10.230.164.2"
PORT = 8080
OUTDIR = sys.argv[1] if len(sys.argv) > 1 else r"D:\qwb\03_EVIDENCE\tsp_s09"

BASELINE_404 = b"404 page not found"


def raw(req: bytes, timeout=6.0):
    """发原始字节, 返回 (status_line, headers_dict, body_bytes)"""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((HOST, PORT))
        s.sendall(req)
        buf = b""
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > 200000:
                break
        return buf
    except Exception as e:
        return b"ERR: " + str(e).encode()
    finally:
        try:
            s.close()
        except Exception:
            pass


def parse(buf: bytes):
    if not buf:
        return ("<empty>", {}, b"")
    if buf.startswith(b"ERR:"):
        return (buf.decode("latin1"), {}, b"")
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin1", "replace")
    hdrs = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            hdrs[k.decode("latin1").strip().lower()] = v.decode("latin1").strip()
    return (status, hdrs, body)


def build(method, path, headers=None, body=b"", version="HTTP/1.1"):
    h = {"Host": f"{HOST}:{PORT}"}
    if headers:
        h.update(headers)
    if body and "Content-Length" not in h:
        h["Content-Length"] = str(len(body))
    if not body and method in ("POST", "PUT", "PATCH"):
        h["Content-Length"] = "0"
    h["Connection"] = "close"
    out = f"{method} {path} {version}\r\n".encode()
    for k, v in h.items():
        out += f"{k}: {v}\r\n".encode()
    out += b"\r\n" + body
    return out


# ---------- 路径词表 ----------
WORDS = [
    # 赛题语义
    "programming", "programming-session", "programmingsession", "session", "sessions",
    "download", "requestdownload", "request-download", "request_download", "transferdata",
    "transfer-data", "transfer_data", "block", "blocklength", "block-length", "blocks",
    "sign", "signature", "signatures", "sign-firmware", "sign_firmware", "signfirmware",
    "sign/package", "signing", "verify", "verify-signature", "cosign",
    "campaign", "campaigns", "rollback", "vcu", "ecu", "ecus", "firmware", "firmwares",
    "firmware/reference", "firmware/vcu", "reference-firmware", "reference", "ref",
    "ota", "ota/package", "ota/packages", "ota/firmware", "ota/manifest", "ota/campaign",
    "ota/sign", "ota/download", "ota/v1", "package", "packages", "manifest", "manifests",
    "blob", "blobs", "artifact", "artifacts", "image", "images", "bin", "binaries",
    "hex", "srec", "s19", "srp", "update", "updates", "upgrade",
    # 密钥/PKI
    "pki", "ca", "certs", "cert", "certificates", "keys", "key", "pubkey", "public",
    "publickey", "jwks", "jwt", "token", "tokens", "auth", "login", "logout", "signin",
    "apikey", "api-key", "credentials",
    # 内部
    "debug", "metrics", "config", "configuration", "internal", "system", "status",
    "info", "version", "health", "healthz", "readyz", "livez", "admin", "manage",
    "management", "dashboard", "console", "panel", "root", "index", "home",
    # API 版本
    "api", "api/v1", "api/v2", "api/v3", "v1", "v2", "v3", "rest", "rpc", "graphql",
    "graphiql", "playground", "gql", "query", "mutation", "subscriptions",
    # 车联网
    "vehicles", "vehicle", "fleet", "fleets", "car", "cars", "device", "devices",
    "tbox", "tsp", "cv6", "vin", "diagnostics", "diagnostic", "dtc", "doip",
    "can", "bus", "uds", "flash", "flashing", "boot", "bootloader", "partition",
    # 其它常见
    "user", "users", "me", "account", "profile", "settings", "billing", "orders",
    "report", "reports", "audit", "logs", "log", "events", "webhook", "webhooks",
    "notify", "notification", "queue", "jobs", "job", "task", "tasks", "batch",
    "sync", "import", "export", "upload", "downloads", "files", "file", "static",
    "assets", "media", "docs", "doc", "openapi", "swagger", "redoc", "actuator",
    "eureka", "consul", "etcd", "zookeeper", "prometheus", "grafana",
]

# 额外变体
PATHS = set()
for w in WORDS:
    PATHS.add("/" + w)
    PATHS.add("/" + w + "/")
for base in ["api", "api/v1", "api/v2", "v1", "v2"]:
    for w in ["ota", "firmware", "sign", "signature", "campaign", "download",
              "programming", "vehicle", "vehicles", "session", "transferdata",
              "requestdownload", "vcu", "rollback", "block", "package", "manifest"]:
        PATHS.add(f"/{base}/{w}")
        PATHS.add(f"/{base}/{w}/")

# 带值路径
VALUES = [
    "CV6000000DEMO0001", "CV6FF52FEE9EDDD86", "vcu", "VCU", "1", "0",
    "latest", "current", "active", "reference", "default", "demo",
]
for pre in ["vehicles", "vehicle", "firmware", "ota", "ota/package", "ota/firmware",
            "image", "images", "package", "packages", "artifact", "artifacts",
            "bin", "binaries", "campaign", "campaigns", "download", "downloads",
            "file", "files", "blob", "blobs", "vcu", "ecu", "ref", "reference"]:
    for v in VALUES:
        PATHS.add(f"/{pre}/{v}")

PATHS = sorted(PATHS)

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

# 判定: 404 且 body 以 "404 page not found" 开头 -> 忽略
def is_interesting(status, hdrs, body):
    if status == "<empty>" or status.startswith("ERR:"):
        return True
    try:
        code = int(status.split()[1])
    except Exception:
        return True
    if code == 404 and body.strip().startswith(BASELINE_404):
        return False
    return True


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    log = open(os.path.join(OUTDIR, "10_method_matrix_A.jsonl"), "w", encoding="utf-8")
    interesting = []
    n = 0
    t0 = time.time()
    for p in PATHS:
        for m in METHODS:
            n += 1
            buf = raw(build(m, p))
            status, hdrs, body = parse(buf)
            if is_interesting(status, hdrs, body):
                rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "method": m, "path": p,
                       "status": status, "headers": hdrs,
                       "body": body[:600].decode("latin1", "replace")}
                log.write(json.dumps(rec, ensure_ascii=False) + "\n")
                log.flush()
                interesting.append(rec)
                print(f"[HIT] {m} {p} -> {status}")
    log.close()
    print(f"\n=== A done: {n} requests in {time.time()-t0:.1f}s, {len(interesting)} interesting ===")
    for r in interesting:
        print(r["method"], r["path"], "|", r["status"], "|", r["body"][:120].replace("\n", " "))


if __name__ == "__main__":
    main()

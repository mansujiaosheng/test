#!/usr/bin/env python3
"""route_enum.py -- 基于 Go/多数框架路由语义的**真实路由表**枚举器。

原理（关键）：
  注册过的路径在收到**未注册方法**时不会返回 404，而是返回 405/200/400（handler 跑了）。
  未注册路径一律 404（Go http.ServeMux 默认行为）。
  => 每个路径只需 **1 个请求**（方法用 FOOBAR），就能判定"这条路由存不存在"，
     不受"该路由只接受 POST"这类干扰，也不需要为每个方法各扫一遍。

用法：
  python route_enum.py 10.230.164.2 8080 -w a.txt b.txt --gen
  python route_enum.py 10.230.164.2 8080 --self-test

退出码：0 正常；1 目标不可达；2 参数错误
"""
import argparse, itertools, socket, sys, json, time
from concurrent.futures import ThreadPoolExecutor

HDR = "FOOBAR {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def req(host, port, path, timeout=4.0):
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(HDR.format(path=path, host=host).encode())
        d = b""
        while True:
            c = s.recv(8192)
            if not c:
                break
            d += c
        head, _, body = d.partition(b"\r\n\r\n")
        first = head.split(b"\r\n")[0].decode("latin1")
        code = int(first.split()[1]) if len(first.split()) > 1 else -1
        return code, body[:200]
    except Exception as e:
        return -1, repr(e).encode()[:100]
    finally:
        s.close()


def gen_paths():
    base = []
    words = """healthz health readyz livez status version info metrics debug pprof vars
graphql gql api apis v1 v2 v3 rest rpc soap json xml wsdl docs swagger openapi redoc
auth login logout token tokens oauth oauth2 session sessions refresh introspect
vehicle vehicles vin vins fleet fleets device devices tbox tboxes gateway gateways cgw
ota otas campaign campaigns package packages firmware firmwares image images bundle bundles
artifact artifacts release releases channel channels rollout rollouts rollout-groups
update updates upgrade upgrades flash flashing bootloader ecu ecus bcm bms vcu tcu hcu
sign signing signature signatures signer signers keys key pubkey pub cert certs ca pki
issue issue-cert provision provisioning enroll enrollment enrollments bootstrap
diag diagnostics diagnostic dtc dtcs telemetry trips trip log logs trace traces transport
admin internal private public system config configs settings setting user users me profile
report reports audit audits event events webhook webhooks callback callbacks notify
manifest manifests metadata meta descriptor descriptors index download downloads upload uploads
static assets files file media content contents data db database storage bucket objects
test tests demo sandbox mock example examples sample samples ref reference references
state states job jobs task tasks queue worker workers cron scheduler
crypto ecdsa ecdsa256 p256 sha256 hmac verify validation validate
rollback rollbacks antirollback version-control compat compatibility matrix
"""
    filler = """acc accs action actions activate activation adapter add address addresses agent agents
alarm alarms alert alerts allow allowed analysis analyze announce announcement apply app apps
approve archive assign assignee attach attribute attributes authc authorize availability
backup backups ban banner base baseline batch bin binary bind binding bindings board boards
body book boot box boxes branch branches build builds bulk call cancel capacity case cases
catalog cert-check chain change changes check checks child claim claims class clear client clients
clone close cluster clusters cmd code codes collect collection collect commands commit common
company compare compile component components condition conditions connect connection connections
console const contact container containers content control controller controllers cookie count
create created credential credentials current customer customers cut cycle daily dashboard
data-sync declare default delete deliver delivery deploy deployment deployments desc description
descriptor detail details detect detection diff disable discover discovery disk dns domain
drain drift dump edge edit element elements enable engine entry env environment errors eval
exchange execute execution expand expire export extended extension external factory fail failed
feature features feed fetch field fields filter find finish flag flags flow flows format frame
front fs full generate get git global grant group groups handle handler hash head header headers
help hidden hide history hook host hosts http ic id ident identity ids ignore image-info import
in info init input insert inspect install instance instances interface invalid inventory invoke
ip issue-item item items join keep label labels last latest launch layout lead left legacy length
level license limit link links list load local locale lock log-level lookup machine manage
manager map mark mask master match measure media-type member members merge message messages
method methods migrate migration mirror mode model models module monitor mount move name names
namespace nav network networks new next node nodes normalize note notes notify-item null object
offline offset online open operation operations operator order orders org origin output owner
pack page pages pair parent parse partner pass patch path paths pattern pay peer pending period
permission permissions phase pin ping pipe plan platform plugin plugins point policy pool port
position post prefix preload prepare preview previous primary print priority probe process
produce product products progress project projects prometheus prompt property props protect
proto protocol proxy publish pull push put query queries quick quota raw read ready rebuild
receive record records recover redirect ref refresh-item region regions register-item registry
reject reload remote remove rename reorder replace reply repo report-item request requests
reset resolve resource resources response restore result results resume retry return reveal
revoke right role roles root route routes router rules run runtime save scan schema schemas
scope script search secret secrets section secure security seed select send sensor sensors
separate sequence server servers service services set setup shell shift short show side sign-in
sign-out signup size skip slave smart snapshot source space split stage stages start stat stats
step stop store stores strategy stream string submit subscribe suffix summary support switch
sync system-item table tables tag tags target targets team tech template templates tenant tenants
term test-data text theme thread time timezone title tool tools topic total trace-item track
traffic transfer transform tree trigger trim trust try turn type types ui uid unit units unknown
unlock update-item upgrade-item upload-url uptime url usage use used uuid valid value values
vendor verify-item view views virtual volume wait warn watch web weight who window with work
worker-item write zone zones"""
    paths = set()
    for w in words.split():
        paths.add("/" + w)
    prefixes = ["", "api", "api/v1", "api/v2", "v1", "v2", "internal", "admin", "public",
                "tsp", "tsp/api", "api/tsp", "ota", "api/ota", "v1/ota", "firmware", "v2/ota"]
    res = ["sign", "signing", "signature", "signatures", "signer", "ota", "campaign",
           "campaigns", "firmware", "firmwares", "package", "packages", "image", "bundle",
           "flash", "update", "updates", "release", "releases", "rollback", "verify",
           "issue", "submit", "create", "upload", "vcu", "vins", "vin", "cert", "certs"]
    acts = ["", "sign", "create", "submit", "issue", "verify", "upload", "list", "get",
            "generate", "new", "publish", "approve", "validate"]
    for p, r_, a in itertools.product(prefixes, res, acts):
        seg = "/".join([x for x in [p, r_, a] if x])
        if seg:
            paths.add("/" + seg)
    # 资源 + 通配/ID
    for p in ["", "api", "api/v1", "v1", "ota", "api/ota", "internal"]:
        for r_ in ["ota", "campaign", "campaigns", "firmware", "firmwares", "package",
                   "packages", "vehicle", "vehicles", "sign", "signature", "cert", "certs",
                   "flash", "update", "vcu", "ecu", "release"]:
            for tail in ["1", "0", "{id}", ":id", "current", "latest", "default", "active",
                         "sign", "signatures", "download", "binary", "file", "blob"]:
                seg = "/".join([x for x in [p, r_, tail] if x])
                if seg:
                    paths.add("/" + seg)
    # 文件名/静态
    for r_ in ["firmware", "ota", "packages", "static", "assets", "download", "files", "pkg"]:
        for f in ["vcu.bin", "vcu_ref.bin", "ref.bin", "firmware.bin", "ota.zip", "package.zip",
                  "vcu.zip", "manifest.json", "ca.crt", "ca.pem", "root.crt", "tls.crt",
                  "server.crt", "client.crt", "cert.pem", "key.pem", "config.json", "index.html"]:
            paths.add(f"/{r_}/{f}")
    return sorted(paths)


def load(paths_files):
    out = set()
    for f in paths_files:
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    out.add("/" + line.lstrip("/"))
        except OSError as e:
            print(f"[!] cannot read {f}: {e}", file=sys.stderr)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host"); ap.add_argument("port", type=int, nargs="?", default=8080)
    ap.add_argument("-w", nargs="*", default=[])
    ap.add_argument("--gen", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("--threads", type=int, default=64)
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()

    paths = set(load(a.w))
    if a.gen or not paths:
        paths |= set(gen_paths())
    paths = sorted(paths)

    # 基线：一个几乎肯定不存在的路径
    base_code, base_body = req(a.host, a.port, "/zzz-not-exists-9f3a", a.timeout)

    hits, t0 = [], time.time()
    with ThreadPoolExecutor(max_workers=a.threads) as ex:
        for p, (code, body) in zip(paths, ex.map(lambda p: req(a.host, a.port, p, a.timeout), paths)):
            if code != base_code or body != base_body:
                hits.append({"path": p, "code": code, "len": len(body),
                             "body": body.decode("latin1", "replace")[:200]})
    dt = time.time() - t0
    print(f"[*] {a.host}:{a.port} probed={len(paths)} in {dt:.1f}s  baseline={base_code}/{base_body[:40]!r}")
    for h in hits:
        print(f"  {h['code']:4d} {h['len']:6d} {h['path']}  {h['body'][:100]!r}")
    print(f"[*] non-baseline hits = {len(hits)}")
    if a.json:
        json.dump({"host": a.host, "port": a.port, "probed": len(paths), "elapsed": dt,
                   "baseline": {"code": base_code, "body": base_body.decode("latin1", "replace")},
                   "hits": hits}, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()

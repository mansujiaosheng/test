#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate the CGW :8080 route wordlist.

Design notes (why this is not a generic dirbuster list):
  * The server is a Go binary whose mux does decoded-path exact matching and
    has NO 405 oracle (any method hits /healthz). So the ONLY signal for a
    registered route is "status != 404 or body_len != 19".
  * 40 first-level prefixes (/api /v1 /diag /doip /canfd /bridge ...) were
    probed as subtree roots (/P and /P/zzq7x) -> all 404/19. Therefore routes,
    if any, are literal full paths of depth 1..3.
  * So the list is a cross product of domain vocabulary (CGW / DoIP / UDS /
    CAN(FD) / SecOC) with REST-ish container+object+action shapes, plus the
    usual Go dev endpoints.

Output: wordlist.txt (one path per line, leading '/'), plus probe list for
wildcard-subtree detection.
"""
import itertools
import os
import re

# ---------------------------------------------------------------- vocabulary
OBJ = """
diag diagnostics diagnostic diagservice diagservices routine routines
uds doip doipserver can canfd canfd_bridge can_fd canbridge bridge
gateway gw cgw vehicle vehicles ecu ecus bus buses frame frames secoc
payload freshness cmac key keys seed counter dtc dtcs fault faults obd
isotp tp node nodes target targets channel channels link links port ports
vcan socket sockets raw monitor sniff trace capture log logs event events
data mode modes state status config
""".split()

ACT = """
enable disable open close start stop on off control send tx rx inject
forward exec invoke run list get status info create delete reset clear set
config cmd command action mount attach connect link pump relay bridge
activate deactivate toggle up down patch write read
""".split()

PRE = """
api apis v1 v2 v3 internal admin mgmt management gateway gw cgw diag
system sys service services debug private secure root _internal _admin __admin
""".split()

PRE_TOP = "api v1 v2 internal admin mgmt cgw diag".split()
OBJ_TOP = """
canfd can can_fd can-fd bridge gateway diag diagnostics routine uds doip
frame session ecu secoc vehicle payload bus
""".split()
ACT_TOP = "enable disable control send start stop tx rx inject status".split()

paths = set()


def add(p):
    p = "/" + p.strip("/")
    if p != "/" and "//" not in p:
        paths.add(p)


# 1) depth 1
for t in set(OBJ) | set(ACT) | set(PRE):
    add(t)

# 2) PRE / X
for a, b in itertools.product(PRE, OBJ):
    add(a + "/" + b)
for a, b in itertools.product(PRE, ACT):
    add(a + "/" + b)

# 3) OBJ / ACT
for a, b in itertools.product(OBJ, ACT):
    add(a + "/" + b)

# 4) PRE / OBJ / ACT  (restricted cross product)
for a, b, c in itertools.product(PRE_TOP, OBJ_TOP, ACT_TOP):
    add(a + "/" + b + "/" + c)

# 5) api/v1/<obj>[/<act>]
for b in OBJ:
    add("api/v1/" + b)
for b, c in itertools.product(OBJ_TOP, ACT_TOP):
    add("api/v1/" + b + "/" + c)
    add("v1/" + b + "/" + c)
    add("api/v2/" + b + "/" + c)

# 6) hyphen / underscore / camel variants of the juicy compounds
COMPOUND = [
    "canfd", "can-fd", "can_fd", "canfd-bridge", "canfd_bridge", "can-fd-bridge",
    "can-fd_bridge", "canbridge", "can-bridge", "can_bridge",
    "diag-routine", "diag_routine", "diagroutine",
    "doip-routine", "doip_routine", "doiproutine",
    "secoc-key", "secoc_key", "freshness-read", "freshness_read",
]
for c in COMPOUND:
    add(c)
    for p in ("api", "v1", "api/v1", "internal", "admin", "diag", "cgw", "gateway"):
        add(p + "/" + c)

# 7) framework / dev / docs endpoints (Go-flavoured)
FRAMEWORK = """
healthz readyz livez startupz health healthcheck ping pong version buildinfo
info metrics debug vars pprof
debug/pprof debug/pprof/ debug/pprof/cmdline debug/pprof/profile
debug/pprof/symbol debug/pprof/trace debug/pprof/heap debug/pprof/goroutine
debug/pprof/allocs debug/pprof/block debug/pprof/mutex debug/pprof/threadcreate
debug/vars debug/requests debug/events
openapi.json openapi.yaml openapi.yml swagger.json swagger.yaml swagger.yml
swagger swagger/ swagger/index.html swagger-ui swagger-ui/ redoc docs doc
api-docs api/docs apidocs api/openapi.json api/swagger.json
robots.txt favicon.ico index.html index.htm index
README README.md readme readme.md CHANGELOG LICENSE NOTICE
actuator actuator/health actuator/info actuator/env actuator/routes
actuator/mappings actudoc routes route table tables endpoints endpoint
status stats statistics zpages
-/healthz
""".split()
for f in FRAMEWORK:
    add(f)

# 8) extra CGW-flavoured guesses
EXTRA = """
diag/routine/routine diag/routine/enable routine/enable routine/control
diag/control diag/session diag/sessions diag/start diag/stop
canfd/bridge canfd/bridge/enable can/bridge can/bridge/enable
bridge/enable bridge/control bridge/state bridge/status bridge/on
doip/routine doip/control doip/session doip/start
uds/routine uds/control uds/session uds/enable
vehicle/bridge vehicle/diag vehicles/diag
gateway/bridge gateway/diag gateway/routine gateway/control gateway/status
cgw/bridge cgw/diag cgw/routine cgw/control cgw/status cgw/api
canfd/enable canfd/state canfd/status canfd/control canfd/start
can/enable can/start can/control can/state can/status can/send can/tx
frame/send frame/inject frame/tx frames/send
send frame relay/enable relay/start relay/on tunnel/enable
enable disable control start stop
admin/diag admin/bridge internal/diag internal/bridge internal/canfd
mgmt/diag mgmt/bridge api/diag api/diag/routine api/diag/routines
api/v1/diag/routine api/v1/diag/routines api/v1/diagnostics/routine
api/v1/bridge/enable api/v1/canfd/enable api/v1/canfd/bridge
api/v1/routine api/v1/routine/control api/v1/uds/routine
v1/diag v1/diag/routine v1/canfd v1/canfd/enable v1/bridge v1/bridge/enable
v1/routine v1/routine/control v1/uds v1/doip v1/doip/routine
healthz/readyz healthz/livez api/healthz api/health api/status api/version
""".split()
for f in EXTRA:
    add(f)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    lst = sorted(paths)
    with open(os.path.join(here, "wordlist.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lst) + "\n")
    # wildcard-subtree probes: /P/zzq7x for every depth-1 token and depth-2 head
    heads = set()
    for p in lst:
        seg = p.strip("/").split("/")
        if len(seg) >= 1:
            heads.add("/" + seg[0])
        if len(seg) >= 2:
            heads.add("/" + seg[0] + "/" + seg[1])
    wild = sorted(h + "/zzq7x" for h in heads)
    with open(os.path.join(here, "wordlist_wild.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(wild) + "\n")
    print("wordlist.txt      : %d paths" % len(lst))
    print("wordlist_wild.txt : %d probes" % len(wild))


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""Poll the TSP/TBOX stubs and detect the moment a real GraphQL service appears.
Writes JSONL samples + a human log. Exits after MAX_SAMPLES."""
import sys, os, json, time, hashlib, ssl, socket, traceback
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from httpc import request, request_raw

EV = "03_EVIDENCE/tsp"
J = os.path.join(EV, "0405_tsplive.jsonl")
LOG = os.path.join(EV, "0405_tsplive.log")
MAX_SAMPLES = int(os.environ.get("MAX_SAMPLES", "80"))
INTERVAL = float(os.environ.get("INTERVAL", "60"))

TARGETS = [("10.230.164.2", 8080), ("10.230.164.3", 8080),
           ("10.230.164.4", 8080), ("10.229.221.2", 8080)]
STUB_BODY = b'{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}\n'

def log(s):
    line = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + s
    print(line, flush=True)
    with open(LOG, "a", encoding="utf-8") as f: f.write(line + "\n")

def cert_serial(host, port):
    try:
        ctx = ssl._create_unverified_context()
        s = socket.socket(); s.settimeout(6)
        s.connect((host, port))
        ss = ctx.wrap_socket(s, server_hostname="tbox")
        der = ss.getpeercert(binary_form=True); ss.close()
        return hashlib.sha256(der).hexdigest()[:16]
    except Exception as e:
        return "ERR:" + type(e).__name__

def sample():
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "targets": {}}
    for h, p in TARGETS:
        t = {}
        try:
            r = request(h, p, "POST", "/graphql",
                        headers=[("Content-Type", "application/json")],
                        body=b'{"query":"{ __typename }"}', timeout=8)
            t["gql_post"] = {"status": r.status, "len": len(r.body),
                             "sha": hashlib.sha256(r.body).hexdigest()[:16],
                             "canned": r.body == STUB_BODY, "body": r.body[:160].decode("latin1")}
        except Exception as e:
            t["gql_post"] = {"err": repr(e)[:80]}
        try:
            r = request(h, p, "GET", "/graphql", timeout=8)
            t["gql_get"] = {"status": r.status, "len": len(r.body)}
        except Exception as e:
            t["gql_get"] = {"err": repr(e)[:80]}
        try:
            r = request(h, p, "GET", "/healthz", timeout=8)
            t["healthz"] = {"status": r.status, "body": r.body[:60].decode("latin1")}
        except Exception as e:
            t["healthz"] = {"err": repr(e)[:80]}
        # new-surface probes that would light up if a real service replaced the stub
        for probe in ("/graphql/v1", "/api/graphql", "/v1/graphql", "/ota", "/api/ota"):
            try:
                r = request(h, p, "GET", probe, timeout=6)
                if r.status not in (404,):
                    t["probe" + probe] = {"status": r.status, "body": r.body[:80].decode("latin1")}
            except Exception:
                pass
        rec["targets"][f"{h}:{p}"] = t
    rec["mtls_cert_sha"] = cert_serial("10.230.164.3", 8443)
    return rec

baseline = None
log(f"=== tsplive start  targets={TARGETS}  interval={INTERVAL}s  max={MAX_SAMPLES} ===")
for i in range(MAX_SAMPLES):
    try:
        rec = sample()
        rec["i"] = i
        with open(J, "a", encoding="utf-8") as f: f.write(json.dumps(rec) + "\n")
        sig = json.dumps({k: {kk: (vv.get("sha") or vv.get("status") or vv.get("err"))
                              for kk, vv in v.items()} for k, v in rec["targets"].items()},
                         sort_keys=True)
        if baseline is None:
            baseline = sig
            log(f"[{i}] baseline sig={hashlib.sha256(sig.encode()).hexdigest()[:16]} cert={rec['mtls_cert_sha']}")
            for k, v in rec["targets"].items():
                g = v.get("gql_post", {})
                log(f"      {k:<22} gql_post={g.get('status')} canned={g.get('canned')} sha={g.get('sha')}")
        elif sig != baseline:
            log(f"[{i}] *** CHANGE DETECTED ***")
            log(f"      old={hashlib.sha256(baseline.encode()).hexdigest()[:16]} new={hashlib.sha256(sig.encode()).hexdigest()[:16]}")
            log("      " + json.dumps(rec["targets"])[:1500])
            with open(os.path.join(EV, "0405_CHANGE_DETECTED.json"), "w", encoding="utf-8") as f:
                json.dump(rec, f, indent=1)
            baseline = sig
        else:
            log(f"[{i}] no change  cert={rec['mtls_cert_sha']}")
    except Exception:
        log("[!] sample error\n" + traceback.format_exc()[:600])
    time.sleep(INTERVAL)
log("=== tsplive done ===")

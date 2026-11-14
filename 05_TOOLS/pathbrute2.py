#!/usr/bin/env python3
"""Bigger path brute for CTF web reco. Read-only."""
import sys, concurrent.futures, requests, itertools
requests.packages.urllib3.disable_warnings()
BASE = """
api api/v1 api/v2 api/v3 v1 v2 v3 graphql graphiql playground query
ota otas ota/jobs ota/job ota/campaign ota/campaigns ota/package ota/packages ota/download ota/upload ota/manifest ota/sign ota/verify
firmware firmwares firmware/list firmware/download firmware/upload firmware/latest firmware/sign
package packages pkg artifact artifacts release releases image images update updates upgrade upgrades flash flashing
vehicle vehicles vin vins tbox tbox/ota tbox/update tbox/firmware tbox/diag tbox/diagnostics tbox/cert tbox/certs tbox/register tbox/provision
diag diagnostics diag/run diag/start diag/report diagnostic dtc dtcs
cgw gateway gw doip can canfd can-fd bridge frames frame send recv uds
bcm bms vcu ecu ecus secoc key keys keyderiv kdf derive derivation
auth login logout token tokens refresh register enroll enrollments provision provisioning bootstrap ca cert certs certificate certificates crl ocsp
admin internal debug config settings status info health healthz readyz livez metrics stats version ping
sign verify signature signatures hmac aes gcm wrap unwrap rfc3394 kek dek
download downloads upload uploads file files static assets public private data storage
report reports log logs audit backup db database
download/ota download/firmware get_ota get_firmware ota/get ota/fetch fetch
""".split()
EXT = ["", ".json", ".zip", ".bin", ".tar.gz", ".txt", ".xml", ".yaml", ".yml"]
VIN = "CV6FF52FEE9EDDD86"
def gen():
    seen=set()
    for b in BASE:
        for e in EXT:
            p=b+e
            if p not in seen: seen.add(p); yield p
    extras=[f"ota/{VIN}", f"ota/{VIN}.zip", f"firmware/{VIN}", f"firmware/{VIN}.bin",
            f"vehicles/{VIN}", f"vehicles/{VIN}/ota", f"tbox/{VIN}", f"api/v1/vehicles/{VIN}",
            f"api/v1/ota/{VIN}", f"api/v1/firmware/{VIN}", f"package/{VIN}.zip",
            "CV6000000DEMO0001", "ota/CV6000000DEMO0001.zip"]
    for p in extras:
        if p not in seen: yield p
def probe(host, path, method):
    url=f"http://{host}/{path}"
    try:
        r=requests.request(method,url,timeout=4,verify=False,allow_redirects=False)
        if r.status_code!=404:
            return (method,path,r.status_code,len(r.content),r.headers.get("Content-Type",""),r.text[:120].replace("\n"," "))
    except Exception:
        return None
if __name__=="__main__":
    hosts=sys.argv[1].split(",")
    methods=sys.argv[2].split(",") if len(sys.argv)>2 else ["GET"]
    jobs=[(h,p,m) for h in hosts for p in gen() for m in methods]
    print("jobs",len(jobs))
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for res in ex.map(lambda a: probe(*a), jobs):
            if res: print(*res, sep=" | ", flush=True)

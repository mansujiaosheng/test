import concurrent.futures, requests, itertools
BASE="http://10.226.193.2:8080"
segs="""api api/v1 api/v2 v1 v2 health healthz readyz livez status info version config configs
debug internal admin metrics diag diagnostics diagnostic uds doip can canfd isotp bridge
session sessions ticket tickets auth token tokens login ota firmware fw update updates
vehicle vehicles ecu ecus cgw tbox bms bcm vcu vcuupdate sign signature verify key keys
security access seed unlock open enable start stop state control command cmd routine
routines engineering bundle bundles package packages artifact artifacts manifest manifest.json
download upload transfer flash program programming bootloader secoc freshness cmac
objectives objective final flag result results test tests probe ping echo""".split()
leaves=["","/open","/enable","/start","/status","/session","/seed","/key","/unlock","/bind",
"/ticket","/sign","/verify","/final","/list","/info","/state","/read","/write","/send","/recv"]
paths=set()
for s in segs:
    for l in leaves:
        paths.add(f"/{s}{l}")
        paths.add(f"/api/v1/{s}{l}")
def probe(p):
    for m in ("GET","POST"):
        try:
            r=requests.request(m,BASE+p,timeout=3,allow_redirects=False,
                               json={} if m=="POST" else None)
            if r.status_code!=404:
                return f"{m:4s} {r.status_code} {len(r.content):5d} {p}  {r.text[:120]!r}"
        except Exception: pass
    return None
print(f"scanning {len(paths)} paths on CGW 8080")
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
    for res in ex.map(probe,sorted(paths)):
        if res: print(res,flush=True)
print("done")

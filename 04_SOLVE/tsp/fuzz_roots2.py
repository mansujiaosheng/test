import requests
URL="http://10.225.139.2:8080/graphql"
BASE='{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN="CV622697F82A936A1"
roots="""vehicleDiagnostics vehicleOta vehicleOtaCredentials vehicleCredentials otaCredentials otaAuth
vehicleAuth diagnosticAuth firmwareAuth credentials login token auth otaLogin vehicleLogin fleetCredentials
vehicleBundle bundle engineeringBundle otaBundle vehiclePackage packageCredentials bundleCredentials
firmwareDownload otaDownload download vehicleFirmware firmware vcu vcuFirmware vehicleVcu ota otaCampaign
vehicleCampaign campaign campaigns diagnostics diag otaSign sign signature signingKey manifest
engineering engineeringPackage artifacts resources keys secret secrets tboxCredential tboxAuth
vehicleDiagnostic diagnosticEntry entry""".split()
for r in roots:
    body={"query":f"{{ {r} {{ vin }} }}","variables":{"vin":VIN}}
    try:
        x=requests.post(URL,json=body,timeout=5)
        t=x.text.strip()
        if t!=BASE:
            print("DIFF",r,x.status_code,t[:400],flush=True)
    except Exception: pass
print("done")

import requests
URL="http://10.225.139.2:8080/graphql"
BASE='{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
keys="""query variables operationName extensions token access_token accessToken auth authorization apiKey api_key
vin vehicleId vehicle_id id campaignId campaign signature sign timestamp nonce clientId client_id session
sessionId user username password secret key tenant tenantId fleetId deviceId tboxId lang locale version
apiVersion debug mock fixtures scenario role scope actAs impersonate admin internal bypass pkg package
resource resources ota firmware data payload body request graphql ctx context headers meta""".split()
hits=[]
for k in keys:
    try:
        r=requests.post(URL,json={k:123},timeout=5)
        if r.status_code!=200:
            hits.append((k,r.status_code,r.text[:80]))
            print("TYPE-CHECKED:",k,r.status_code,r.text[:80],flush=True)
    except Exception as e: pass
print("checked",len(keys),"hits",len(hits))

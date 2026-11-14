import socket,struct,binascii,time
HOST=("10.229.221.2",13400); SA=0x0E00
def pkt(pt,payload=b""):
    return bytes([0x02,0xFD])+struct.pack(">H",pt)+struct.pack(">I",len(payload))+payload
def recv(s):
    hdr=b""
    while len(hdr)<8:
        c=s.recv(8-len(hdr))
        if not c: return None
        hdr+=c
    v,iv,pt,pl=struct.unpack(">BBHI",hdr)
    d=b""
    while len(d)<pl:
        c=s.recv(pl-len(d))
        if not c: break
        d+=c
    return pt,d
s=socket.socket(); s.settimeout(3); s.connect(HOST)
s.sendall(pkt(0x0005, bytes.fromhex("0E000000000000"))); recv(s)
NRC={0x10:"generalReject",0x11:"serviceNotSupported",0x12:"subFunctionNotSupported",0x13:"incorrectLength",0x21:"busyRepeatRequest",0x22:"conditionsNotCorrect",0x24:"requestSequenceError",0x31:"requestOutOfRange",0x33:"securityAccessDenied",0x35:"invalidKey",0x36:"exceedAttempts",0x37:"delayNotExpired",0x70:"uploadDownloadNotAccepted",0x71:"transferDataSuspended",0x72:"generalProgrammingFailure",0x73:"wrongBlockSeqCounter",0x78:"responsePending",0x7E:"subFnNotSupportedInSession",0x7F:"serviceNotSupportedInSession"}
res={}
svcs=list(range(0x10,0x40))+[0x83,0x84,0x85,0x86,0x87,0xBA,0xBE,0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA]
for svc in svcs:
    try:
        s.sendall(pkt(0x8001, struct.pack(">HH",SA,0x1000)+bytes([svc])))
        r=recv(s)
        if r is None: res[svc]="TIMEOUT"; continue
        d=r[1][4:]
        res[svc]=binascii.hexlify(d).decode()
    except Exception as e:
        res[svc]="EXC"
        try: s.close()
        except: pass
        s=socket.socket(); s.settimeout(3); s.connect(HOST)
        s.sendall(pkt(0x0005, bytes.fromhex("0E000000000000"))); recv(s)
for svc,v in res.items():
    tag=""
    if isinstance(v,str) and v.startswith("7f") and len(v)>=6:
        n=int(v[4:6],16); tag=NRC.get(n,"")
    print(f"svc 0x{svc:02X} -> {v}  {tag}")
s.close()

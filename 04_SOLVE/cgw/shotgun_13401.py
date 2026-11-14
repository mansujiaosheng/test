#!/usr/bin/env python3
"""Round-5: protocol shotgun on 13401 (<=20 conns, 300 ms apart, 1.5 s read window)."""
import socket, struct, time, json, binascii, sys
sys.path.insert(0,"04_SOLVE/cgw")
from retry import connect_retry
HOST="10.229.221.2"; PORT=13401
def doip(pt, pl): return bytes([2,0xFD])+struct.pack(">H",pt)+struct.pack(">I",len(pl))+pl
uds = bytes.fromhex("22F190")
probes = [
 ("elm_at_attention", b"ATZ\r\n"),
 ("elm_at_info",      b"ATI\r\n"),
 ("slcan_S8",         b"S8\r\n"),
 ("slcan_open",       b"O\r\n"),
 ("socketcand_hi",    b"< hi >\n"),
 ("json_subscribe",   b'{"op":"subscribe","canids":[123]}\n'),
 ("someip_sd",        bytes.fromhex("FFFF8100000000100000000001000000")),
 ("mqtt_connect",     bytes.fromhex("101000044d515454040200000000")),
 ("h2_preface",       b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + bytes.fromhex("000000040000000000")),
 ("doip_ra",          doip(0x0005, bytes.fromhex("0E000000000000"))),
 ("doip_uds",         doip(0x8001, bytes.fromhex("0E001000")+uds)),
 ("len2be_uds",       struct.pack(">H",len(uds))+uds),
 ("len4le_uds",       struct.pack("<I",len(uds))+uds),
 ("cannelloni",       bytes([0,0])+struct.pack("<I",16)+bytes.fromhex("00000123"+"0000000000000000")),
 ("aa55_magic",       bytes.fromhex("AA550100")+uds),
 ("canfd_magic",      b"CANFD"+struct.pack(">I",len(uds))+uds),
 ("cangw_magic",      b"CANGW"+struct.pack(">I",len(uds))+uds),
 ("ascii_uds",        b"22 F1 90\r\n"),
 ("modbus_tcp",       bytes.fromhex("000100000006010300000001")),
 ("isotp_zero",       bytes.fromhex("0000000002")+uds),
]
out=[]
for name,payload in probes:
    try:
        s=connect_retry(HOST,PORT,timeout=3,tries=3); tc=time.time()
        s.sendall(payload); s.settimeout(1.5)
        try:
            c=s.recv(2048); te=time.time()
            r=dict(name=name,sent=payload.hex()[:48],outcome=("FIN" if c==b"" else "DATA:"+binascii.hexlify(c).decode()),ms=round((te-tc)*1000,1))
        except socket.timeout:
            r=dict(name=name,sent=payload.hex()[:48],outcome="STILL_OPEN_AFTER_SEND",ms=1500)
        except ConnectionResetError:
            r=dict(name=name,sent=payload.hex()[:48],outcome="RST",ms=round((time.time()-tc)*1000,1))
        s.close()
    except Exception as e:
        r=dict(name=name,outcome="ERR",err=type(e).__name__+":"+str(e))
    out.append(r); print(json.dumps(r),flush=True); time.sleep(0.3)
print(json.dumps({"summary":[o["outcome"] for o in out]}))

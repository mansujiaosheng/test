#!/usr/bin/env python3
"""Minimal DoIP/UDS client for CV6 CGW (0xE442 -> node 0x1220)."""
import socket, struct, time

PT_IDENT_REQ=0x0001; PT_IDENT_RES=0x0004; PT_RA_REQ=0x0005; PT_RA_RES=0x0006
PT_DIAG=0x8001; PT_ACK=0x8002; PT_NACK=0x8003

class DoIP:
    def __init__(self, host="10.226.193.2", port=13400, sa=0x0E00, timeout=3.0):
        self.host,self.port,self.sa,self.timeout=host,port,sa,timeout
        self.s=None; self.buf=b""
    @staticmethod
    def pkt(ptype,payload=b""):
        return bytes([0x02,0xFD])+struct.pack(">H",ptype)+struct.pack(">I",len(payload))+payload
    def connect(self):
        self.s=socket.socket(); self.s.settimeout(self.timeout); self.s.connect((self.host,self.port)); return self
    def close(self):
        if self.s: self.s.close(); self.s=None
    def recv_pkt(self):
        hdr=b""
        while len(hdr)<8:
            c=self.s.recv(8-len(hdr))
            if not c: return None
            hdr+=c
        ver,inv,ptype,plen=struct.unpack(">BBHI",hdr)
        pl=b""
        while len(pl)<plen:
            c=self.s.recv(plen-len(pl))
            if not c: break
            pl+=c
        return (ptype,pl)
    def ident(self):
        self.connect(); self.s.sendall(self.pkt(PT_IDENT_REQ))
        r=self.recv_pkt(); self.close(); return r
    def routing_activation(self, act_type=0x00, oem=b"\x00\x00\x00\x00"):
        self.s.sendall(self.pkt(PT_RA_REQ, struct.pack(">H",self.sa)+bytes([act_type])+oem))
        return self.recv_pkt()
    def uds(self, target_la, data, wait=1.5, drain=3):
        """Send UDS to target_la; return list of (ptype,payload)."""
        self.s.sendall(self.pkt(PT_DIAG, struct.pack(">H",self.sa)+struct.pack(">H",target_la)+data))
        out=[]; old=self.s.gettimeout(); self.s.settimeout(wait)
        try:
            for _ in range(drain):
                r=self.recv_pkt()
                if r is None: break
                out.append(r)
                if r[0]==PT_DIAG: break
        except socket.timeout: pass
        finally: self.s.settimeout(old)
        return out
    @staticmethod
    def parse_uds(payloads, tester_sa=None):
        """payload = SA(2) TA(2) UDS..."""
        res=[]
        for ptype,pl in payloads:
            if ptype!=PT_DIAG or len(pl)<5: continue
            src=struct.unpack(">H",pl[:2])[0]; dst=struct.unpack(">H",pl[2:4])[0]
            uds=pl[4:]
            res.append({"src":"0x%04x"%src,"dst":"0x%04x"%dst,"uds":uds.hex()})
        return res

NRC={0x10:"generalReject",0x11:"serviceNotSupported",0x12:"subFunctionNotSupported",
0x13:"incorrectMessageLengthOrInvalidFormat",0x21:"busyRepeatRequest",0x22:"conditionsNotCorrect",
0x24:"requestSequenceError",0x31:"requestOutOfRange",0x33:"securityAccessDenied",
0x35:"invalidKey",0x36:"exceedNumberOfAttempts",0x37:"requiredTimeDelayNotExpired",
0x7E:"subFunctionNotSupportedInActiveSession",0x7F:"serviceNotSupportedInActiveSession",
0x78:"responsePending"}
def explain(uds_hex):
    if not uds_hex: return "EMPTY"
    b=bytes.fromhex(uds_hex)
    if b[0]==0x7F and len(b)>=3:
        return f"NEG svc=0x{b[1]:02x} NRC=0x{b[2]:02x} {NRC.get(b[2],'')}"
    if b[0]==0x50: return "POS sessionControl "+b.hex()
    if b[0]==0x67: return "POS securityAccess seed/key "+b.hex()
    if b[0]==0x62: return "POS readDataByIdentifier "+b.hex()
    return "POS/OTHER "+b.hex()

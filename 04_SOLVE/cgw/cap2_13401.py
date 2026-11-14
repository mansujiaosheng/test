#!/usr/bin/env python3
"""Round-6: packet-level truth for 13401 (sniff started BEFORE connections).
A) connect-only held 3s  B) connect + 16B data held 3s
C) raw handshake where the 3rd ACK carries 16B payload (data queued before accept returns)
D) raw handshake without payload (control)
"""
import socket, struct, time, json, threading, sys
from scapy.all import conf, sniff, send, sr1, IP, TCP, Raw
conf.verb=0
HOST="10.229.221.2"; PORT=13401
IF=r"\Device\NPF_{42C6004D-50E7-43F6-BA07-8F0CA0F5171F}"
pkts=[]
def start_sniff(dur=14):
    def run():
        pkts.extend(sniff(iface=IF, filter="host %s and tcp port %d"%(HOST,PORT), timeout=dur, store=True))
    t=threading.Thread(target=run); t.start(); return t

def dump(tag, sport, t0):
    rows=[]
    for p in pkts:
        if IP in p and TCP in p and p[TCP].sport==sport or (IP in p and TCP in p and p[TCP].dport==sport):
            t=p[TCP]
            rows.append(dict(dt=round(p.time-t0,4), src=p[IP].src, sport=t.sport,
                             dst=p[IP].dst, dport=t.dport, flags=str(t.flags),
                             seq=t.seq, ack=t.ack, paylen=len(bytes(t.payload)),
                             payload=bytes(t.payload)[:32].hex()))
    print("### %s sport=%d"%(tag,sport), flush=True)
    for r in rows: print(json.dumps(r), flush=True)
    return rows

t0=time.time(); sn=start_sniff(16); time.sleep(1.0)

# A
s=socket.socket(); s.bind(("0.0.0.0",45001)); s.settimeout(4); s.connect((HOST,PORT))
ta=time.time(); time.sleep(3.0)
try: s.recv(100)
except Exception as e: print("A recv", type(e).__name__)
s.close(); time.sleep(0.3)

# B
s=socket.socket(); s.bind(("0.0.0.0",45002)); s.settimeout(4); s.connect((HOST,PORT))
s.sendall(b"\x00"*16); tb=time.time(); time.sleep(3.0)
try: s.recv(100)
except Exception as e: print("B recv", type(e).__name__)
s.close(); time.sleep(0.3)

# C raw: data in 3rd ACK
sp=45003; seq=0x11110000
syn=IP(dst=HOST)/TCP(sport=sp,dport=PORT,flags="S",seq=seq,window=64240)
sa=sr1(syn,timeout=4)
if sa is None:
    print("C no SYN-ACK")
else:
    print("C synack seq=%d"%sa[TCP].seq, flush=True)
    third=IP(dst=HOST)/TCP(sport=sp,dport=PORT,flags="A",seq=seq+1,ack=sa[TCP].seq+1,window=64240)/Raw(b"\x00"*16)
    send(third)
    time.sleep(3.0)
    # close raw: send FIN
    send(IP(dst=HOST)/TCP(sport=sp,dport=PORT,flags="FA",seq=seq+17,ack=sa[TCP].seq+1,window=64240))
    time.sleep(1.0)

# D raw control: no payload in 3rd ACK
sp2=45004; seq2=0x22220000
sa2=sr1(IP(dst=HOST)/TCP(sport=sp2,dport=PORT,flags="S",seq=seq2,window=64240),timeout=4)
if sa2 is None: print("D no SYN-ACK")
else:
    print("D synack seq=%d"%sa2[TCP].seq, flush=True)
    send(IP(dst=HOST)/TCP(sport=sp2,dport=PORT,flags="A",seq=seq2+1,ack=sa2[TCP].seq+1,window=64240))
    time.sleep(3.0)
    send(IP(dst=HOST)/TCP(sport=sp2,dport=PORT,flags="FA",seq=seq2+1,ack=sa2[TCP].seq+1,window=64240))
    time.sleep(1.0)

sn.join()
print("### total captured", len(pkts))
dump("A_connect_only",45001,ta)
dump("B_send16",45002,tb)
dump("C_raw_data_in_ack",45003,t0)
dump("D_raw_no_data",45004,t0)

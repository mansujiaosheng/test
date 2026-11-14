#!/usr/bin/env python3
"""New-env (10.226.193.2) packet-level 13401 test: connect-only / send16 / data-in-3rd-ACK."""
import socket, time, json, threading, sys
from scapy.all import conf, sniff, send, sr1, IP, TCP, Raw
conf.verb=0
HOST=sys.argv[1] if len(sys.argv)>1 else "10.226.193.2"; PORT=13401
IF=r"\Device\NPF_{42C6004D-50E7-43F6-BA07-8F0CA0F5171F}"
pkts=[]
def start_sniff(dur=14):
    def run(): pkts.extend(sniff(iface=IF, filter="host %s and tcp port %d"%(HOST,PORT), timeout=dur, store=True))
    t=threading.Thread(target=run); t.start(); return t
def dump(tag, sport):
    print("### %s sport=%d"%(tag,sport), flush=True)
    for p in pkts:
        if IP in p and TCP in p and (p[TCP].sport==sport or p[TCP].dport==sport):
            t=p[TCP]; print(json.dumps(dict(src=p[IP].src,sport=t.sport,dst=p[IP].dst,dport=t.dport,
                 flags=str(t.flags),seq=t.seq,ack=t.ack,paylen=len(bytes(t.payload)))),flush=True)
t0=time.time(); sn=start_sniff(16); time.sleep(1.0)
# A connect only
s=socket.socket(); s.bind(("0.0.0.0",45101)); s.settimeout(4); s.connect((HOST,PORT)); ta=time.time()
time.sleep(2.5)
try: print("A recv",len(s.recv(64)),flush=True)
except Exception as e: print("A recv",type(e).__name__,flush=True)
s.close(); time.sleep(0.3)
# B send16
s=socket.socket(); s.bind(("0.0.0.0",45102)); s.settimeout(4); s.connect((HOST,PORT)); s.sendall(b"\x00"*16)
time.sleep(2.5)
try: print("B recv",len(s.recv(64)),flush=True)
except Exception as e: print("B recv",type(e).__name__,flush=True)
s.close(); time.sleep(0.3)
# C raw: data in 3rd ACK
sp=45103; seq=0x33330000
sa=sr1(IP(dst=HOST)/TCP(sport=sp,dport=PORT,flags="S",seq=seq,window=64240),timeout=4)
if sa is None: print("C no SYN-ACK",flush=True)
else:
    send(IP(dst=HOST)/TCP(sport=sp,dport=PORT,flags="A",seq=seq+1,ack=sa[TCP].seq+1,window=64240)/Raw(b"\x00"*16))
    time.sleep(2.5)
    send(IP(dst=HOST)/TCP(sport=sp,dport=PORT,flags="FA",seq=seq+17,ack=sa[TCP].seq+1,window=64240))
    time.sleep(0.8)
# D raw no data
sp2=45104; seq2=0x44440000
sa2=sr1(IP(dst=HOST)/TCP(sport=sp2,dport=PORT,flags="S",seq=seq2,window=64240),timeout=4)
if sa2 is None: print("D no SYN-ACK",flush=True)
else:
    send(IP(dst=HOST)/TCP(sport=sp2,dport=PORT,flags="A",seq=seq2+1,ack=sa2[TCP].seq+1,window=64240))
    time.sleep(2.5)
    send(IP(dst=HOST)/TCP(sport=sp2,dport=PORT,flags="FA",seq=seq2+1,ack=sa2[TCP].seq+1,window=64240))
    time.sleep(0.8)
sn.join()
print("### total",len(pkts),flush=True)
for tag,sp in (("A_connect_only",45101),("B_send16",45102),("C_data_in_3rd_ack",45103),("D_no_data",45104)): dump(tag,sp)

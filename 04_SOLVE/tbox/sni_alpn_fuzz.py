import socket, ssl, json, sys, itertools, time

HOST='10.230.164.3'; PORT=8443
SNIS = ['tbox','TBOX','tbox.local','tbox.cv6','diag','diagnostics','ota','firmware','fleet',
        'cv6','root','ca','pki','est','enroll','localhost','api','admin','v1','vehicle',
        'telematics','telemetry','backend','update','swupdate','secure','mtls','default','www',
        'tbox.cybercar','tbox.cybercar.local','diagnostics.local','fleet.local','cv6.local']
ALPNS = [None, ['h2'], ['http/1.1'], ['h2','http/1.1'], ['grpc'], ['acme-tls/1']]

def attempt(sni, alpn, timeout=6):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if alpn: ctx.set_alpn_protocols(alpn)
    try:
        raw = socket.create_connection((HOST,PORT), timeout=timeout)
        s = ctx.wrap_socket(raw, server_hostname=sni)
        # handshake done client-side; try a request, see if alert comes
        try:
            s.sendall(b'GET / HTTP/1.1\r\nHost: '+sni.encode()+b'\r\nConnection: close\r\n\r\n')
            d = s.recv(1024)
        except Exception as e:
            d = b''
            return ('post_hs_err', type(e).__name__+':'+str(e), None)
        return ('resp', d[:80].decode('latin1'), s.selected_alpn_protocol())
    except Exception as e:
        return ('hs_err', type(e).__name__+':'+str(e), None)
    finally:
        try: s.close()
        except: pass

results=[]
for sni in SNIS:
    for alpn in ALPNS:
        r = attempt(sni, alpn)
        results.append({'sni':sni,'alpn':alpn,'r':r})
        if r[0] != 'hs_err' or 'CERTIFICATE_REQUIRED' not in r[1]:
            print('INTERESTING', sni, alpn, r, flush=True)
print('total', len(results))
from collections import Counter
print(Counter(x['r'][0]+'|'+x['r'][1].split(':')[0] for x in results))
json.dump(results, open('03_EVIDENCE/tbox/0005_sni_alpn_fuzz.json','w'), indent=1)

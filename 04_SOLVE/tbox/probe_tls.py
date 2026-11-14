import socket, ssl, sys, json, time

HOST='10.230.164.3'; PORT=8443

def probe(cert=None, key=None, alpn=None, sni='tbox', req=b'GET / HTTP/1.1\r\nHost: tbox\r\nConnection: close\r\n\r\n', timeout=10):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if cert: ctx.load_cert_chain(cert, key)
    if alpn:
        ctx.set_alpn_protocols(alpn)
    out = {'cert': cert, 'alpn': alpn, 'sni': sni}
    try:
        raw = socket.create_connection((HOST, PORT), timeout=timeout)
        s = ctx.wrap_socket(raw, server_hostname=sni if sni else None)
        out['handshake'] = 'OK'
        out['version'] = s.version()
        out['cipher'] = s.cipher()[0]
        out['alpn_sel'] = s.selected_alpn_protocol()
        out['peercert_subject'] = dict(x[0] for x in s.getpeercert()['subject']) if s.getpeercert() else None
        s.sendall(req)
        data=b''
        while True:
            c = s.recv(65536)
            if not c: break
            data += c
            if len(data) > 65536: break
        out['resp_hex_head'] = data[:64].hex()
        out['resp_text'] = data.decode('latin1')
        s.close()
    except Exception as e:
        out['error'] = f'{type(e).__name__}: {e}'
    return out

if __name__ == '__main__':
    tests = json.loads(sys.argv[1]) if len(sys.argv)>1 else [{}]
    for t in tests:
        r = probe(**t)
        print(json.dumps(r, indent=1, ensure_ascii=False))
        print('='*70)

#!/usr/bin/env bash
# T-BOX 8443 TLS surface, round 2: resumption / reconnect / PHA / ticket / CA-list stability.
# Every block prints the exact command that produced it.
# Usage: bash tls_surface2.sh   (writes to stdout; caller tees into 03_EVIDENCE/tbox/)
set -u
H=10.230.164.3
P=8443
SNI=tbox
TMP=$(mktemp -d)
SESS="$TMP/sess.pem"

hdr() { echo; echo "##################### $*"; }

hdr "S01 ticket issuance on a FAILED client-auth handshake (grep NewSessionTicket)"
echo "### cmd: openssl s_client -connect $H:$P -servername $SNI -tls1_3 -sess_out $SESS -msg -ign_eof </dev/null"
openssl s_client -connect $H:$P -servername $SNI -tls1_3 -sess_out "$SESS" -msg -ign_eof </dev/null 2>&1 \
  | grep -E "NewSessionTicket|alert|SSL-Session|Session-ID|New, TLS|Verify return" 
echo "### does a session file exist? "
if [ -s "$SESS" ]; then echo "YES $(wc -c <"$SESS") bytes"; else echo "NO - server never delivered a ticket (handshake aborted at client-auth)"; fi

hdr "S02 session resumption attempt (-sess_in) with the (absent) session"
echo "### cmd: openssl s_client -connect $H:$P -servername $SNI -tls1_3 -sess_in $SESS"
if [ -s "$SESS" ]; then
  openssl s_client -connect $H:$P -servername $SNI -tls1_3 -sess_in "$SESS" 2>&1 \
    | grep -E "Reused|alert|New, TLS|Verify return|Session-ID:"
else
  echo "SKIPPED: no session to resume (S01 produced none)."
  echo "Note: TLS1.3 resumption is PSK-based; without a completed handshake there is no ticket,"
  echo "      so the 'resume-and-skip-client-cert' branch is structurally unreachable."
fi

hdr "S03 -reconnect x3 on one TCP connection (does handshake #2/#3 still demand a cert?)"
echo "### cmd: openssl s_client -connect $H:$P -servername $SNI -tls1_3 -reconnect -no_ticket"
openssl s_client -connect $H:$P -servername $SNI -tls1_3 -reconnect -no_ticket </dev/null 2>&1 \
  | grep -E "^New,|alert|Reused|drop connection" 
echo "### count of certificate-required alerts:"
openssl s_client -connect $H:$P -servername $SNI -tls1_3 -reconnect -no_ticket </dev/null 2>&1 \
  | grep -c "certificate required"

hdr "S04 CA list stability: 3 independent handshakes, extract the certificate_authorities DN"
for i in 1 2 3; do
  echo "### handshake $i: openssl s_client ... -servername $SNI -tls1_3 -msg -no_ticket"
  openssl s_client -connect $H:$P -servername $SNI -tls1_3 -msg -no_ticket </dev/null 2>&1 \
    | awk '/CertificateRequest/{f=1} f&&/^    /{print} /SSLv3 read server certificate request/{f=0}' \
    | tr -d ' ' | tr -d '\n' | sed 's/.*0000//' >/dev/null 2>&1
  openssl s_client -connect $H:$P -servername $SNI -tls1_3 -msg -no_ticket </dev/null 2>&1 \
    | grep -A6 "Handshake \[length .*\], CertificateRequest" | tr -d '\n' | sed 's/  */ /g'
  echo
  sleep 1
done

hdr "S05 CertificateRequest extension list (decoded from one handshake)"
echo "### cmd: openssl s_client ... -msg -no_ticket   (bytes of the CertificateRequest body)"
openssl s_client -connect $H:$P -servername $SNI -tls1_3 -msg -no_ticket </dev/null 2>&1 \
  | grep -A6 "Handshake \[length .*\], CertificateRequest"

hdr "S06 post-handshake-auth advertisement (python ssl post_handshake_auth=True, no client cert)"
echo "### cmd: python -c 'ctx.post_handshake_auth=True; handshake' (see inline)"
python - <<'PY'
import socket, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.post_handshake_auth = True
    ctx.set_alpn_protocols(["h2", "http/1.1"])
except Exception as e:
    print("setup err", e)
s = socket.create_connection(("10.230.164.3", 8443), 8)
try:
    t = ctx.wrap_socket(s, server_hostname="tbox")
    print("handshake OK", t.version(), t.cipher(), "alpn=", t.selected_alpn_protocol())
    t.sendall(b"GET / HTTP/1.1\r\nHost: tbox\r\nConnection: close\r\n\r\n")
    print(t.recv(4096)[:200])
except Exception as e:
    print("handshake err:", type(e).__name__, e)
finally:
    try: s.close()
    except Exception: pass
PY

hdr "S07 nmap cipher/cert enumeration (independent tool, TLS1.2 probe included)"
echo "### cmd: nmap -Pn -p 8443 --script ssl-enum-ciphers,ssl-cert $H"
nmap -Pn -p $P --script ssl-enum-ciphers,ssl-cert $H 2>&1 | sed -n '1,120p'

hdr "S08 session-ticket count on a handshake that carries a (rejected) client cert"
echo "### cmd: openssl s_client -cert 01_TARGETS/tbox/vpn_client.pem -key 01_TARGETS/tbox/vpn_client.key -msg"
openssl s_client -connect $H:$P -servername $SNI -tls1_3 -msg -no_ticket \
  -cert /d/qwb/01_TARGETS/tbox/vpn_client.pem -key /d/qwb/01_TARGETS/tbox/vpn_client.key </dev/null 2>&1 \
  | grep -E "NewSessionTicket|alert|Handshake \[length .*\], (Finished|Certificate)" | head -20

rm -rf "$TMP"
echo
echo "== tls_surface2.sh done =="

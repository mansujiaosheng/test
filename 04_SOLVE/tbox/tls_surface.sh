#!/usr/bin/env bash
# T-BOX 10.230.164.3:8443 TLS surface matrix (A-side, read-only, no brute force)
# Each block: exact command, then raw openssl output. stdin closed => s_client exits.
HOST=10.230.164.3
PORT=8443
run() {
  local label="$1"; shift
  echo "##################### $label"
  echo "### cmd: openssl $*"
  ( exec 2>&1; timeout 12 openssl "$@" </dev/null ) \
    | grep -vE '^( 0 s:| 1 s:| 2 s:)' \
    | sed -n '1,200p'
  echo "### rc=$?"
  echo
}

echo "###### T-BOX 8443 TLS surface matrix  $(date -u +%Y-%m-%dT%H:%M:%SZ) ######"
echo

run "T01 full chain (-showcerts, count certs)" \
  s_client -connect $HOST:$PORT -servername tbox -showcerts
echo "### BEGIN CERT COUNT"
timeout 12 openssl s_client -connect $HOST:$PORT -servername tbox -showcerts </dev/null 2>/dev/null \
  | grep -c -- "-----BEGIN CERTIFICATE-----"
echo "### END CERT COUNT"
echo

run "T02 force TLS1.2" \
  s_client -connect $HOST:$PORT -servername tbox -tls1_2
run "T03 force TLS1.1" \
  s_client -connect $HOST:$PORT -servername tbox -tls1_1
run "T04 force TLS1.0" \
  s_client -connect $HOST:$PORT -servername tbox -tls1
run "T05 TLS1.3 group P-256" \
  s_client -connect $HOST:$PORT -servername tbox -tls1_3 -groups P-256
run "T06 TLS1.3 group secp384r1 only" \
  s_client -connect $HOST:$PORT -servername tbox -tls1_3 -groups secp384r1
run "T07 TLS1.3 group ffdhe2048 only" \
  s_client -connect $HOST:$PORT -servername tbox -tls1_3 -groups ffdhe2048
run "T08 ALPN h2,http/1.1" \
  s_client -connect $HOST:$PORT -servername tbox -alpn h2,http/1.1
run "T09 ALPN acme-tls/1" \
  s_client -connect $HOST:$PORT -servername tbox -alpn acme-tls/1
run "T10 no servername (empty SNI)" \
  s_client -connect $HOST:$PORT -noservername
run "T11 legacy_server_connect (SSLv2-format hello)" \
  s_client -connect $HOST:$PORT -servername tbox -legacy_server_connect
run "T12 TLS1.3 + early data attempt (-early_data)" \
  s_client -connect $HOST:$PORT -servername tbox -tls1_3 -early_data
run "T13 TLS1.3 post-handshake auth flag" \
  s_client -connect $HOST:$PORT -servername tbox -tls1_3 -post_handshake_auth
run "T14 no client cert, send GET immediately (-ign_eof)" \
  s_client -connect $HOST:$PORT -servername tbox -ign_eof -no_ign_eof
run "T15 TLS1.3 PSK (out-of-band) ciphers" \
  s_client -connect $HOST:$PORT -servername tbox -tls1_3 -psk_identity tbox -psk 00112233445566778899aabbccddeeff
run "T16 cipher list smax: TLS_AES_256_GCM_SHA384 only" \
  s_client -connect $HOST:$PORT -servername tbox -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384
run "T17 renegotiation attempt under TLS1.2 (must fail on version)" \
  s_client -connect $HOST:$PORT -servername tbox -tls1_2 -legacy_renegotiation
run "T18 status_request / OCSP stapling" \
  s_client -connect $HOST:$PORT -servername tbox -status
run "T19 compress (TLS compression)" \
  s_client -connect $HOST:$PORT -servername tbox -compress
echo "###### END ######"

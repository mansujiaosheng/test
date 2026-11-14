#!/usr/bin/env bash
# TBOX 8443 mTLS handshake characterization.
# Goal: capture -state/-msg message-level trace for several client-cert variants,
#       and the full CertificateRequest (incl. certificate_authorities DER).
# Usage: ./capture_handshake.sh <outdir>
set -u
OUT="${1:-/d/qwb/03_EVIDENCE/tbox}"
HOST=10.230.164.3
PORT=8443
MAT=/d/qwb/04_SOLVE/tbox/mat
mkdir -p "$OUT"

run() {
  local tag="$1"; shift
  local f="$OUT/${tag}.txt"
  {
    echo "########## $tag ##########"
    echo "### cmd: openssl s_client -connect $HOST:$PORT -servername tbox -tls1_3 -state -msg -no_ticket $*"
    echo "### date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "-------------------------------------------"
  } > "$f"
  # stdin </dev/null so s_client does not try to send an HTTP request
  openssl s_client -connect "$HOST:$PORT" -servername tbox -tls1_3 \
      -state -msg -no_ticket "$@" </dev/null >> "$f" 2>&1
  echo "[rc=$?]" >> "$f"
  echo "wrote $f"
}

# 1. no client cert at all -> expect alert 116 at some specific point
run 0009_hs_nocert

# 2. self-signed client cert (CN=tbox) -> expect alert 48
run 0010_hs_selfsigned -cert "$MAT/v1_ed25519_selfsign.pem" -key "$MAT/v1_ed25519_selfsign.key"

# 3. cert whose subject DN == the real root DN, self-signed CA (v6) -> the odd one
run 0011_hs_rootdn_selfca -cert "$MAT/v6_root_as_client.pem" -key "$MAT/v6_root_as_client.key"

# 4. leaf signed by same-DN fake CA, with chain -> confirmed real sig check
run 0012_hs_fakeca_chain -cert "$MAT/v5_leaf.pem" -key "$MAT/v5_leaf.key" -cert_chain "$MAT/v5_leaf_chain.pem"

# 5. no cert, but explicitly ask for TLS1.3 PHA + force empty cert via -no_middlebox
run 0013_hs_nocert_pha -post_handshake_auth

echo "done"

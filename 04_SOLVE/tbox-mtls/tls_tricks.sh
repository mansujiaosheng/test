#!/usr/bin/env bash
# TLS-level trick matrix against the T-BOX mTLS port (read-only).
# Usage: ./tls_tricks.sh <host> [port]
set -u
H="${1:-10.225.139.3}"
P="${2:-8443}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PKI="$ROOT/04_SOLVE/tbox-mtls/pki"
OUT="$ROOT/03_EVIDENCE/tbox-mtls"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

sec() { printf '\n=== %s ===\n' "$*"; }

{
  echo "###### 0109 TLS-level trick matrix against ${H}:${P} ######"
  echo "# utc=$(date -u +%FT%TZ)  openssl=$(openssl version)  bash=$BASH_VERSION"
  echo "# every case: s_client </dev/null, 25s cap, server alert printed verbatim"

  sec "K01 CA-first chain order (fake CA first, leaf second)"
  timeout 25 openssl s_client -connect "$H:$P" -servername tbox \
      -cert "$PKI/chain_samedn_ca_first.pem" -key "$PKI/leaf_samedn.key" -no_ticket \
      </dev/null 2>&1 | head -40

  sec "K02 leaf-first chain order (control)"
  timeout 25 openssl s_client -connect "$H:$P" -servername tbox \
      -cert "$PKI/chain_samedn_leaf_first.pem" -key "$PKI/leaf_samedn.key" -no_ticket \
      </dev/null 2>&1 | head -40

  sec "K03 session ticket attempt: -sess_out with no client cert"
  rm -f "$TMP/s1.pem"
  timeout 25 openssl s_client -connect "$H:$P" -servername tbox -sess_out "$TMP/s1.pem" \
      </dev/null 2>&1 | head -30
  echo "--- sess_out file produced? ---"
  ls -l "$TMP/s1.pem" 2>&1 || echo "NO SESSION FILE (handshake never completed)"

  sec "K04 session resumption attempt: -sess_in (no session available)"
  timeout 25 openssl s_client -connect "$H:$P" -servername tbox -sess_in "$TMP/s1.pem" \
      </dev/null 2>&1 | head -20

  sec "K05 -reconnect (session id reuse path)"
  timeout 25 openssl s_client -connect "$H:$P" -servername tbox -reconnect \
      </dev/null 2>&1 | grep -E "Reused|New, |Session-ID|alert|error" | head -20

  sec "K06 -enable_pha (post-handshake auth) with no client cert"
  timeout 25 openssl s_client -connect "$H:$P" -servername tbox -enable_pha \
      </dev/null 2>&1 | head -25

  sec "K07 0-RTT early data attempt (requires a ticket from a completed handshake)"
  printf 'GET / HTTP/1.1\r\nHost: tbox\r\n\r\n' > "$TMP/ed.bin"
  timeout 25 openssl s_client -connect "$H:$P" -servername tbox \
      -early_data "$TMP/ed.bin" -sess_in "$TMP/s1.pem" </dev/null 2>&1 | head -20

  sec "K08 TLS1.2 with a client cert (downgrade path)"
  timeout 25 openssl s_client -connect "$H:$P" -servername tbox -tls1_2 \
      -cert "$PKI/s01_cn_tbox.pem" -key "$PKI/s01_cn_tbox.key" </dev/null 2>&1 | head -20

  sec "K09 request extra tickets (-num_tickets 4) with no client cert"
  timeout 25 openssl s_client -connect "$H:$P" -servername tbox -num_tickets 4 \
      </dev/null 2>&1 | head -25

  sec "K10 full live leaf + chain (chain length check)"
  timeout 25 openssl s_client -connect "$H:$P" -servername tbox -showcerts -no_ticket \
      </dev/null 2>&1 | sed -n '/Certificate chain/,/^---/p'
} > "$OUT/0109_tls_tricks.txt" 2>&1

echo "[wrote] 03_EVIDENCE/tbox-mtls/0109_tls_tricks.txt"
grep -nE "alert|NO SESSION FILE|sess_out file produced|Certificate chain|s:CN" "$OUT/0109_tls_tricks.txt" | head -30

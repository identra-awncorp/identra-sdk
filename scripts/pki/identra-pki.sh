#!/usr/bin/env bash
# Identra PKI operations with OpenSSL 3.0 or later (ADR-0015 sections 2, 9, 10, 14, 15).
# Step-by-step operating guide: scripts/pki/README.md. Run without arguments for usage.
#
# Every subcommand refuses to overwrite an existing key or certificate. Certificates are issued
# with `openssl ca -startdate/-enddate`: OpenSSL 3.0.x has no -not_before/-not_after on
# `x509`/`req` (those arrived in 3.4). A CA never issues past its own notAfter.
set -euo pipefail
umask 077

OPENSSL=${OPENSSL:-openssl}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

die() { echo "identra-pki: $*" >&2; exit 1; }

usage() {
  cat >&2 <<'EOF'
Usage: identra-pki.sh <command> [--option value ...]

  init-root               --dir <root-ca-dir> --o <organisation> --cn <common name> [--start T]
  init-issuing            --dir <issuing-ca-dir> --root-dir <root-ca-dir> --o <organisation> --cn <common name> [--start T]
  new-key-and-csr         --key <key.pem> --csr <csr.pem> --o <organisation> --mst <tax code> --cn <common name>
  issue-leaf              --ca-dir <issuing-ca-dir> --csr <csr.pem> --purpose vc|vc-product|status|request
                          [--san-uri <issuer URL>] --out <cert.pem> --chain <chain.pem> [--start T]
  issue-trust-list-signer --root-dir <root-ca-dir> --csr <csr.pem> --out <cert.pem> [--start T]

A CA directory holds ca.key.pem, ca.cert.pem and db/ (the OpenSSL issuance database).
--start sets notBefore as YYYYMMDDHHMMSSZ (UTC); default now. Only test PKIs need it.
Lifetimes (ADR-0015 section 14): root 25 y, issuing CA 15 y, vc 3 y, vc-product 11 y,
status / request / trust-list signer 13 months.
EOF
  exit 2
}

ROOT_EXT='basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash'
ISSUING_EXT='basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always'
LEAF_EXT='basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always'

lifetime_months() {
  case $1 in
    root) echo 300 ;; issuing) echo 180 ;; vc) echo 36 ;; vc-product) echo 132 ;;
    status | request | trust-list) echo 13 ;;
    *) die "unknown purpose: $1" ;;
  esac
}

now_utc() { date -u +%Y%m%d%H%M%SZ; }

# add_months YYYYMMDDHHMMSSZ N: same day and time N months later, day clamped to the month's end.
add_months() {
  local t=$1 n=$2
  local y=$((10#${t:0:4})) mo=$((10#${t:4:2})) d=$((10#${t:6:2}))
  local total=$((y * 12 + mo - 1 + n))
  y=$((total / 12)) mo=$((total % 12 + 1))
  local days=(31 28 31 30 31 30 31 31 30 31 30 31)
  local max=${days[mo - 1]}
  if ((mo == 2 && ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0))); then max=29; fi
  ((d > max)) && d=$max
  printf '%04d%02d%02d%s\n' "$y" "$mo" "$d" "${t:8}"
}

check_time() { [[ $1 =~ ^[0-9]{14}Z$ ]] || die "time must be YYYYMMDDHHMMSSZ: $1"; }

# notAfter of a certificate as YYYYMMDDHHMMSS.
not_after() { "$OPENSSL" x509 -in "$1" -noout -enddate -dateopt iso_8601 | tr -dc '0-9'; }

refuse_existing() { for f; do [ ! -e "$f" ] || die "refusing to overwrite existing $f"; done; }

# Values go into an OpenSSL -subj string and config file: forbid characters with meaning there.
check_name() { [[ -n $2 && $2 != *[/\\+=\$]* && $2 != *$'\n'* ]] || die "--$1 must be non-empty and must not contain / \\ + = \$ or newlines"; }

new_key() { # new_key <path> [P-256|P-384|rsa]
  refuse_existing "$1"
  if [ "${2:-P-256}" = rsa ]; then
    "$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" 2>/dev/null
  else
    "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"${2:-P-256}" -pkeyopt ec_param_enc:named_curve -out "$1"
  fi
}

new_csr() { # new_csr <key> <csr> <subject>
  refuse_existing "$2"
  printf '[req]\ndistinguished_name = dn\nstring_mask = utf8only\nutf8 = yes\n[dn]\n' >"$WORK/req.cnf"
  OPENSSL_CONF=/dev/null "$OPENSSL" req -new -config "$WORK/req.cnf" -utf8 -key "$1" -subj "$3" -out "$2"
}

init_db() { mkdir -p "$1/db/certs" && : >"$1/db/index.txt" && "$OPENSSL" rand -hex 16 >"$1/db/serial"; }

# ca_sign <ca-dir> <csr> <out> <start> <end> <extensions> [self]
# Signs with <ca-dir>/ca.key.pem (and ca.cert.pem unless self-signing); records in <ca-dir>/db.
# The subject is taken from the CSR unchanged; CSR extensions are never copied.
ca_sign() {
  local dir=$1 csr=$2 out=$3 start=$4 end=$5 ext=$6 mode=${7:-}
  refuse_existing "$out"
  [[ $dir != *\$* ]] || die "CA directory path must not contain \$"
  cat >"$WORK/ca.cnf" <<EOF
[ca]
default_ca = identra_ca
[identra_ca]
database = $dir/db/index.txt
new_certs_dir = $dir/db/certs
serial = $dir/db/serial
policy = policy_any
unique_subject = no
email_in_dn = no
copy_extensions = none
preserve = yes
# Subject attributes not listed here are dropped; the CSR order is kept (preserve).
[policy_any]
countryName = optional
organizationName = optional
organizationIdentifier = optional
commonName = optional
[ext]
$ext
EOF
  local signer=(-cert "$dir/ca.cert.pem")
  [ "$mode" = self ] && signer=(-selfsign)
  # CA_MD exists only so the test PKI can produce an ecdsa-with-SHA384 certificate.
  "$OPENSSL" ca -batch -notext -config "$WORK/ca.cnf" "${signer[@]}" -keyfile "$dir/ca.key.pem" -md "${CA_MD:-sha256}" \
    -in "$csr" -out "$out" -extensions ext -startdate "$start" -enddate "$end" 2>"$WORK/ca.log" ||
    { cat "$WORK/ca.log" >&2; die "openssl ca failed for $out"; }
}

# make_ca <dir> <subject> <parent-ca-dir|self> <start> <end> <extensions> [curve]
make_ca() {
  local dir=$1 subj=$2 parent=$3 start=$4 end=$5 ext=$6
  mkdir -p "$dir"
  new_key "$dir/ca.key.pem" "${7:-P-256}"
  new_csr "$dir/ca.key.pem" "$WORK/ca.csr.pem" "$subj"
  init_db "$dir"
  if [ "$parent" = self ]; then
    ca_sign "$dir" "$WORK/ca.csr.pem" "$dir/ca.cert.pem" "$start" "$end" "$ext" self
  else
    ca_sign "$parent" "$WORK/ca.csr.pem" "$dir/ca.cert.pem" "$start" "$end" "$ext"
  fi
  rm -f "$WORK/ca.csr.pem"
}

# Refuses a validity end beyond the issuing CA's own notAfter (ADR-0015 section 14).
check_within_ca() {
  local ca_end
  ca_end=$(not_after "$1/ca.cert.pem")
  [[ ! ${2%Z} > $ca_end ]] || die "notAfter ${2%Z} would exceed the CA's own notAfter $ca_end; renew the CA first"
}

# A leaf CSR must be self-signed correctly, hold a P-256 key and carry exactly the subject of
# ADR-0015 section 9: C=VN, O, organizationIdentifier=VATVN-<tax code>, CN (in this order).
check_leaf_csr() {
  "$OPENSSL" req -in "$1" -noout -verify 2>/dev/null || die "CSR signature does not verify: $1"
  "$OPENSSL" req -in "$1" -noout -pubkey | "$OPENSSL" pkey -pubin -noout -text | grep -q '^NIST CURVE: P-256$' ||
    die "CSR key is not EC P-256: $1"
  local subject nl=$'\n'
  subject=$("$OPENSSL" req -in "$1" -noout -subject -nameopt multiline,utf8,-esc_msb | tail -n +2 | sed -E 's/^ +//; s/ += /=/')
  local re="^countryName=VN${nl}organizationName=[^${nl}]+${nl}organizationIdentifier=VATVN-[0-9]{10}(-[0-9]{3})?${nl}commonName=[^${nl}]+$"
  [[ $subject =~ $re ]] || die "CSR subject must be exactly C=VN, O, organizationIdentifier=VATVN-<tax code>, CN; got:${nl}$subject"
}

print_fingerprint() {
  local hex b64
  hex=$("$OPENSSL" x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2)
  b64=$("$OPENSSL" x509 -in "$1" -outform DER | "$OPENSSL" dgst -sha256 -binary | "$OPENSSL" base64 -A | tr '+/' '-_' | tr -d '=')
  echo "$1"
  echo "  subject:             $("$OPENSSL" x509 -in "$1" -noout -subject -nameopt RFC2253,utf8,-esc_msb | cut -d= -f2-)"
  echo "  notAfter:            $("$OPENSSL" x509 -in "$1" -noout -enddate | cut -d= -f2)"
  echo "  SHA-256 (hex):       $hex"
  echo "  SHA-256 (base64url): $b64"
}

# parse_args "<allowed options>" "$@": sets ARG_<name> for each --name value pair.
parse_args() {
  local allowed=" $1 " key
  shift
  unset "${!ARG_@}"
  while [ $# -gt 0 ]; do
    key=${1#--}
    [[ $1 == --* && $allowed == *" $key "* ]] || die "unexpected argument: $1"
    [ $# -ge 2 ] || die "missing value for $1"
    printf -v "ARG_${key//-/_}" '%s' "$2"
    shift 2
  done
}
need() { local v; for k; do v="ARG_${k//-/_}"; [ -n "${!v:-}" ] || die "missing --$k"; done; }
start_time() { local s=${ARG_start:-$(now_utc)}; check_time "$s"; echo "$s"; }

cmd_init_root() {
  parse_args "dir o cn start" "$@" && need dir o cn
  check_name o "$ARG_o" && check_name cn "$ARG_cn"
  local start end
  start=$(start_time) && end=$(add_months "$start" "$(lifetime_months root)")
  make_ca "$ARG_dir" "/C=VN/O=$ARG_o/CN=$ARG_cn" self "$start" "$end" "$ROOT_EXT"
  print_fingerprint "$ARG_dir/ca.cert.pem"
}

cmd_init_issuing() {
  parse_args "dir root-dir o cn start" "$@" && need dir root-dir o cn
  check_name o "$ARG_o" && check_name cn "$ARG_cn"
  local start end
  start=$(start_time) && end=$(add_months "$start" "$(lifetime_months issuing)")
  check_within_ca "$ARG_root_dir" "$end"
  make_ca "$ARG_dir" "/C=VN/O=$ARG_o/CN=$ARG_cn" "$ARG_root_dir" "$start" "$end" "$ISSUING_EXT"
  print_fingerprint "$ARG_dir/ca.cert.pem"
}

cmd_new_key_and_csr() {
  parse_args "key csr o mst cn" "$@" && need key csr o mst cn
  check_name o "$ARG_o" && check_name cn "$ARG_cn"
  [[ $ARG_mst =~ ^[0-9]{10}(-[0-9]{3})?$ ]] || die "--mst must be a tax code of 10 digits, optionally -NNN"
  refuse_existing "$ARG_key" "$ARG_csr"
  new_key "$ARG_key"
  new_csr "$ARG_key" "$ARG_csr" "/C=VN/O=$ARG_o/organizationIdentifier=VATVN-$ARG_mst/CN=$ARG_cn"
  echo "$ARG_csr: send this CSR to the Identra administrator; keep $ARG_key private."
}

cmd_issue_leaf() {
  parse_args "ca-dir csr purpose san-uri out chain start" "$@" && need ca-dir csr purpose out chain
  local ext=$LEAF_EXT start end
  case $ARG_purpose in
    vc | vc-product)
      [[ ${ARG_san_uri:-} =~ ^https://[^,[:space:]]+$ ]] || die "--san-uri (the issuer URL, https://...) is required for $ARG_purpose"
      ext+=$'\n'"subjectAltName = URI:$ARG_san_uri" ;;
    status | request) [ -z "${ARG_san_uri:-}" ] || die "--san-uri only applies to vc and vc-product" ;;
    *) die "--purpose must be vc, vc-product, status or request" ;;
  esac
  refuse_existing "$ARG_out" "$ARG_chain"
  check_leaf_csr "$ARG_csr"
  start=$(start_time) && end=$(add_months "$start" "$(lifetime_months "$ARG_purpose")")
  check_within_ca "$ARG_ca_dir" "$end"
  ca_sign "$ARG_ca_dir" "$ARG_csr" "$ARG_out" "$start" "$end" "$ext"
  "$OPENSSL" verify -x509_strict -no_check_time -partial_chain -CAfile "$ARG_ca_dir/ca.cert.pem" "$ARG_out" >/dev/null
  cat "$ARG_out" "$ARG_ca_dir/ca.cert.pem" >"$ARG_chain"
  print_fingerprint "$ARG_out"
}

cmd_issue_trust_list_signer() {
  parse_args "root-dir csr out start" "$@" && need root-dir csr out
  local start end
  check_leaf_csr "$ARG_csr"
  start=$(start_time) && end=$(add_months "$start" "$(lifetime_months trust-list)")
  check_within_ca "$ARG_root_dir" "$end"
  ca_sign "$ARG_root_dir" "$ARG_csr" "$ARG_out" "$start" "$end" "$LEAF_EXT"
  "$OPENSSL" verify -x509_strict -no_check_time -CAfile "$ARG_root_dir/ca.cert.pem" "$ARG_out" >/dev/null
  print_fingerprint "$ARG_out"
}

main() {
  [ $# -ge 1 ] || usage
  local cmd=$1
  shift
  case $cmd in
    init-root) cmd_init_root "$@" ;;
    init-issuing) cmd_init_issuing "$@" ;;
    new-key-and-csr) cmd_new_key_and_csr "$@" ;;
    issue-leaf) cmd_issue_leaf "$@" ;;
    issue-trust-list-signer) cmd_issue_trust_list_signer "$@" ;;
    *) usage ;;
  esac
}

# Sourcing this file (make-test-pki.sh does) only defines the functions.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi

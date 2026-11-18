#!/usr/bin/env bash
# Identra PKI operations with OpenSSL 3.0 or later (ADR-0015 sections 2, 9, 10, 14, 15).
# Step-by-step ceremony: scripts/pki/README.md. Run without arguments for usage.
#
# Every argument is validated before anything is created; no key or certificate is ever
# overwritten; a run that fails removes what it created (never anything that pre-existed);
# every issued certificate is read back and compared with the request; a CA never issues past
# its own notAfter.
set -euo pipefail
umask 077
# shellcheck source=pki-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pki-lib.sh"

usage() {
  cat >&2 <<'EOF'
Usage: identra-pki.sh <command> [--option value ...]

Root machine (offline):
  init-root               --dir <root-ca-dir> --o <organisation> --cn <common name> [--start T]
  sign-issuing-csr        --root-dir <root-ca-dir> --csr <issuing.csr.pem> --out <issuing.cert.pem> [--start T]
  issue-trust-list-signer --root-dir <root-ca-dir> --csr <csr.pem> --out <cert.pem> [--start T]
  export-root-der         --in <root.cert.pem> --out <root.cert.der>
Issuing-CA machine (offline):
  new-issuing-key-and-csr --dir <issuing-ca-dir> --o <organisation> --cn <common name>
  issue-leaf              --ca-dir <issuing-ca-dir> --csr <csr.pem> --purpose vc|vc-product|status|request
                          [--san-uri <issuer URL>] --out <cert.pem> --chain <chain.pem> [--start T]
Organisation / VPS:
  new-key-and-csr         --key <key.pem> --csr <csr.pem> --o <organisation> --mst <tax code> --cn <common name>
Anywhere:
  show                    --cert <cert.pem>
Demo and test PKIs only (Root and Issuing CA on one machine):
  init-issuing            --dir <issuing-ca-dir> --root-dir <root-ca-dir> --o <organisation> --cn <common name> [--start T]

A CA directory holds ca.key.pem, ca.cert.pem and db/ (the OpenSSL issuance database).
--start sets notBefore as YYYYMMDDHHMMSSZ (UTC); default now. Only test PKIs need it.
Lifetimes (ADR-0015 section 14): root 25 y, issuing CA 15 y, vc 3 y, vc-product 11 y,
status / request / trust-list signer 13 months.
EOF
  exit 2
}

# parse_args "<allowed options>" "$@": sets ARG_<name> for each --name value pair. Refuses
# unknown, repeated and empty options; validates every path argument.
parse_args() {
  local allowed=" $1 " key var
  shift
  unset "${!ARG_@}"
  while [ $# -gt 0 ]; do
    key=${1#--}
    var="ARG_${key//-/_}"
    [[ $1 == --* && $allowed == *" $key "* ]] || die "unexpected argument: $1"
    [ $# -ge 2 ] && [ -n "$2" ] || die "missing value for $1"
    [ -z "${!var+x}" ] || die "$1 given twice"
    printf -v "$var" '%s' "$2"
    shift 2
  done
  for key in dir root-dir ca-dir key csr out chain cert in; do
    var="ARG_${key//-/_}"
    [ -z "${!var+x}" ] || check_path "${!var}"
  done
  [ -z "${ARG_start+x}" ] || check_time "$ARG_start"
}
need() { local v k; for k; do v="ARG_${k//-/_}"; [ -n "${!v+x}" ] || die "missing --$k"; done; }
start_time() { echo "${ARG_start:-$(now_utc)}"; }

# Subject lines as subject_of prints them.
ca_subject_lines() { printf 'countryName=VN\norganizationName=%s\ncommonName=%s' "$1" "$2"; }
leaf_subject_lines() { printf 'countryName=VN\norganizationName=%s\norganizationIdentifier=VATVN-%s\ncommonName=%s' "$1" "$2" "$3"; }

# A CSR must be self-signed correctly, hold a P-256 key and carry exactly the expected subject shape.
check_csr() { # check_csr <csr> leaf|ca
  "$OPENSSL" req -in "$1" -noout -verify 2>/dev/null || die "CSR signature does not verify: $1"
  "$OPENSSL" req -in "$1" -noout -pubkey | "$OPENSSL" pkey -pubin -noout -text | grep -q '^NIST CURVE: P-256$' ||
    die "CSR key is not EC P-256: $1"
  local subject nl=$'\n' re
  subject=$(subject_of req "$1")
  if [ "$2" = leaf ]; then
    re="^countryName=VN${nl}organizationName=[^${nl}]+${nl}organizationIdentifier=VATVN-[0-9]{10}(-[0-9]{3})?${nl}commonName=[^${nl}]+$"
    [[ $subject =~ $re ]] || die "CSR subject must be exactly C=VN, O, organizationIdentifier=VATVN-<tax code>, CN; got:${nl}$subject"
  else
    re="^countryName=VN${nl}organizationName=[^${nl}]+${nl}commonName=[^${nl}]+$"
    [[ $subject =~ $re ]] || die "issuing CA CSR subject must be exactly C=VN, O, CN; got:${nl}$subject"
  fi
}

# issue <ca-dir> <csr> <out> <purpose> <extensions> <san or empty>: sign, then read back and compare.
issue() {
  local dir=$1 csr=$2 out=$3 purpose=$4 ext=$5 san=$6 start end
  start=$(start_time)
  end=$(add_months "$start" "$(lifetime_months "$purpose")")
  check_within_ca "$dir" "$end"
  ca_sign "$dir" "$csr" "$out" "$start" "$end" "$ext"
  expect_subject x509 "$out" "$(subject_of req "$csr")"
  expect_sans "$out" "$san"
  "$OPENSSL" verify -x509_strict -no_check_time -partial_chain -CAfile "$dir/ca.cert.pem" "$out" >/dev/null
}

cmd_init_root() {
  parse_args "dir o cn start" "$@" && need dir o cn
  check_name o "$ARG_o" && check_name cn "$ARG_cn"
  refuse_existing "$ARG_dir/ca.key.pem" "$ARG_dir/ca.cert.pem"
  local start end
  start=$(start_time)
  end=$(add_months "$start" "$(lifetime_months root)")
  make_ca "$ARG_dir" "/C=VN/O=$ARG_o/CN=$ARG_cn" self "$start" "$end" "$ROOT_EXT"
  expect_subject x509 "$ARG_dir/ca.cert.pem" "$(ca_subject_lines "$ARG_o" "$ARG_cn")"
  show "$ARG_dir/ca.cert.pem"
}

cmd_new_issuing_key_and_csr() {
  parse_args "dir o cn" "$@" && need dir o cn
  check_name o "$ARG_o" && check_name cn "$ARG_cn"
  refuse_existing "$ARG_dir/ca.key.pem" "$ARG_dir/ca.csr.pem" "$ARG_dir/db"
  make_dir "$ARG_dir"
  new_key "$ARG_dir/ca.key.pem"
  new_csr "$ARG_dir/ca.key.pem" "$ARG_dir/ca.csr.pem" "/C=VN/O=$ARG_o/CN=$ARG_cn"
  expect_subject req "$ARG_dir/ca.csr.pem" "$(ca_subject_lines "$ARG_o" "$ARG_cn")"
  created "$ARG_dir/db"
  init_db "$ARG_dir"
  echo "$ARG_dir/ca.csr.pem: take it to the Root machine; SHA-256 $("$OPENSSL" dgst -sha256 -r "$ARG_dir/ca.csr.pem" | cut -c1-64)"
}

cmd_sign_issuing_csr() {
  parse_args "root-dir csr out start" "$@" && need root-dir csr out
  need_ca_dir "$ARG_root_dir" && need_file "$ARG_csr"
  refuse_existing "$ARG_out"
  check_csr "$ARG_csr" ca
  issue "$ARG_root_dir" "$ARG_csr" "$ARG_out" issuing "$ISSUING_EXT" ""
  show "$ARG_out"
}

cmd_init_issuing() {
  parse_args "dir root-dir o cn start" "$@" && need dir root-dir o cn
  check_name o "$ARG_o" && check_name cn "$ARG_cn"
  need_ca_dir "$ARG_root_dir"
  refuse_existing "$ARG_dir/ca.key.pem" "$ARG_dir/ca.cert.pem"
  # The subcommands below parse their own arguments, so ours are copied first.
  local dir=$ARG_dir root=$ARG_root_dir o=$ARG_o cn=$ARG_cn start=${ARG_start:-}
  cmd_new_issuing_key_and_csr --dir "$dir" --o "$o" --cn "$cn" >/dev/null
  cmd_sign_issuing_csr --root-dir "$root" --csr "$dir/ca.csr.pem" --out "$dir/ca.cert.pem" ${start:+--start "$start"}
}

cmd_new_key_and_csr() {
  parse_args "key csr o mst cn" "$@" && need key csr o mst cn
  check_name o "$ARG_o" && check_name cn "$ARG_cn" && check_mst "$ARG_mst"
  refuse_existing "$ARG_key" "$ARG_csr"
  make_dir "$(dirname -- "$ARG_key")" && make_dir "$(dirname -- "$ARG_csr")"
  new_key "$ARG_key"
  new_csr "$ARG_key" "$ARG_csr" "/C=VN/O=$ARG_o/organizationIdentifier=VATVN-$ARG_mst/CN=$ARG_cn"
  expect_subject req "$ARG_csr" "$(leaf_subject_lines "$ARG_o" "$ARG_mst" "$ARG_cn")"
  echo "$ARG_csr: send this CSR to the Identra administrator; keep $ARG_key private."
}

cmd_issue_leaf() {
  parse_args "ca-dir csr purpose san-uri out chain start" "$@" && need ca-dir csr purpose out chain
  local ext=$LEAF_EXT san=${ARG_san_uri:-}
  case $ARG_purpose in
    vc | vc-product)
      [ -n "$san" ] || die "--san-uri (the issuer URL) is required for $ARG_purpose"
      check_uri san-uri "$san"
      ext+=$'\n'"subjectAltName = URI:$san" ;;
    status | request) [ -z "$san" ] || die "--san-uri only applies to vc and vc-product" ;;
    *) die "--purpose must be vc, vc-product, status or request" ;;
  esac
  need_ca_dir "$ARG_ca_dir" && need_file "$ARG_csr"
  refuse_existing "$ARG_out" "$ARG_chain"
  check_csr "$ARG_csr" leaf
  issue "$ARG_ca_dir" "$ARG_csr" "$ARG_out" "$ARG_purpose" "$ext" "$san"
  created "$ARG_chain"
  cat "$ARG_out" "$ARG_ca_dir/ca.cert.pem" >"$ARG_chain"
  show "$ARG_out"
}

cmd_issue_trust_list_signer() {
  parse_args "root-dir csr out start" "$@" && need root-dir csr out
  need_ca_dir "$ARG_root_dir" && need_file "$ARG_csr"
  refuse_existing "$ARG_out"
  check_csr "$ARG_csr" leaf
  issue "$ARG_root_dir" "$ARG_csr" "$ARG_out" trust-list "$LEAF_EXT" ""
  show "$ARG_out"
}

cmd_show() {
  parse_args "cert" "$@" && need cert
  need_file "$ARG_cert"
  show "$ARG_cert"
}

cmd_export_root_der() {
  parse_args "in out" "$@" && need in out
  need_file "$ARG_in"
  refuse_existing "$ARG_out"
  created "$ARG_out"
  "$OPENSSL" x509 -in "$ARG_in" -outform DER -out "$ARG_out"
  echo "$ARG_out: SHA-256 $("$OPENSSL" dgst -sha256 -r "$ARG_out" | cut -c1-64)"
}

main() {
  [ $# -ge 1 ] || usage
  local cmd=$1
  shift
  init_run
  case $cmd in
    init-root) cmd_init_root "$@" ;;
    new-issuing-key-and-csr) cmd_new_issuing_key_and_csr "$@" ;;
    sign-issuing-csr) cmd_sign_issuing_csr "$@" ;;
    init-issuing) cmd_init_issuing "$@" ;;
    new-key-and-csr) cmd_new_key_and_csr "$@" ;;
    issue-leaf) cmd_issue_leaf "$@" ;;
    issue-trust-list-signer) cmd_issue_trust_list_signer "$@" ;;
    show) cmd_show "$@" ;;
    export-root-der) cmd_export_root_der "$@" ;;
    *) usage ;;
  esac
}

main "$@"

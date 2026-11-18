# shellcheck shell=bash
# Internals of identra-pki.sh (sourced; also used by make-test-pki.sh). OpenSSL 3.0 or later.
# Nothing here checks the ADR-0015 profiles of its inputs: identra-pki.sh does that.
#
# Certificates are issued with `openssl ca -startdate/-enddate`: OpenSSL 3.0.x has no
# -not_before/-not_after on `x509`/`req` (those arrived in 3.4).

OPENSSL=${OPENSSL:-openssl}

die() { echo "identra-pki: $*" >&2; exit 1; }

# --- run bookkeeping: everything a run creates is removed again when the run fails -----------
init_run() {
  umask 077
  WORK=$(mktemp -d)
  CREATED=()
  trap finish_run EXIT
}
finish_run() {
  local status=$? i
  if [ "$status" -ne 0 ]; then
    for ((i = ${#CREATED[@]} - 1; i >= 0; i--)); do rm -rf -- "${CREATED[i]}"; done
    [ ${#CREATED[@]} -eq 0 ] || echo "identra-pki: failed; removed what this run created" >&2
  fi
  rm -rf -- "$WORK"
}
# created <path>: <path> did not exist before and belongs to this run.
created() { CREATED+=("$1"); }
refuse_existing() { local f; for f; do [ ! -e "$f" ] || die "refusing to overwrite existing $f"; done; }
make_dir() { [ -d "$1" ] && return 0; local parent; parent=$(dirname -- "$1"); make_dir "$parent"; mkdir -- "$1"; created "$1"; }

# --- profiles (ADR-0015 section 15) and lifetimes (section 14) --------------------------------
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

# --- argument checks: no value may carry OpenSSL config or -subj metacharacters --------------
# https://<host>[:port][/path-and-query]; no userinfo, no fragment, no "'" (the OpenSSL config
# parser silently drops it), no "," (SAN list separator), no "#" (config comment), no "$" (config
# variable), no '"' or "\" (config quoting). The issued SAN is read back and compared anyway.
URI_RE='^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(/[A-Za-z0-9._~:/?@!&()*+;%=-]*)?$'
check_uri() { [[ $2 =~ $URI_RE ]] || die "--$1 must be https://<host>[:port][/path] using only [A-Za-z0-9._~:/?@!&()*+;%=-]"; }
check_name() {
  [[ -n $2 && $2 != *[/\\+=\$\#\"\`]* && $2 != *[[:cntrl:]]* && $2 != [[:space:]]* && $2 != *[[:space:]] ]] ||
    die "--$1 must be non-empty, without leading/trailing spaces, control characters or / \\ + = \$ # \" \`"
}
check_mst() { [[ $1 =~ ^[0-9]{10}(-[0-9]{3})?$ ]] || die "--mst must be a tax code of 10 digits, optionally -NNN"; }
check_time() { [[ $1 =~ ^[0-9]{14}Z$ ]] || die "--start must be YYYYMMDDHHMMSSZ (UTC), got: $1"; }
check_path() { [[ -n $1 && $1 != *\$* && $1 != *[[:cntrl:]]* ]] || die "path must be non-empty and contain no \$ or control characters: $1"; }
need_file() { [ -f "$1" ] || die "no such file: $1"; }
need_ca_dir() { need_file "$1/ca.key.pem"; need_file "$1/ca.cert.pem"; [ -d "$1/db" ] || die "$1 is not a CA directory (no db/)"; }

# --- dates -------------------------------------------------------------------------------------
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
# notAfter of a certificate as YYYYMMDDHHMMSS.
not_after() { "$OPENSSL" x509 -in "$1" -noout -enddate -dateopt iso_8601 | tr -dc '0-9'; }
# A CA never issues past its own notAfter (ADR-0015 section 14).
check_within_ca() {
  local ca_end
  ca_end=$(not_after "$1/ca.cert.pem")
  [[ ! ${2%Z} > $ca_end ]] || die "notAfter ${2%Z} would exceed the CA's own notAfter $ca_end; renew the CA first"
}

# --- keys, CSRs, signing -----------------------------------------------------------------------
new_key() { # new_key <path> [P-256|P-384|rsa]
  refuse_existing "$1"
  created "$1"
  if [ "${2:-P-256}" = rsa ]; then
    "$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" 2>/dev/null
  else
    "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"${2:-P-256}" -pkeyopt ec_param_enc:named_curve -out "$1"
  fi
}
new_csr() { # new_csr <key> <csr> <subject>
  refuse_existing "$2"
  created "$2"
  printf '[req]\ndistinguished_name = dn\nstring_mask = utf8only\nutf8 = yes\n[dn]\n' >"$WORK/req.cnf"
  OPENSSL_CONF=/dev/null "$OPENSSL" req -new -config "$WORK/req.cnf" -utf8 -key "$1" -subj "$3" -out "$2"
}
init_db() { mkdir -p "$1/db/certs" && : >"$1/db/index.txt"; }

# ca_sign <ca-dir> <csr> <out> <start> <end> <extensions> [self]
# Signs with <ca-dir>/ca.key.pem (and ca.cert.pem unless self-signing) under a fresh random
# serial; records in <ca-dir>/db. The subject is taken from the CSR unchanged; CSR extensions
# are never copied.
ca_sign() {
  local dir=$1 csr=$2 out=$3 start=$4 end=$5 ext=$6 mode=${7:-} serial
  refuse_existing "$out"
  check_path "$dir"
  # A fresh random serial for every signature (124 random bits; the fixed first nibble keeps it
  # positive and makes OpenSSL's db/certs/<SERIAL>.pem file name predictable).
  serial="1$("$OPENSSL" rand -hex 16 | cut -c2-)"
  echo "$serial" >"$dir/db/serial"
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
  created "$out"
  created "$dir/db/certs/${serial^^}.pem"
  # CA_MD exists only so the test PKI can produce an ecdsa-with-SHA384 certificate.
  "$OPENSSL" ca -batch -notext -config "$WORK/ca.cnf" "${signer[@]}" -keyfile "$dir/ca.key.pem" -md "${CA_MD:-sha256}" \
    -in "$csr" -out "$out" -extensions ext -startdate "$start" -enddate "$end" 2>"$WORK/ca.log" ||
    { cat "$WORK/ca.log" >&2; die "openssl ca failed for $out"; }
}

# make_ca <dir> <subject> <parent-ca-dir|self> <start> <end> <extensions> [curve]: key, CSR, db, certificate.
make_ca() {
  local dir=$1 subj=$2 parent=$3 start=$4 end=$5 ext=$6
  make_dir "$dir"
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

# --- reading back what OpenSSL wrote -----------------------------------------------------------
# subject_of <req|x509> <file>: one "attribute=value" line per RDN, in order.
subject_of() {
  "$OPENSSL" "$1" -in "$2" -noout -subject -nameopt multiline,utf8,-esc_msb | tail -n +2 | sed -E 's/^ +//; s/ += /=/'
}
# san_uris_of <cert>: the SAN URIs, one per line (nothing when there is no SAN).
san_uris_of() {
  "$OPENSSL" x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr ',' '\n' | sed -nE 's/^ *URI://p'
}
expect_subject() { # expect_subject <req|x509> <file> <expected lines>
  local got
  got=$(subject_of "$1" "$2")
  [ "$got" = "$3" ] || die "subject of $2 differs from the request:"$'\n'"expected:"$'\n'"$3"$'\n'"got:"$'\n'"$got"
}
expect_sans() { # expect_sans <cert> <expected URI or empty>
  local got
  got=$(san_uris_of "$1")
  [ "$got" = "$2" ] || die "SAN of $1 differs from the request: expected '${2:-none}', got '${got:-none}'"
}

# show <cert>: what an operator compares with the request before handing a certificate over.
show() {
  local b64
  b64=$("$OPENSSL" x509 -in "$1" -outform DER | "$OPENSSL" dgst -sha256 -binary | "$OPENSSL" base64 -A | tr '+/' '-_' | tr -d '=')
  echo "$1"
  echo "  subject:             $("$OPENSSL" x509 -in "$1" -noout -subject -nameopt RFC2253,utf8,-esc_msb | cut -d= -f2-)"
  echo "  issuer:              $("$OPENSSL" x509 -in "$1" -noout -issuer -nameopt RFC2253,utf8,-esc_msb | cut -d= -f2-)"
  echo "  SAN URI:             $(san_uris_of "$1" | paste -sd' ' -)"
  echo "  notBefore:           $("$OPENSSL" x509 -in "$1" -noout -startdate | cut -d= -f2)"
  echo "  notAfter:            $("$OPENSSL" x509 -in "$1" -noout -enddate | cut -d= -f2)"
  echo "  basicConstraints:    $("$OPENSSL" x509 -in "$1" -noout -ext basicConstraints 2>/dev/null | tail -n +2 | sed 's/^ *//' | paste -sd' ' -)"
  echo "  keyUsage:            $("$OPENSSL" x509 -in "$1" -noout -ext keyUsage 2>/dev/null | tail -n +2 | sed 's/^ *//' | paste -sd' ' -)"
  echo "  serial:              $("$OPENSSL" x509 -in "$1" -noout -serial | cut -d= -f2)"
  echo "  SHA-256 (hex):       $("$OPENSSL" x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2)"
  echo "  SHA-256 (base64url): $b64"
}

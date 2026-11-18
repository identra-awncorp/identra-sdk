#!/usr/bin/env bash
# Generates the TEST PKI used by the sdk-core tests, including negative material.
# Usage: make-test-pki.sh <outdir>
#
# All dates are fixed so the tests are deterministic: CAs start 2025-01-01, leaves 2026-01-01,
# and the tests validate at 2026-06-01T00:00:00Z unless they say otherwise.
# Good material goes through the identra-pki.sh subcommands; negative material, which those
# subcommands refuse to produce, goes through its internal functions (sourced below).
# Layout: <outdir>/ca/<name>/ca.{key,cert}.pem and <outdir>/leaf/<name>.{key,cert}.pem
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PKI="$HERE/identra-pki.sh"
# shellcheck source=identra-pki.sh
. "$PKI"

OUT=${1:?usage: make-test-pki.sh <outdir>}
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT")" ]; then die "$OUT exists and is not empty"; fi
CA="$OUT/ca"
LEAF="$OUT/leaf"
mkdir -p "$CA" "$LEAF"

CA_START=20250101000000Z
CA_END=20400101000000Z
LEAF_START=20260101000000Z
LEAF_END=20290101000000Z
ISS=https://api-identra.awncorp.vn/issuers
VC_SUBJ="/C=VN/O=Truong Mau TEST/organizationIdentifier=VATVN-0100000001/CN=Truong Mau TEST (vc)"
ROOT_SUBJ="/C=VN/O=Identra TEST/CN=Identra TEST Root CA"
ISSUING_SUBJ="/C=VN/O=Identra TEST/CN=Identra TEST Issuing CA 1"
VC_EXT="$LEAF_EXT"$'\n'"subjectAltName = URI:$ISS/truong-mau"

# leaf <name> <ca-name> <subject> <extensions> [start] [end] [key type]
leaf() {
  new_key "$LEAF/$1.key.pem" "${7:-P-256}"
  new_csr "$LEAF/$1.key.pem" "$WORK/$1.csr.pem" "$3"
  ca_sign "$CA/$2" "$WORK/$1.csr.pem" "$LEAF/$1.cert.pem" "${5:-$LEAF_START}" "${6:-$LEAF_END}" "$4"
}
# good <name> <O> <tax code> <purpose> [san]: a leaf made by the operational subcommands.
good() {
  local san=()
  [ -z "${5:-}" ] || san=(--san-uri "$5")
  "$PKI" new-key-and-csr --key "$LEAF/$1.key.pem" --csr "$WORK/$1.csr.pem" --o "$2" --mst "$3" --cn "$2 ($4)" >/dev/null
  "$PKI" issue-leaf --ca-dir "$CA/issuing" --csr "$WORK/$1.csr.pem" --purpose "$4" "${san[@]}" \
    --out "$LEAF/$1.cert.pem" --chain "$LEAF/$1.chain.pem" --start "$LEAF_START" >/dev/null
}

# --- the real test chain (root notAfter 2050-01-01 is a GeneralizedTime) -------------------
"$PKI" init-root --dir "$CA/root" --o "Identra TEST" --cn "Identra TEST Root CA" --start "$CA_START" >/dev/null
"$PKI" init-issuing --dir "$CA/issuing" --root-dir "$CA/root" --o "Identra TEST" --cn "Identra TEST Issuing CA 1" --start "$CA_START" >/dev/null
good vc "Truong Mau TEST" 0100000001 vc "$ISS/truong-mau"
good vc-product "Nha San Xuat TEST" 0100000002 vc-product "$ISS/nha-san-xuat"
good status "Truong Mau TEST" 0100000001 status
good request "Nha Tuyen Dung Mau TEST" 0100000005 request
good utf8 "Trường Mẫu TEST" 0100000001 vc "$ISS/truong-mau"
"$PKI" new-key-and-csr --key "$LEAF/trust-list.key.pem" --csr "$WORK/trust-list.csr.pem" \
  --o "Identra TEST" --mst 0100000000 --cn "Identra TEST Trust List Signer" >/dev/null
"$PKI" issue-trust-list-signer --root-dir "$CA/root" --csr "$WORK/trust-list.csr.pem" --out "$LEAF/trust-list.cert.pem" --start "$LEAF_START" >/dev/null

# --- negative leaves under the real issuing CA ---------------------------------------------
leaf expired issuing "$VC_SUBJ" "$VC_EXT" "$LEAF_START" 20260301000000Z
leaf not-yet-valid issuing "$VC_SUBJ" "$VC_EXT" 20261201000000Z 20271201000000Z
leaf rsa issuing "$VC_SUBJ" "$VC_EXT" "" "" rsa
leaf p384 issuing "$VC_SUBJ" "$VC_EXT" "" "" P-384
leaf ca-true issuing "$VC_SUBJ" "${VC_EXT/CA:FALSE/CA:TRUE}"
leaf no-basic-constraints issuing "$VC_SUBJ" "${VC_EXT/basicConstraints = critical,CA:FALSE/}"
leaf no-digital-signature issuing "$VC_SUBJ" "${VC_EXT/digitalSignature/nonRepudiation}"
leaf no-org-id issuing "/C=VN/O=Truong Mau TEST/CN=Truong Mau TEST (vc)" "$VC_EXT"
leaf no-o issuing "/C=VN/organizationIdentifier=VATVN-0100000001/CN=Truong Mau TEST (vc)" "$VC_EXT"
leaf no-c issuing "/O=Truong Mau TEST/organizationIdentifier=VATVN-0100000001/CN=Truong Mau TEST (vc)" "$VC_EXT"
leaf wrong-san issuing "$VC_SUBJ" "$LEAF_EXT"$'\n'"subjectAltName = URI:https://evil.example/issuers/truong-mau"
leaf critical-ext issuing "$VC_SUBJ" "$VC_EXT"$'\n'"1.3.6.1.4.1.55555.1 = critical,ASN1:NULL"
leaf big issuing "$VC_SUBJ" "$VC_EXT"$'\n'"1.3.6.1.4.1.55555.2 = ASN1:UTF8String:$(printf 'A%.0s' {1..4200})"
CA_MD=sha384 leaf sha384 issuing "$VC_SUBJ" "$VC_EXT"

# --- impostor PKI: other keys, byte-identical names ----------------------------------------
make_ca "$CA/evil-root" "$ROOT_SUBJ" self "$CA_START" 20500101000000Z "$ROOT_EXT"
make_ca "$CA/evil-issuing" "$ISSUING_SUBJ" "$CA/evil-root" "$CA_START" "$CA_END" "$ISSUING_EXT"
leaf evil-vc evil-issuing "$VC_SUBJ" "$VC_EXT"

# --- bad issuing CAs under the real root, each with a leaf ---------------------------------
make_ca "$CA/issuing-no-pathlen" "/C=VN/O=Identra TEST/CN=Issuing no pathlen" "$CA/root" "$CA_START" "$CA_END" "${ISSUING_EXT/,pathlen:0/}"
make_ca "$CA/issuing-ca-false" "/C=VN/O=Identra TEST/CN=Issuing CA FALSE" "$CA/root" "$CA_START" "$CA_END" "${ISSUING_EXT/CA:TRUE,pathlen:0/CA:FALSE}"
make_ca "$CA/issuing-no-key-cert-sign" "/C=VN/O=Identra TEST/CN=Issuing no keyCertSign" "$CA/root" "$CA_START" "$CA_END" "${ISSUING_EXT/keyCertSign,cRLSign/digitalSignature}"
make_ca "$CA/issuing-p384" "/C=VN/O=Identra TEST/CN=Issuing P-384" "$CA/root" "$CA_START" "$CA_END" "$ISSUING_EXT" P-384
make_ca "$CA/issuing-expired" "/C=VN/O=Identra TEST/CN=Issuing expired" "$CA/root" "$CA_START" 20260301000000Z "$ISSUING_EXT"
for c in issuing-no-pathlen issuing-ca-false issuing-no-key-cert-sign issuing-p384 issuing-expired; do
  leaf "under-$c" "$c" "$VC_SUBJ" "$VC_EXT"
done

# --- bad roots, each with an issuing CA and a leaf -----------------------------------------
make_ca "$CA/root-expired" "/C=VN/O=Identra TEST/CN=Root expired" self "$CA_START" 20260301000000Z "$ROOT_EXT"
make_ca "$CA/root-no-key-cert-sign" "/C=VN/O=Identra TEST/CN=Root no keyCertSign" self "$CA_START" 20500101000000Z "${ROOT_EXT/keyCertSign,cRLSign/cRLSign}"
make_ca "$CA/root-ca-false" "/C=VN/O=Identra TEST/CN=Root CA FALSE" self "$CA_START" 20500101000000Z "${ROOT_EXT/CA:TRUE/CA:FALSE}"
make_ca "$CA/root2" "/C=VN/O=Identra TEST/CN=Identra TEST Root CA 2" self "$CA_START" 20500101000000Z "$ROOT_EXT"
for r in root-expired root-no-key-cert-sign root-ca-false root2; do
  make_ca "$CA/issuing-under-$r" "/C=VN/O=Identra TEST/CN=Issuing under $r" "$CA/$r" "$CA_START" "$CA_END" "$ISSUING_EXT"
  leaf "under-$r" "issuing-under-$r" "$VC_SUBJ" "$VC_EXT"
done

# --- leaves signed directly by the root: valid only for profile trust-list ------------------
leaf trust-list-no-org-id root "/C=VN/O=Identra TEST/CN=Identra TEST Trust List Signer" "$LEAF_EXT"

echo "TEST PKI written to $OUT"

#!/usr/bin/env bash
# Generates the DEMO PKI of ADR-0015 section 10 with identra-pki.sh. DEMO material only: every
# name says DEMO and the tax codes are fake. The real Root is made offline (see README.md).
#
# Usage: make-demo-pki.sh <outdir> [<issuer-base-url>]
#   <issuer-base-url> defaults to https://api-identra.awncorp.vn/issuers; a vc / vc-product
#   leaf gets the SAN URI <issuer-base-url>/<organisation>.
#
# Layout: <outdir>/ca/root/, <outdir>/ca/issuing/, <outdir>/orgs/<name>/<purpose>.{key,csr,cert,chain}.pem,
#         <outdir>/trust-list-signer/trust-list.{key,csr,cert}.pem, <outdir>/root.cert.pem
set -euo pipefail

PKI="$(cd "$(dirname "$0")" && pwd)/identra-pki.sh"
OUT=${1:?usage: make-demo-pki.sh <outdir> [<issuer-base-url>]}
BASE=${2:-https://api-identra.awncorp.vn/issuers}
BASE=${BASE%/}
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT")" ]; then echo "make-demo-pki: $OUT exists and is not empty" >&2; exit 1; fi

"$PKI" init-root --dir "$OUT/ca/root" --o "Identra DEMO" --cn "Identra DEMO Root CA"
"$PKI" init-issuing --dir "$OUT/ca/issuing" --root-dir "$OUT/ca/root" --o "Identra DEMO" --cn "Identra DEMO Issuing CA 1"
cp "$OUT/ca/root/ca.cert.pem" "$OUT/root.cert.pem"

# org <name> <O> <tax code> <purpose...>
org() {
  local name=$1 o=$2 mst=$3 purpose dir="$OUT/orgs/$1"
  shift 3
  mkdir -p "$dir"
  for purpose; do
    local san=()
    case $purpose in vc | vc-product) san=(--san-uri "$BASE/$name") ;; esac
    "$PKI" new-key-and-csr --key "$dir/$purpose.key.pem" --csr "$dir/$purpose.csr.pem" --o "$o" --mst "$mst" --cn "$o ($purpose)"
    "$PKI" issue-leaf --ca-dir "$OUT/ca/issuing" --csr "$dir/$purpose.csr.pem" --purpose "$purpose" "${san[@]}" \
      --out "$dir/$purpose.cert.pem" --chain "$dir/$purpose.chain.pem"
  done
}

org truong-mau "Trường Mẫu DEMO" 0100000001 vc status
org nha-san-xuat "Nhà Sản Xuất DEMO" 0100000002 vc-product status
org kiem-dinh "Kiểm Định DEMO" 0100000003 vc-product status
org phan-phoi "Phân Phối DEMO" 0100000004 vc-product status
org nha-tuyen-dung-mau "Nhà Tuyển Dụng Mẫu DEMO" 0100000005 request

mkdir -p "$OUT/trust-list-signer"
"$PKI" new-key-and-csr --key "$OUT/trust-list-signer/trust-list.key.pem" --csr "$OUT/trust-list-signer/trust-list.csr.pem" \
  --o "Identra DEMO" --mst 0100000000 --cn "Identra DEMO Trust List Signer"
"$PKI" issue-trust-list-signer --root-dir "$OUT/ca/root" --csr "$OUT/trust-list-signer/trust-list.csr.pem" \
  --out "$OUT/trust-list-signer/trust-list.cert.pem"

echo "DEMO PKI written to $OUT"

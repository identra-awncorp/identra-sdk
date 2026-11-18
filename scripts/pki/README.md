# Identra PKI scripts

OpenSSL scripts for the two-tier PKI of ADR-0015 (sections 2, 9, 10, 14, 15). They need `bash`
and OpenSSL 3.0 or later (tested with 3.0.17).

| Script | Purpose |
|---|---|
| `identra-pki.sh` | The operational tool: Root, Issuing CA, organisation keys and CSRs, leaf and trust-list-signer certificates |
| `make-demo-pki.sh <outdir> [<issuer-base-url>]` | The DEMO set of ADR-0015 section 10 (every name says DEMO, fake tax codes) |
| `make-test-pki.sh <outdir>` | Test material for `npm test`, including invalid certificates, with fixed dates |
| `ensure-test-pki.sh` | Run by `npm test`; regenerates `.pki/test` and `.pki/demo` when the scripts change |

Rules the scripts enforce:

- No key or certificate is ever overwritten. A step that fails halfway leaves its key behind;
  inspect it and delete it by hand before running the step again.
- Keys are P-256 only, written with `umask 077`. They are **not** passphrase-protected: keep the
  CA directories on an encrypted volume (ADR-0015 section 2: Root on an encrypted USB plus an
  encrypted copy elsewhere; Issuing CA on a separate offline machine).
- Lifetimes come from ADR-0015 section 14: Root 25 years, Issuing CA 15 years, `vc` 3 years,
  `vc-product` 11 years, `status` / `request` / trust-list signer 13 months.
- A CA refuses to issue a certificate whose `notAfter` is later than its own.
- Leaf subjects are exactly `C=VN, O=<name>, organizationIdentifier=VATVN-<tax code>, CN=<name>`
  (section 9); `vc` and `vc-product` leaves carry the issuer URL as their only SAN URI.
- Every issued certificate is printed with its SHA-256 fingerprint in hex and in base64url. The
  base64url value is what goes into the trust list (`chung_thu[].sha256`) and into `x509_hash`.
- Names and paths are always arguments. Names must not contain `/ \ + = $`; paths must not contain `$`.

Nothing generated here may be committed: `.pki/`, `*.key.pem` and `*.csr.pem` are git-ignored.

## Production procedure (ADR-0015 section 10)

### 1. Root CA (once, offline, by the Root key holder)

On an offline machine, with the encrypted USB mounted at `/media/root-usb`:

```sh
scripts/pki/identra-pki.sh init-root --dir /media/root-usb/identra-root \
  --o "Identra" --cn "Identra Root CA"
```

This writes `ca.key.pem`, `ca.cert.pem` and the issuance database `db/`. Then:

1. Copy the whole directory to the second encrypted medium kept elsewhere.
2. Write down the printed fingerprint. Publish it on the website (section 8).
3. `ca.cert.pem` (no key) is the pinned root for the app, the website bundle and the server.

### 2. Issuing CA (offline, every 4 years)

With the Root USB mounted, on the administrator's offline machine:

```sh
scripts/pki/identra-pki.sh init-issuing --dir /secure/identra-issuing-1 \
  --root-dir /media/root-usb/identra-root --o "Identra" --cn "Identra Issuing CA 1"
```

Unmount the Root USB immediately afterwards. The Issuing CA key stays on this offline machine,
never on the VPS. Replace the Issuing CA when less than 11 years of its lifetime remain (every
4 years), otherwise it can no longer issue an 11-year `vc-product` certificate. Build a new Root
before the old one's tenth year and pin both roots during the change (section 8).

### 3. Organisation key and CSR (organisation side)

The organisation (for the demo, Identra on its behalf) creates its key and CSR. One key per
certificate and purpose:

```sh
scripts/pki/identra-pki.sh new-key-and-csr --key vc.key.pem --csr vc.csr.pem \
  --o "Trường ABC" --mst 0101234567 --cn "Trường ABC (vc)"
```

The key never leaves the organisation; only `vc.csr.pem` is sent to the Identra administrator.

### 4. Check and issue (Identra administrator, offline)

1. Check the organisation's identity and its tax code against the CSR (`openssl req -in vc.csr.pem -noout -subject`).
2. Issue with the purpose it was approved for:

```sh
scripts/pki/identra-pki.sh issue-leaf --ca-dir /secure/identra-issuing-1 --csr vc.csr.pem \
  --purpose vc --san-uri https://api-identra.awncorp.vn/issuers/truong-abc \
  --out vc.cert.pem --chain vc.chain.pem
```

`--purpose` is `vc` (personal credentials, 3 years), `vc-product` (product records, 11 years),
`status` (status list signing) or `request` (verifier presentation requests). `--san-uri` is
required for `vc` / `vc-product`, refused otherwise. `vc.chain.pem` holds the leaf and the
Issuing CA certificate: the `x5c` of everything this key signs.

3. Copy `vc.cert.pem` and `vc.chain.pem` to the organisation (for the demo: to the VPS).
4. Add the printed base64url fingerprint to the trust list with the matching `muc_dich`.

### 5. Trust-list signer (yearly, offline, by the Root key holder)

The trust list is signed by a certificate issued directly by the Root (section 6). Its key lives
on the VPS because the list is re-signed every hour:

```sh
scripts/pki/identra-pki.sh new-key-and-csr --key trust-list.key.pem --csr trust-list.csr.pem \
  --o "Identra" --mst <Identra tax code> --cn "Identra Trust List Signer"
scripts/pki/identra-pki.sh issue-trust-list-signer --root-dir /media/root-usb/identra-root \
  --csr trust-list.csr.pem --out trust-list.cert.pem
```

Renew it before its 13 months run out.

### Revocation

Until CRL/OCSP (GĐ8), revoking a certificate means removing its fingerprint from the trust list.

## Demo and test sets

```sh
scripts/pki/make-demo-pki.sh /path/to/demo-pki                          # default issuer URLs
scripts/pki/make-demo-pki.sh /path/to/demo-pki http://localhost:3000/issuers  # local / e2e origin
```

The demo layout is `ca/root/`, `ca/issuing/`, `orgs/<name>/<purpose>.{key,csr,cert,chain}.pem`,
`trust-list-signer/trust-list.{key,csr,cert}.pem` and `root.cert.pem` (the pin). Organisations:
`truong-mau` (`vc`, `status`), `nha-san-xuat`, `kiem-dinh`, `phan-phoi` (`vc-product`, `status`),
`nha-tuyen-dung-mau` (`request`), tax codes `0100000001` to `0100000005`; the trust-list signer
uses `0100000000`.

`make-test-pki.sh` uses fixed dates (CAs from 2025-01-01, leaves from 2026-01-01) so the tests
are deterministic, and produces the invalid material the tests need through the internal
functions of `identra-pki.sh`, bypassing its checks. `npm test` creates both sets under `.pki/`.

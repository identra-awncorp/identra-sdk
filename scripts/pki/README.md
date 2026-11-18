# Identra PKI scripts

OpenSSL scripts for the two-tier PKI of ADR-0015 (sections 2, 6, 9, 10, 14, 15). They need
`bash` and OpenSSL 3.0 or later (tested with 3.0.17).

| Script | Purpose |
|---|---|
| `identra-pki.sh` | The operational tool (subcommands below) |
| `pki-lib.sh` | Its internals; must sit next to `identra-pki.sh` |
| `make-demo-pki.sh <outdir> [<issuer-base-url>]` | The DEMO set of ADR-0015 section 10 (every name says DEMO, fake tax codes) |
| `make-test-pki.sh <outdir>` | Test material for `npm test`, including invalid certificates, with fixed dates |
| `ensure-test-pki.sh` | Run by `npm test`; regenerates `.pki/test` and `.pki/demo` when the scripts change |

What the scripts guarantee:

- Every argument is validated before the first key is generated. A run that fails removes
  everything it created in that run, and never anything that existed before.
- No key or certificate is ever overwritten.
- Names (`--o`, `--cn`) may not contain control characters, leading or trailing spaces, or any of
  `/ \ + = $ # " ``; `--mst` is 10 digits (optionally `-NNN`). The issuer URL (`--san-uri`) is
  `https://<host>[:port][/path]` using only `A-Z a-z 0-9 . _ ~ : / ? @ ! & ( ) * + ; % = -`
  (no `'`: the OpenSSL config parser silently drops it).
- After every CSR and every certificate, the subject and the SAN are read back from the file and
  compared with the request; a difference fails the run and deletes the certificate.
- Keys are P-256, written with `umask 077`, **without a passphrase**: they must live on an
  encrypted volume (see the checklist).
- Lifetimes come from ADR-0015 section 14: Root 25 years, Issuing CA 15 years, `vc` 3 years,
  `vc-product` 11 years, `status` / `request` / trust-list signer 13 months. A CA refuses to
  issue a certificate whose `notAfter` is later than its own.
- Every certificate gets a fresh random serial (124 bits).
- `show` prints subject, issuer, SAN, validity, basicConstraints, keyUsage, serial and the
  SHA-256 fingerprint in hex and base64url. The base64url value is what goes into the trust list
  (`chung_thu[].sha256`) and into `x509_hash`.

Identifiers are canonical `https://` URLs in every environment, including development and e2e
tests: those redirect network access through an injected fetch mapping, they do not change
identifiers.

Nothing generated here may be committed: `.pki/`, `*.key.pem` and `*.csr.pem` are git-ignored.
When a failed run reports "removed what this run created", the CA's `db/index.txt` still lists
the signature OpenSSL made (an audit record); the certificate files themselves are deleted.

## Ceremony (ADR-0015 sections 2 and 10)

Three places hold keys. **The Root key and the Issuing CA key never touch the VPS.**

| Place | Holds | Online |
|---|---|---|
| Root machine (offline, encrypted USB kept by daudaudinang, encrypted copy elsewhere) | Root key and database | never |
| Issuing-CA machine (offline, the administrator's, separate from the Root) | Issuing CA key and database | never |
| VPS, `/etc/identra/keys/` (readable by the server process only) | the DEMO organisations' keys, the trust-list signer key, their certificates | yes |

### Checklist before each session

1. Copy `identra-pki.sh` and `pki-lib.sh` to the offline machine on read-only media, and compare
   their SHA-256 with the values from the repository at a reviewed commit:
   `sha256sum identra-pki.sh pki-lib.sh` (on the online machine and again offline).
2. Check that the key volume is encrypted before writing to it: `lsblk -f` shows the device as
   `crypto_LUKS` with the mounted file system on the `/dev/mapper/...` device below it
   (`findmnt -T /media/root-usb` names that mapper device). Do not proceed on an unencrypted disk.
3. `openssl version` reports 3.0 or later.
4. After every issuance: run `identra-pki.sh show --cert <file>` and compare subject, SAN and
   validity with the request **before** handing the certificate over.

### 1. Root CA (once, Root machine)

```sh
./identra-pki.sh init-root --dir /media/root-usb/identra-root --o "Identra" --cn "Identra Root CA"
./identra-pki.sh export-root-der --in /media/root-usb/identra-root/ca.cert.pem --out identra-root.der
```

1. Copy `/media/root-usb/identra-root` to the second encrypted medium kept elsewhere.
2. Record the printed fingerprints and publish the SHA-256 on the website (section 8).
3. `ca.cert.pem` (PEM) and `identra-root.der` (DER, for `trustedRoots`) are public: they are the
   pin in the app, the website bundle and the server configuration. The key is not.

### 2. Issuing CA (every 4 years; two machines)

On the Issuing-CA machine:

```sh
./identra-pki.sh new-issuing-key-and-csr --dir /secure/identra-issuing-1 --o "Identra" --cn "Identra Issuing CA 1"
```

It prints the SHA-256 of `ca.csr.pem`. Carry only the CSR to the Root machine (USB stick), check
its SHA-256 there, then:

```sh
./identra-pki.sh sign-issuing-csr --root-dir /media/root-usb/identra-root \
  --csr ca.csr.pem --out identra-issuing-1.cert.pem
```

Unmount the Root USB. Carry the certificate back, copy it to
`/secure/identra-issuing-1/ca.cert.pem`, and run `show` on it. Replace the Issuing CA when less
than 11 years of its lifetime remain (every 4 years), otherwise it can no longer issue an 11-year
`vc-product` certificate. Build a new Root before the old one's tenth year and pin both roots
during the change (section 8).

### 3. Organisation key and CSR (organisation side; for the demo, on the VPS)

One key per certificate and purpose:

```sh
./identra-pki.sh new-key-and-csr --key /etc/identra/keys/truong-abc/vc.key.pem \
  --csr vc.csr.pem --o "Trường ABC" --mst 0101234567 --cn "Trường ABC (vc)"
```

Only `vc.csr.pem` travels to the administrator; the key stays where it was made.

### 4. Check and issue (administrator, Issuing-CA machine)

1. Check the organisation's identity and its tax code against the CSR
   (`openssl req -in vc.csr.pem -noout -subject -nameopt multiline,utf8,-esc_msb`).
2. Issue with the purpose it was approved for:

```sh
./identra-pki.sh issue-leaf --ca-dir /secure/identra-issuing-1 --csr vc.csr.pem \
  --purpose vc --san-uri https://api-identra.awncorp.vn/issuers/truong-abc \
  --out vc.cert.pem --chain vc.chain.pem
```

`--purpose` is `vc` (personal credentials, 3 years), `vc-product` (product records, 11 years),
`status` (status list signing) or `request` (verifier presentation requests). `--san-uri` is
required for `vc` / `vc-product`, refused otherwise. `vc.chain.pem` holds the leaf and the
Issuing CA certificate: the `x5c` of everything this key signs.

3. Run `show --cert vc.cert.pem`; compare subject and SAN with the request.
4. Copy `vc.cert.pem` and `vc.chain.pem` to the organisation (demo: `/etc/identra/keys/<org>/`).
5. Add the printed base64url fingerprint to the trust list with the matching `muc_dich`.

### 5. Trust-list signer (yearly; CSR from the VPS, signed on the Root machine)

The trust list is signed by a certificate issued directly by the Root (section 6). Its key is
made on the VPS, because the list is re-signed every hour, and never leaves it:

```sh
# on the VPS
./identra-pki.sh new-key-and-csr --key /etc/identra/keys/trust-list/trust-list.key.pem \
  --csr trust-list.csr.pem --o "Identra" --mst <Identra tax code> --cn "Identra Trust List Signer"
# carry trust-list.csr.pem to the Root machine, check its SHA-256, then
./identra-pki.sh issue-trust-list-signer --root-dir /media/root-usb/identra-root \
  --csr trust-list.csr.pem --out trust-list.cert.pem
# carry trust-list.cert.pem back to /etc/identra/keys/trust-list/ and run show on it
```

Renew it before its 13 months run out.

### Revocation

Until CRL/OCSP (GĐ8), revoking a certificate means removing its fingerprint from the trust list.

## Demo and test sets

```sh
scripts/pki/make-demo-pki.sh /path/to/demo-pki
scripts/pki/make-demo-pki.sh /path/to/demo-pki https://issuers.example.test   # another canonical https base
```

The demo layout is `ca/root/`, `ca/issuing/`, `orgs/<name>/<purpose>.{key,csr,cert,chain}.pem`,
`trust-list-signer/trust-list.{key,csr,cert}.pem` and `root.cert.pem` (the pin). Organisations:
`truong-mau` (`vc`, `status`), `nha-san-xuat`, `kiem-dinh`, `phan-phoi` (`vc-product`, `status`),
`nha-tuyen-dung-mau` (`request`), tax codes `0100000001` to `0100000005`; the trust-list signer
uses `0100000000`. The demo set uses `init-issuing` (Root and Issuing CA on one machine), which
the real ceremony does not.

`make-test-pki.sh` uses fixed dates (CAs from 2025-01-01, leaves from 2026-01-01) so the tests
are deterministic, and produces the invalid material the tests need through the internal
functions of `pki-lib.sh`, bypassing the checks. `npm test` creates both sets under `.pki/`.

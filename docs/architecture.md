# Identra SDK architecture

This document is the contract between the four packages and their consumers
(`identra-server`, `identra-app`, `identra-website`). The decisions behind it are
the ADRs 0001–0017 kept in the private parent repository; where this file and an
ADR disagree, the ADR wins and this file must be fixed.

All protocol logic lives in this SDK. Consumers only do UI, HTTP, storage and
call the SDK (ADR-0005).

## 1. Packages

| Package | Runs on | Contains | Runtime dependencies (pinned exactly) |
|---|---|---|---|
| `@identra/sdk-core` | Node, browser, React Native | Interfaces, JWS, X.509 chain validation, SD-JWT VC issue / present / verify, verification policy, status list, trust list, product chain, `did:jwk` | `@sd-jwt/core`, `@sd-jwt/sd-jwt-vc`, `@owf/token-status-list`, `micro-key-producer` |
| `@identra/sdk-core/webcrypto` | Node, browser | `Signer` / `Verifier` / `Hasher` / `RandomSource` on `globalThis.crypto` | none |
| `@identra/sdk-server` | Node | Key store, OpenID4VCI issuer, status list and trust list signing, OpenID4VP verifier | `@openid4vc/openid4vci`, `@openid4vc/openid4vp`, `@openid4vc/oauth2`, `dcql`, `jose` |
| `@identra/sdk-app` | React Native, Node (simulated wallet) | `@noble` crypto adapters, JWE, `WalletKeyStore`, `CredentialStore`, OpenID4VCI client, OpenID4VP wallet | `@noble/curves`, `@noble/hashes`, `@noble/ciphers`, `@openid4vc/openid4vci`, `@openid4vc/openid4vp`, `@openid4vc/oauth2`, `dcql` |
| `@identra/sdk-client` | browser | Verifier session client for web pages (create session, QR payload, poll result) | none |

Rules:

- The main entry of `sdk-core` imports no platform library (`jose`, `node:*`,
  `expo-*`, `react-native`) and touches no platform global other than
  `TextEncoder` / `TextDecoder`. It never references `crypto.subtle`, `Buffer`,
  `process`, `fetch` or `Date.now()` implicitly: crypto, HTTP, randomness and the
  clock are injected. A lint rule and a bundle test enforce this.
- The `webcrypto` subpath is the only file in `sdk-core` allowed to use
  `globalThis.crypto`. React Native code must not import it.
- Only ES256 (P-256) exists. There is no algorithm parameter anywhere; the
  allow-list has one entry.
- Dependencies are pinned to exact versions. Licences must be MIT or Apache-2.0
  (one recorded exception: `pako`, ADR-0017).
- IDs and salts come from `RandomSource`, never from `Date.now()` or `Math.random()`.

## 2. Injected interfaces (`sdk-core`)

```ts
interface EcPublicJwk { kty: 'EC'; crv: 'P-256'; x: string; y: string }

interface Signer {
  alg: 'ES256';
  publicJwk: EcPublicJwk;
  x5c?: string[];            // [leaf, issuing CA], standard base64 DER; wallets have none
  kid?: string;
  sign(data: Uint8Array): Promise<Uint8Array>;   // 64-byte r||s (JOSE form), never DER
}
interface Verifier {
  // The algorithm is derived from the JWK (kty/crv), never from a JWS header.
  // Must accept both low-S and high-S signatures. Returns false, never throws, on bad input.
  verify(publicJwk: EcPublicJwk, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}
interface Hasher { sha256(data: Uint8Array): Promise<Uint8Array> }
interface RandomSource { bytes(n: number): Uint8Array }
interface Clock { now(): Date }
type HttpFetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number })
  => Promise<{ status: number; headers: { get(name: string): string | null }; text(): Promise<string> }>;

interface CertificateChainValidator {
  validate(input: { x5c: string[]; profile: 'vc' | 'status' | 'request' | 'trust-list'; now: Date; expectedIssuerUri?: string }): Promise<ChainValidationResult>;
}
interface StatusChecker {
  // 'unavailable' = no valid list could be obtained or it failed any check (fail-closed, ADR-0013).
  check(ref: { uri: string; idx: number }, issuer: { maToChuc: string }): Promise<'valid' | 'revoked' | 'suspended' | 'unavailable'>;
}
interface TrustRegistry {
  // Looks up a leaf-certificate fingerprint (base64url SHA-256 of the DER).
  // Returns null when absent or outside validFrom/validUntil at `at`.
  // Rejects with TrustListUnavailableError when no valid trust list is held (ADR-0015 §6).
  lookup(fingerprint: string, at?: Date): Promise<TrustEntry | null>;
}
interface TrustEntry { maToChuc: string; ten: string; mucDich: 'vc' | 'status' | 'request'; vct?: string[]; congDoan?: string[] }
interface DidResolver { resolve(did: string, opts?: { versionTime?: string }): Promise<DidResolutionResult> }  // did:jwk only; tests and later did:certnet
```

Two implementations of the crypto interfaces exist and are tested with the same
vectors: WebCrypto (`@identra/sdk-core/webcrypto`) and `@noble/*` (`@identra/sdk-app`).

## 3. Results and error codes

Verification never throws for bad input. It returns every check so a UI can
show a tick or a cross per step (ADR-0006 §5, ADR-0007):

```ts
interface Check { id: CheckId; ok: boolean; code: ErrorCode | null; skipped?: true; detail?: string }
interface VerificationResult { ok: boolean; checks: Check[] }   // ok = every listed check is ok
```

Functions throw only on programmer error (wrong argument types, missing
configuration). `detail` is for logs and must never contain claim values,
compact credentials, disclosures or KB-JWTs (ADR-0014 §4).

Checks of a credential, in order. Steps 1–4 stop the run: when one fails, every
later check is listed with `ok: false, code: 'SKIPPED', skipped: true`. From
step 5 on, all checks run. A check that does not apply to the credential kind
is not listed.

```ts
verifyCredential(compact: string, options: {
  verifier: Verifier; hasher: Hasher; chainValidator: CertificateChainValidator;
  trustRegistry: TrustRegistry; statusChecker: StatusChecker;
  supportedVcts: string[]; now: Date;
  presentation?: { nonce: string; audience: string };   // given = verifying a presentation
}): Promise<{ ok: boolean; checks: Check[]; chainChecks?: Check[]; credential?: VerifiedCredential }>

interface VerifiedCredential {          // only when steps 1–4 passed
  vct: string; iss: string; fingerprint: string;
  issuer: { maToChuc: string; ten: string } | null;   // null unless step 7 passed
  iat: number; nbf?: number; exp?: number; status?: { idx: number; uri: string }; cnfJwk?: EcPublicJwk;
  claims?: Record<string, unknown>;     // subject claims: visible + verified disclosures; only when step 9 passed or is not listed
}
```

| # | `id` | What | Codes |
|---|---|---|---|
| 1 | `structure` | ≤ 16 384 bytes and ≤ 50 disclosures, checked before any decoding (`TOO_LARGE`). ASCII compact `<jwt>~<disclosure>~…~[<kb-jwt>]`; strict JWS; every disclosure is base64url of a JSON array; payload is a JSON object with string `iss` and `vct`, numeric `iat`, numeric `nbf` / `exp` and object `cnf` / `status` when present (shape only, nothing is trusted yet). Header `typ` is exactly `dc+sd-jwt`. Without `options.presentation` a KB-JWT is `MALFORMED`: a stored credential never has one | `MALFORMED`, `TYP_INVALID`, `TOO_LARGE` |
| 2 | `algorithm` | Header `alg` is `ES256` | `ALG_NOT_ALLOWED` |
| 3 | `certificate_chain` | `CertificateChainValidator` (section 4) with profile `vc` and `expectedIssuerUri` = `iss`; the check carries the code of the failing chain step, and `chainChecks` lists the chain steps without details | `CERT_CHAIN_MALFORMED`, `CERT_CHAIN_UNTRUSTED`, `CERT_NOT_YET_VALID`, `CERT_EXPIRED`, `CERT_CONSTRAINT_INVALID`, `CERT_KEY_NOT_ALLOWED`, `ISSUER_MISMATCH` |
| 4 | `signature` | Issuer signature with the leaf key | `SIGNATURE_INVALID` |
| 5 | `validity_time` | `iat` ≤ now + 60 s, `nbf` ≤ now + 60 s, `exp` > now − 60 s | `NOT_YET_VALID`, `EXPIRED` |
| 6 | `credential_type` | `vct` is in `supportedVcts` | `VCT_UNSUPPORTED` |
| 7 | `issuer_trust` | `trustRegistry.lookup(fingerprint, now)` returns an entry with `mucDich` `vc`, `maToChuc` equal to the leaf `organizationIdentifier`, `vct` containing the credential `vct`, and for product events `congDoan` containing the event's `cong_doan`. `TrustListUnavailableError` is `TRUST_LIST_UNAVAILABLE`; any other failure (null, mismatch, other exception) is `ISSUER_NOT_TRUSTED` | `ISSUER_NOT_TRUSTED`, `TRUST_LIST_UNAVAILABLE` |
| 8 | `status` | Only when step 7 passed, otherwise `SKIPPED` and the `StatusChecker` is not called (no request on behalf of an untrusted issuer). Rules below, then the checker's answer: `valid` passes, `revoked` / `suspended` map to their codes, anything else or an exception is `STATUS_UNAVAILABLE` | `REVOKED`, `SUSPENDED`, `STATUS_UNAVAILABLE` |
| 9 | `holder_binding` | Listed when the compact carries disclosures or `options.presentation` is given. Disclosures (ADR-0008 §6), any failure `DISCLOSURE_INVALID`: `_sd_alg` is `sha-256`; each disclosure is `[salt, name, value]` with string salt and name (array-element disclosures are refused); name not `_sd`, `...`, `_sd_alg` nor a metadata claim (`iss`, `vct`, `iat`, `nbf`, `exp`, `cnf`, `status`); no duplicate disclosure; digest referenced by the top-level `_sd`; no two disclosures with one name; no clash with a visible payload claim; no nested `_sd` or array-element digest anywhere. With `options.presentation`, the KB-JWT, any failure `KB_INVALID`: present; credential has a valid P-256 `cnf.jwk`; header `typ` `kb+jwt` and `alg` `ES256`; signature by `cnf.jwk`; `sd_hash` = base64url(SHA-256(`<jwt>~<disclosures>~`)) recomputed by the verifier; `iat` within [now − 300 s − 60 s, now + 60 s]. Then `nonce` (`NONCE_MISMATCH`), then `aud` (`AUD_MISMATCH`), so an unsigned KB-JWT never yields a mismatch | `DISCLOSURE_INVALID`, `KB_INVALID`, `NONCE_MISMATCH`, `AUD_MISMATCH` |
| 10 | `product_chain` | Product events only: `prev` matches the previous credential, stage order (GĐ6b) | `CHAIN_BROKEN` |

Other codes: `CLIENT_ID_MISMATCH`, `VERIFIER_NOT_TRUSTED` (wallet checking a
presentation request), `DID_RESOLUTION_FAILED`, `KEY_NOT_FOUND` (`did:jwk`
helper only; the credential path no longer resolves DIDs, ADR-0015), `SKIPPED`.

All codes are exported as one `ErrorCodes` constant object; UI and logs branch
on codes, never on messages. Library error messages are never inspected:
verification does not call `@sd-jwt/*` at all; the library is used to issue and
to present only (ADR-0004, "Bổ sung 2026-11-19" point 3).

Status rules enforced by the policy before the `StatusChecker` is called: the
credential must carry `status.status_list.{uri, idx}` with `idx` a non-negative
integer, and `uri` must be `https:` and start with `<iss>/status/` (ADR-0015 §11).
Anything else is `STATUS_UNAVAILABLE` without a network call.

Issuance and presentation (programmer errors throw `TypeError`):
`issueCredential` (generic), `issueDiploma`, `issueProductEvent`,
`createPresentation`, and `decodeCredentialUnverified` (display only, verifies
nothing). The issuer refuses a signer without `x5c` [leaf, issuing CA], an
`iss` that is not a SAN URI of the leaf, a status `uri` outside `<iss>/status/`
and any disclosable metadata claim, `iat` included.

## 4. X.509 (ADR-0015 §7, §14, §15)

`parseCertificate(der)` wraps `micro-key-producer` and is the only place that
library is imported. It accepts strict DER only (re-encoding must reproduce the
input) and returns the fields the validator needs: signed TBS bytes, signature
as r||s, P-256 public JWK or the foreign key algorithm, validity (UTCTime and
GeneralizedTime), raw issuer and subject names, `O` / `C` /
`organizationIdentifier`, basicConstraints, keyUsage, SAN URIs, the list of
critical extensions.

`createCertificateChainValidator({ trustedRoots, verifier, hasher })` pins one
or two root certificates (DER). `validate` returns
`{ ok, code, checks, leaf?, fingerprint? }` and applies, in this order:

1. `CERT_CHAIN_MALFORMED`: `x5c` is not exactly two certificates (leaf, issuing CA)
   for profiles `vc` / `status` / `request`, or not exactly one for `trust-list`;
   an entry is not valid base64 DER, is larger than 4 KB, or is a self-signed /
   pinned root.
2. `CERT_CHAIN_UNTRUSTED`: issuer and subject names do not chain byte for byte,
   a signature does not verify, or the last certificate is not signed by a
   pinned root. A certificate signed with anything but ECDSA P-256 / SHA-256
   cannot verify and lands here.
3. `CERT_NOT_YET_VALID` / `CERT_EXPIRED`: every certificate including the pinned
   root, at `now` ± 60 s.
4. `CERT_CONSTRAINT_INVALID`: leaf must have `CA:FALSE` and `digitalSignature`;
   issuing CA must have `CA:TRUE`, `pathLenConstraint` 0 and `keyCertSign`;
   root `CA:TRUE` and `keyCertSign`; the leaf must carry `O`, `C` and
   `organizationIdentifier` (not required for `trust-list`); any unknown
   critical extension.
5. `CERT_KEY_NOT_ALLOWED`: the leaf key is not P-256.
6. `ISSUER_MISMATCH`: `expectedIssuerUri` is given and is not one of the leaf's
   SAN URIs (profile `vc` only).

`fingerprint` is base64url (no padding) of SHA-256 over the leaf DER, the same
value as an OpenID4VP `x509_hash`.

## 5. Credential formats

- Diploma: `vct` `https://identra.awncorp.vn/vct/bang-tot-nghiep/v1`; always
  visible `iss`, `vct`, `iat`, `cnf.jwk`, `status`; seven subject claims
  (`ho_ten`, `ngay_sinh`, `ma_sinh_vien`, `nganh`, `hang_tot_nghiep`,
  `nam_tot_nghiep`, `so_hieu_bang`), all non-empty strings, each its own
  top-level disclosure; `_sd` padded with decoys to exactly 10 digests; 128-bit
  salts from `RandomSource`; no `exp`.
- Product lifecycle event: `vct`
  `https://identra.awncorp.vn/vct/su-kien-vong-doi/v1`; no disclosures, no
  `cnf`; claims `ma_san_pham` (GS1 element string `(01)<GTIN>(21)<serial>`),
  `cong_doan` (`san_xuat` | `kiem_dinh` | `phan_phoi`), `thoi_diem`,
  `dia_diem`, `mo_ta`, and `prev` = base64url(SHA-256(previous compact)) on
  every event but the first; all strings of at most 500 characters; has
  `status`; no `exp`.
- Header of both: `{ alg: 'ES256', typ: 'dc+sd-jwt', x5c: [leaf, issuingCa] }`,
  no `kid`. `iss` = `https://api-identra.awncorp.vn/issuers/<name>`.
- Metadata claims (`iss`, `vct`, `iat`, `nbf`, `exp`, `cnf`, `status`) are never
  disclosable; a presentation that delivers one through a disclosure is
  `DISCLOSURE_INVALID`.
- KB-JWT: `typ: kb+jwt`, `alg: ES256`, payload `iat`, `aud`, `nonce`, `sd_hash`;
  accepted when `iat` is within 5 minutes (± 60 s).
- Status list token: JWS `typ: statuslist+jwt` with `x5c` (profile `status`),
  payload `sub` (= list URI), `iat`, `exp` (24 h), `ttl` (900), `status_list:
  { bits: 2, lst }`; 131 072 entries; values 0 valid, 1 revoked, 2 suspended.
- Trust list token: JWS `typ: identra-trust-list+jwt` with `x5c` of exactly one
  certificate signed directly by a pinned root; payload `iat`, `exp` (24 h),
  `ttl` (3600), `issuers: [{ ma_to_chuc, ten, chung_thu: [{ sha256, muc_dich }],
  vct, cong_doan?, validFrom, validUntil }]`, `verifiers: [{ ma_to_chuc, ten,
  chung_thu: [...] }]`.

Caching rules shared by both lists (ADR-0013 §4, ADR-0015 §6): reload when the
held copy is older than `ttl`; if the reload fails keep using the held copy
until its `exp`; never accept a copy whose `iat` is older than the held one;
with no valid copy the answer is `unavailable` / `TrustListUnavailableError`.

## 6. Testing

- `node:test` only, no test framework. `npm test` at the workspace root runs
  every package.
- Test PKI is generated by `scripts/pki/` (OpenSSL) into a git-ignored
  directory; private keys are never committed.
- Every error code above has at least one test that provokes exactly that code.
- `examples/gd2-e2e.mjs` (issue → store → present → verify, then a tampered
  disclosure) runs as part of `npm test`.
- A bundle test runs issue → present → verify from an esbuild
  `--platform=neutral` bundle in a `node:vm` realm without `crypto`, `Buffer`,
  `process` or `fetch`; beyond ECMAScript it needs only `TextEncoder` and
  `TextDecoder` (the latter for `@sd-jwt/*`; React Native needs a polyfill).
- Crypto adapters: RFC 7515 Appendix A.3 ES256 vector; sign → verify →
  one-byte tamper fails; `alg: none` and `HS256` rejected; high-S accepted;
  DER → r||s conversion.

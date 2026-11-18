# Identra SDK architecture

This document is the contract between the four packages and their consumers
(`identra-server`, `identra-app`, `identra-website`). The decisions behind it are
the ADRs 0001–0019 kept in the private parent repository; where this file and an
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
| `@identra/sdk-client` | browser | Verifier session client for web pages (create session, QR payload, poll result); the separate entry `@identra/sdk-client/product` verifies a product chain in the browser (section 10) | none (main entry); `@identra/sdk-core` (product entry) |

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
// Implementations MUST enforce timeoutMs (reject when it passes) and a response size limit:
// sdk-core has no timer and reads text() whole.
type HttpFetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number })
  => Promise<{ status: number; headers: { get(name: string): string | null }; text(): Promise<string> }>;

interface CertificateChainValidator {
  // expectedIssuerUri: required for profile 'vc', forbidden for the others (TypeError).
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
Both validate the JWK exactly as `normalizeEcPublicJwk` does: EC, P-256, 32-byte
coordinates, no private members, and the point on the curve (y² = x³ − 3x + b mod p).

JWS (one code path, ADR-0006): `signJws` builds every JWS; `decodeJws(compact,
maxBytes)` has a required size bound (`TOO_LARGE`; credentials 16 384, KB-JWT
4 096); `verifyJws(decoded, publicJwk, verifier)` is the only verification and
always applies the `alg` allow-list first (`ALG_NOT_ALLOWED`, then
`SIGNATURE_INVALID`), so a caller cannot skip it.

`createWebCryptoSigner({ privateKey, publicJwk?, x5c? })`: `privateKey` is a
CryptoKey (may be non-extractable) or PKCS#8 PEM/DER (imported non-extractable).
The public key comes from `x5c[0]` when given (x5c = 1 or 2 certificates that all
parse and, when 2, chain by name), else from `publicJwk`, else from the public key
inside the PKCS#8 structure; the private key is never exported, and a throwaway
signature proves that the public key belongs to it.
`generateWebCryptoKeyPair()` returns `{ privateKey (non-extractable), publicJwk }`.

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
is not listed. Which checks are listed is decided only from what is knowable
without parsing, so it is the same whichever of steps 1–4 fails:
`holder_binding` is listed for every presentation, and for a stored credential
whose compact shows at least one disclosure segment.

Two entry points over one implementation, so the modes cannot be confused:

```ts
type VerifyCredentialOptions = {
  verifier: Verifier; hasher: Hasher; chainValidator: CertificateChainValidator;
  trustRegistry: TrustRegistry; statusChecker: StatusChecker;
  supportedVcts: string[]; now: Date;
};
// Anything received from another party: steps 1-9, the KB-JWT is required (step 9 always listed).
verifyPresentation(compact, options & { presentation: { nonce: string; audience: string } })
// MUST NOT be used to accept a credential presented by someone else: never proves possession.
// A credential the caller already holds (wallet on receipt or display, a public product event).
// A compact carrying a KB-JWT is MALFORMED.
verifyStoredCredential(compact, options)
// both: Promise<{ ok: boolean; checks: Check[]; chainChecks?: Check[]; credential?: VerifiedCredential }>

interface VerifiedCredential {          // only when steps 1–4 passed
  vct: string; iss: string; fingerprint: string;
  issuer: { maToChuc: string; ten: string } | null;   // null unless step 7 passed
  iat: number; nbf?: number; exp?: number; status?: { idx: number; uri: string }; cnfJwk?: EcPublicJwk;
  claims?: Record<string, unknown>;     // subject claims (visible + verified disclosures); only when the WHOLE result is ok
}
```

| # | `id` | What | Codes |
|---|---|---|---|
| 1 | `structure` | ≤ 16 384 bytes and ≤ 50 disclosures, checked before any decoding (`TOO_LARGE`). ASCII compact `<jwt>~<disclosure>~…~[<kb-jwt>]`; strict JWS; every disclosure is base64url of a JSON array; payload is a JSON object with string `iss` and `vct`, numeric `iat`, numeric `nbf` / `exp` and object `cnf` / `status` when present (shape only, nothing is trusted yet). SD shape of the payload (RFC 9901), with or without disclosures: top-level `_sd`, if present, is an array of unique 43-character base64url digests; `_sd_alg` is exactly `sha-256`, required with `_sd` (allowed alone only as `sha-256`); no key `_sd`, `_sd_alg` or `...` anywhere below the top level. Header `typ` is exactly `dc+sd-jwt`. In `verifyStoredCredential` a KB-JWT is `MALFORMED`: a stored credential never has one | `MALFORMED`, `TYP_INVALID`, `TOO_LARGE` |
| 2 | `algorithm` | Header `alg` is `ES256` | `ALG_NOT_ALLOWED` |
| 3 | `certificate_chain` | `CertificateChainValidator` (section 4) with profile `vc` and `expectedIssuerUri` = `iss`; the check carries the code of the failing chain step, and `chainChecks` lists the chain steps without details | `CERT_CHAIN_MALFORMED`, `CERT_CHAIN_UNTRUSTED`, `CERT_NOT_YET_VALID`, `CERT_EXPIRED`, `CERT_CONSTRAINT_INVALID`, `CERT_KEY_NOT_ALLOWED`, `ISSUER_MISMATCH` |
| 4 | `signature` | Issuer signature with the leaf key | `SIGNATURE_INVALID` |
| 5 | `validity_time` | `iat` ≤ now + 60 s, `nbf` ≤ now + 60 s, `exp` > now − 60 s | `NOT_YET_VALID`, `EXPIRED` |
| 6 | `credential_type` | `vct` is in `supportedVcts` | `VCT_UNSUPPORTED` |
| 7 | `issuer_trust` | `trustRegistry.lookup(fingerprint, now)` returns an entry with `mucDich` `vc`, `maToChuc` equal to the leaf `organizationIdentifier`, `vct` containing the credential `vct`, and for product events `congDoan` containing the event's `cong_doan`. `TrustListUnavailableError` is `TRUST_LIST_UNAVAILABLE`; any other failure (null, mismatch, other exception) is `ISSUER_NOT_TRUSTED` | `ISSUER_NOT_TRUSTED`, `TRUST_LIST_UNAVAILABLE` |
| 8 | `status` | Only when step 7 passed, otherwise `SKIPPED` and the `StatusChecker` is not called (no request on behalf of an untrusted issuer). Rules below, then the checker's answer: `valid` passes, `revoked` / `suspended` map to their codes, anything else or an exception is `STATUS_UNAVAILABLE` | `REVOKED`, `SUSPENDED`, `STATUS_UNAVAILABLE` |
| 9 | `holder_binding` | Always listed by `verifyPresentation`; listed by `verifyStoredCredential` when the compact carries disclosures. Disclosures (ADR-0008 §6), any failure `DISCLOSURE_INVALID`: a top-level `_sd` exists; each disclosure is `[salt, name, value]` with string salt and name (array-element disclosures are refused); name not `_sd`, `...`, `_sd_alg` nor a metadata claim (`iss`, `vct`, `iat`, `nbf`, `exp`, `cnf`, `status`); no duplicate disclosure; digest referenced by the top-level `_sd`; no two disclosures with one name; no clash with a visible payload claim; no `_sd`, `_sd_alg` or `...` key inside a disclosed value. In `verifyPresentation`, the KB-JWT, any failure `KB_INVALID`: present and at most 4 096 bytes; credential has a valid P-256 `cnf.jwk`; header `typ` `kb+jwt` and `alg` `ES256`; signature by `cnf.jwk`; `sd_hash` = base64url(SHA-256(`<jwt>~<disclosures>~`)) recomputed by the verifier; `iat` within [now − 300 s − 60 s, now + 60 s] (both ends inclusive); `exp`, when present, a number > now − 60 s; `nbf`, when present, a number ≤ now + 60 s. Then `nonce` (`NONCE_MISMATCH`), then `aud` (`AUD_MISMATCH`), so an unsigned KB-JWT never yields a mismatch | `DISCLOSURE_INVALID`, `KB_INVALID`, `NONCE_MISMATCH`, `AUD_MISMATCH` |
| 10 | `product_chain` | Only in `verifyProductChain` (section 10), listed last for every event; `SKIPPED` when steps 1–4 failed. The event is a product event of the product being viewed, at its stage position, linked by `prev` to the event before it as received, with a valid, non-decreasing `thoi_diem`; the five claims are strings of 1–500 characters (`MALFORMED` otherwise) | `CHAIN_BROKEN`, `MALFORMED` |

Other codes: `CLIENT_ID_MISMATCH`, `VERIFIER_NOT_TRUSTED` (wallet checking a
presentation request), `DID_RESOLUTION_FAILED`, `KEY_NOT_FOUND` (`did:jwk`
helper only; the credential path no longer resolves DIDs, ADR-0015), `SKIPPED`.

All codes are exported as one `ErrorCodes` constant object; UI and logs branch
on codes, never on messages. Library error messages are never inspected:
verification does not call `@sd-jwt/*` at all; the library is used to issue and
to present only (ADR-0004, "Bổ sung 2026-11-19" point 3).

Status rules enforced by the policy before the `StatusChecker` is called: the
credential must carry `status.status_list.{uri, idx}` with `idx` a non-negative
integer, and `uri` must be exactly `<iss>/status/<n>` with `n` matching
`^[1-9][0-9]{0,8}$` (ADR-0015 §11), compared as strings: no URL parsing and no
platform `URL`, so `..`, `%2e`, `\`, whitespace, query, fragment, userinfo, port
and case variants never reach the checker. Anything else is
`STATUS_UNAVAILABLE` without a network call. The issuer enforces the same form.

Known limitation: no rule ties a credential's `iat` to its certificate's
validity or to the 12-month signing window of ADR-0015 §14. A key stolen after
its signing window can still sign backdated credentials until the certificate
expires; the remedy is removing the certificate's fingerprint from the trust
list (step 7).

Issuance and presentation (programmer errors throw `TypeError`; errors of the
library are wrapped in `TypeError` without echoing claim values):
`issueCredential` (generic), `issueDiploma`, `issueProductEvent`,
`createPresentation`, and `decodeCredentialUnverified` (display only, verifies
nothing). The issuer refuses a signer without `x5c` [leaf, issuing CA], an
`iss` that is not a SAN URI of the leaf, a status `uri` not of the form
`<iss>/status/<n>`, any disclosable metadata claim (`iat` included), claim names
`__proto__` / `constructor` / `prototype` / `_sd` / `_sd_alg` / `...` / metadata
names, values JSON cannot carry unchanged (undefined, functions, symbols,
bigints, non-finite numbers, non-plain objects, cycles; reserved keys at any
depth), more than 50 disclosable claims, and a result larger than 16 384 bytes.

## 4. X.509 (ADR-0015 §7, §14, §15)

`parseCertificate(der)` wraps `micro-key-producer` and is the only place that
library is imported (it also reads the public key of a PKCS#8 EC key for the
WebCrypto signer). It accepts strict DER v3 certificates only (re-encoding must
reproduce the input) and throws `TypeError`, never another error, otherwise. It
returns the fields the validator needs: signed TBS bytes, signature as r||s (only
for ecdsa-with-SHA256), P-256 public JWK (only for an uncompressed point on the
curve; a compressed or off-curve key yields none) or the foreign key algorithm,
validity, raw issuer and subject names, `O` / `C` / `organizationIdentifier` /
`CN`, basicConstraints, all nine keyUsage bits, SAN URIs, the list of critical
extensions. Duplicate extensions, duplicate subject attributes and mismatching
inner/outer signature algorithms are refused. Times: UTCTime as RFC 5280;
GeneralizedTime is accepted from 1950 on (RFC 5280 wants UTCTime through 2049:
a documented leniency); years before 1950 are refused.

`createCertificateChainValidator({ trustedRoots, verifier, hasher })` pins one
or two root certificates (DER). `validate` returns
`{ ok, code, checks, leaf?, fingerprint? }` and applies, in this order:

1. `CERT_CHAIN_MALFORMED`: `x5c` is not exactly two certificates (leaf, issuing CA)
   for profiles `vc` / `status` / `request`, or not exactly one for `trust-list`;
   an entry is not valid base64 DER, is larger than 4 KB, or is a self-signed /
   pinned root.
2. `CERT_CHAIN_UNTRUSTED`: issuer and subject names do not chain byte for byte,
   a signature does not verify, or the last certificate is not signed by a
   pinned root. A certificate signed with anything but ECDSA P-256 / SHA-256,
   or by a key that is not a valid P-256 point, cannot verify and lands here.
3. `CERT_NOT_YET_VALID` / `CERT_EXPIRED`: every certificate including the pinned
   root, valid when `notBefore − 60 s ≤ now ≤ notAfter + 60 s` (both ends inclusive).
4. `CERT_CONSTRAINT_INVALID` (ADR-0015 §9, §15), for every profile:
   - leaf: `basicConstraints` present with `CA:FALSE`; keyUsage exactly
     `digitalSignature` (extension present, no other bit); subject `C` = `VN`,
     non-empty `O`, `organizationIdentifier` matching `^VATVN-[0-9]{10}(-[0-9]{3})?$`
     (the trust-list signer included);
   - issuing CA: `CA:TRUE`, `pathLenConstraint` 0, keyUsage exactly
     `keyCertSign` + `cRLSign`;
   - root: `CA:TRUE`, keyUsage exactly `keyCertSign` + `cRLSign`;
   - no unknown critical extension on any of them (known: basicConstraints,
     keyUsage, subjectAltName; extendedKeyUsage is not interpreted, so a
     critical one is refused).
5. `CERT_KEY_NOT_ALLOWED`: the leaf has no P-256 key (other algorithm or curve,
   compressed or off-curve point).
6. `ISSUER_MISMATCH` (profile `vc`, where `expectedIssuerUri` is required): it is
   not exactly equal to one of the leaf's SAN URIs.

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
  `dia_diem`, `mo_ta`, and `prev` = base64url(SHA-256(previous compact, its
  trailing `~` included)) on every event but the first (the first has no `prev`
  claim at all); all strings of at most 500 characters; `thoi_diem` an ISO 8601
  UTC instant (`YYYY-MM-DDTHH:MM:SS[.sss]Z`), enforced by `verifyProductChain`;
  has `status`; no `exp`. The issuer refuses a `ma_san_pham` that
  `parseProductCode` refuses (section 10).
- Header of both: `{ alg: 'ES256', typ: 'dc+sd-jwt', x5c: [leaf, issuingCa] }`,
  no `kid`. `iss` = `https://api-identra.awncorp.vn/issuers/<name>`.
- Metadata claims (`iss`, `vct`, `iat`, `nbf`, `exp`, `cnf`, `status`) are never
  disclosable; a presentation that delivers one through a disclosure is
  `DISCLOSURE_INVALID`.
- KB-JWT: `typ: kb+jwt`, `alg: ES256`, payload `iat`, `aud`, `nonce`, `sd_hash`;
  accepted when `iat` is within 5 minutes (± 60 s); `exp` / `nbf`, when present,
  are enforced with the same 60 s skew.
- Profile rule: `typ` values are compared exactly and case-sensitively
  (`dc+sd-jwt`, `kb+jwt`, `statuslist+jwt`, `identra-trust-list+jwt`), without an
  `application/` prefix.
- Status list token (Token Status List draft 21 §5.1): JWS `typ: statuslist+jwt`,
  `alg: ES256`, `x5c` [leaf, issuing CA] of a `status` certificate (profile
  `status`); payload `sub` (= list URI `<iss>/status/<n>`), `iat`, `exp` (24 h),
  `ttl` (900), `status_list: { bits: 2, lst }`; `lst` = base64url of the ZLIB
  (RFC 1950) compressed 32 768-byte array of 131 072 entries, entry `i` in bits
  `2·(i mod 4)` and up of byte `⌊i / 4⌋`; values 0 valid, 1 revoked, 2
  suspended (3 is refused). At most 128 KB.
- Trust list token: JWS `typ: identra-trust-list+jwt` with `x5c` of exactly one
  certificate signed directly by a pinned root; payload `iat`, `exp` (24 h),
  `ttl` (3600), `issuers: [{ ma_to_chuc, ten, chung_thu: [{ sha256, muc_dich }],
  vct, cong_doan?, validFrom, validUntil }]`, `verifiers: [{ ma_to_chuc, ten,
  chung_thu: [...], validFrom?, validUntil? }]`. `ma_to_chuc` is
  `VATVN-<tax code>`; `sha256` is 43 base64url characters; `muc_dich` is `vc` or
  `status` under `issuers` and `request` under `verifiers`; instants are ISO 8601
  in UTC (`…Z`). At most 256 KB and 1000 entries.

Caching rules shared by both lists (ADR-0013 §4, ADR-0015 §6, ADR-0019): a held
copy is used without a reload while younger than `min(ttl, cap, maxAgeSeconds ??
∞)`, where the cap is a constant of `sdk-core` (900 s for a status list, 3600 s
for the trust list) and a missing `ttl` means the cap; the age is counted from
when this process fetched it, and a clock that stepped back before that instant
makes the copy stale (`maxAgeSeconds: 0` = always try to reload: the
server-side verifier). Otherwise reload; if the reload fails or yields an
invalid token keep using the held copy until its `exp` (+ 60 s skew). Both
tokens are refused when `exp − iat` exceeds 86 400 s + 60 s. Never accept a copy
whose `iat` is older than the held one, nor another token with the same `iat`
(the identical token is accepted and refreshes the held copy); the server never
issues two tokens with one `iat` (`iat = max(now, last iat + 1)`). With no valid
copy the answer is `unavailable` / `TrustListUnavailableError`. Concurrent reads
of one URL share one request. The status checker holds at most 100 lists and
never evicts one that is still inside its `exp`: when all are, a new list is
verified and used but not cached.

Optional persistence (`seen: { get(key), set(key, value) }`, ADR-0019 §3) keeps
`iat:<url>` (last accepted `iat` per list URL) and, for the trust list,
`signer-not-before:<url>` across restarts; it is read before verifying and
written after each accepted token. Without a held copy only the stored `iat` is
known, so a token with an equal `iat` is accepted. A failing store is treated as
empty.

## 6. Testing

- `node:test` only, no test framework. `npm test` at the workspace root runs
  every package.
- Test PKI is generated by `scripts/pki/` (OpenSSL) into a git-ignored
  directory; private keys are never committed.
- Every error code above has at least one test that provokes exactly that code.
- Differential test (`sd-jwt-differential.test.ts`): a deterministic corpus of
  valid and mutated presentations is verified by `verifyPresentation` /
  `verifyStoredCredential` and by the
  library's strict `SdJwtVcInstance.verify`; we never accept what the library
  rejects, accepted claims, digests and `sd_hash` agree, and the only cases where
  we are stricter are an explicit list (KB-JWT in a stored credential, `iat` only
  through a disclosure, size and disclosure-count limits, nested and
  array-element disclosures, a non-canonical base64url KB-JWT signature, the SD
  shape rules without disclosures), each with its asserted code. The RFC 9901 worked examples (disclosure digests, the
  section 5.2 SD-JWT+KB) are reproduced from the RFC text.
- `examples/gd2-e2e.mjs` (issue → store → present → verify, then a tampered
  disclosure) runs as part of `npm test`.
- A bundle test runs issue → present → verify from an esbuild
  `--platform=neutral` bundle in a `node:vm` realm without `crypto`, `Buffer`,
  `process` or `fetch`; beyond ECMAScript it needs only `TextEncoder` and
  `TextDecoder` (the latter for `@sd-jwt/*`; React Native needs a polyfill).
- Crypto adapters: RFC 7515 Appendix A.3 ES256 vector; sign → verify →
  one-byte tamper fails; `alg: none` and `HS256` rejected; high-S accepted;
  DER → r||s conversion.

## 7. Status list and trust list (GĐ7a)

`sdk-core` (pure; fetch and clock injected):

- `createStatusList()`, `statusListFromBytes(bytes)`, `statusListEntry(bytes, idx)`,
  `decodeStatusList({ bits, lst })`: the list model on `@owf/token-status-list` (bit
  packing and ZLIB, ADR-0017). Index and value are range-checked here (the library
  allows 3); decoding refuses `bits ≠ 2`, anything but exactly 32 768 inflated bytes,
  and stops inflating once the output passes 32 768 bytes (in the library's 64 KiB
  output chunks).
- `createStatusListToken({ list, uri, signer, now, ttlSeconds = 900, lifetimeSeconds = 86 400 })`,
  `createTrustListToken({ issuers, verifiers, signer, now, ttlSeconds = 3600, lifetimeSeconds = 86 400, signerNotBefore? })`.
  `lifetimeSeconds` is at most 86 400. The trust-list signer must have an `x5c` of
  exactly one certificate; `signerNotBefore` may not be later than its notBefore.
- `verifyStatusListToken(token, { uri, issuer: { maToChuc }, chainValidator, trustRegistry, verifier, now })`
  and `verifyTrustListToken(token, { chainValidator, verifier, now, minSignerNotBefore? })` return
  `{ ok: true, … }` or `{ ok: false, reason, detail }` and never throw for bad input.
  In order: size cap (`too_large`); strict JWS (`malformed`); `typ` exact (`typ`);
  `alg` ES256 (`alg`); `x5c` with profile `status` / `trust-list` (`chain`); signature
  with the leaf key (`signature`); numeric `iat` and `exp` present, `ttl` a positive
  integer if present, `exp − iat` ≤ 86 460 s (`claims`); `iat` ≤ now + 60 s
  (`not_yet_valid`); `exp` > now − 60 s (`expired`). Then for a status list: `sub` =
  `uri` (`claims`); the signer fingerprint is in the trust list with purpose
  `status`, its `organizationIdentifier` equals that entry's `maToChuc`, and that
  `maToChuc` is the issuer's (`not_trusted`; `trust_list_unavailable` when the
  registry has no list); `status_list` decodes (`claims`). For a trust list: the
  payload validator (`claims`), which also refuses unknown fields and purposes, a
  purpose outside its section, malformed fingerprints or instants, `validFrom ≥
  validUntil`, one fingerprint listed twice, one `ma_to_chuc` twice within a
  section, an empty issuer `vct`; a `signer_not_before` later than the signer
  certificate's notBefore (`claims`); a signer certificate whose notBefore is
  earlier than `minSignerNotBefore` (`not_trusted`).
- `signer_not_before` (ADR-0019 §2): after a trust-list signer is replaced, the server
  publishes lists carrying the new certificate's notBefore; the registry remembers
  the largest value of any verified list (and persists it with `seen`) and refuses
  lists of older signer certificates from then on.
- `createStatusListChecker({ fetch, verifier, chainValidator, trustRegistry, clock, maxAgeSeconds?, seen? })`
  (`StatusChecker`): refuses a non-https `uri` and an `idx` outside the list without a
  request; `GET` with `timeoutMs: 5000`, HTTP 200 only; caches per `uri` by the rules
  of section 5 (a list is verified for any trusted `status` signer whose organisation
  matches its trust list entry); every answer re-checks the signer against the trust
  list and against the caller's issuer organisation. Every failure is `'unavailable'`.
- `createSignedTrustListRegistry({ url, fetch, verifier, chainValidator, clock, maxAgeSeconds?, seen? })`
  (`TrustRegistry`): `lookup(fingerprint, at = clock.now())` gives the entry with the
  purpose of the matched certificate, `null` when absent or `at` is outside
  `[validFrom − 60 s, validUntil + 60 s]`; `refresh()`; `current()` (iat, exp, ttl,
  entry counts) for monitoring (ADR-0014 §7).
- `createMappedFetch(fetch, { 'https://api-identra.awncorp.vn': 'http://127.0.0.1:4000' })`:
  development and test deployments send network access for a canonical origin
  elsewhere; identifiers stay canonical. Only the exact origin followed by `/`, `?`,
  `#` or nothing is mapped. `init` (with `timeoutMs`) is passed unchanged: the
  wrapped fetch enforces the timeout and the size limit.

`sdk-server` (Node):

- `createFileKeyStore(dir)` reads the layout of `scripts/pki/make-demo-pki.sh`:
  `orgs/<name>/<purpose>.key.pem` + `.chain.pem` (purpose `vc` is the file `vc` or
  `vc-product`, exactly one of them), `trust-list-signer/trust-list.key.pem` +
  `.cert.pem`, `root.cert.pem` (+ `root2.cert.pem`). Names are lower-case words
  joined by hyphens; a key file is opened with `O_NOFOLLOW` and must be a regular
  file without group or other permissions (checked on the open descriptor); at load
  the chain must pass the core validator for the purpose's profile against the
  store's own roots at the current time (for `vc`, against the leaf's only SAN URI),
  and the key must match the leaf; keys are imported non-extractable.
- `createStatusListService({ issuerUri, keyStore, storage, random, clock })`:
  `allocate(issuer)` draws random indexes of the issuer's current list (64 draws),
  claims one with `storage.reserve`, which must be atomic (Postgres: unique key
  `(issuer, n, idx)`, `INSERT … ON CONFLICT DO NOTHING`), so two concurrent
  allocations never get one index, and only returns an index whose value is 0;
  when the draws fail it moves to list `n + 1` (created), and throws
  `StatusListFullError` only when that fails too. The current list number is kept
  in memory and starts at 1 after a restart. `setStatus` requires a reserved index
  (`StatusIndexNotAllocatedError`), uses `storage.save(…, expectedVersion)`
  (optimistic concurrency, 5 attempts), and keeps `revoked` final
  (`StatusRevokedError`). `token(issuer, n)` (`n` 1–999 999 999) is `null` for a
  list that does not exist (HTTP 404), is re-signed when the stored version changed
  or the token is an hour old, with `iat = max(now, lastIat + 1)` and `lastIat`
  stored with the list; at most 1000 tokens are cached. Bursts of more than one
  change per second make `iat` run ahead of the clock by that many seconds;
  beyond 60 s clients would refuse the list as `not_yet_valid`.
- `createTrustListService({ source, keyStore, clock, signerNotBefore?, lastToken?, onError? })`
  validates the source with the core validator and re-signs when it changed or
  after an hour, with `iat = max(now, lastIat + 1)`; `lastIat` is in memory and,
  after a restart, taken from `lastToken` when the server kept it (otherwise a
  restart within the same second as the last signature can repeat an `iat`, and
  clients then keep their copy until the next one). An invalid or failing source:
  the last good token is served unchanged until its `exp` and `onError` is called;
  with none, the call throws.
- `scripts/pki/make-trust-list-source.mjs <demo-pki-dir> [--out file]` writes the
  trust-list source of the demo organisations (`validFrom` = latest notBefore,
  `validUntil` = earliest notAfter of the organisation's certificates).

Known limitations:

- The trust-list signer is recognised only by being a CA:FALSE leaf signed directly
  by a pinned root; there is no dedicated extended key usage or policy OID for it
  yet (review F11). A future root-signed leaf for another purpose could therefore
  sign a trust list.
- A verifier that has never fetched a list (fresh install, empty `seen`) can be fed
  an older list still inside its 24 h, or a list of a replaced trust-list signer
  until that certificate expires, by an attacker who controls the connection
  (ADR-0019, "Giới hạn còn lại").

## 10. Product chain (GĐ6b, ADR-0012)

GS1 identifiers (`sdk-core`, `product/gs1.ts`; GS1 General Specifications 7.9.1,
3.5.2, figure 7.11-1; GS1 Digital Link URI syntax 4.2):

- GTIN: exactly 14 digits with a valid check digit (`gs1CheckDigit`: weights 3, 1,
  3, … from the right). Serial, AI (21): 1–20 characters of set 82; refused also
  when it contains `%` followed by two hex digits (it would look percent-encoded,
  so element string and path stay one-to-one) and when it is `.` or `..` (a dot
  segment to every URL parser).
- `parseProductCode('(01)<GTIN>(21)<serial>')` / `formatProductCode(gtin, serial)`;
  `parseDigitalLinkPath('/01/<GTIN>/21/<serial>')` / `formatDigitalLinkPath`.
  The path parser accepts only that exact form (no other AI, query, fragment,
  trailing slash, extra segment, at most 82 characters); a serial character is
  written raw only when it is `A–Z a–z 0–9 - . _`, every other set-82 character
  must be percent-encoded (either hex case), and an encoded raw character (`%41`)
  is refused. Parsers return `{ gtin, serial }` or `null`; formatters throw
  `TypeError`.

`productEventHash(compact, hasher)` = base64url(SHA-256(the exact compact string
including its trailing `~`)), the `prev` of the next event.

`verifyProductChain({ gtin, serial, events }, options)` (`options` = the
dependencies of `verifyStoredCredential` without `supportedVcts`, which is fixed to
the product-event `vct`) returns `{ ok, code, complete, events: [{ index, ok,
checks, event? }] }` and never throws for bad `events` (`TypeError` for an invalid
`gtin` / `serial` or options: parse the URL first).

1. Before any work: `events` not an array, empty, or with a non-string entry →
   `code: MALFORMED`; more than 20 entries or more than 20 × 16 384 characters in
   total → `code: TOO_LARGE`. Then `events: []`, nothing is hashed or fetched.
2. Events are verified one after another with `verifyStoredCredential`, so each
   status list and the trust list are fetched at most once per chain (the caches
   answer later events). Each event's checks are followed by `product_chain`.
3. `product_chain` is `SKIPPED` when the event's steps 1–4 failed. Otherwise the
   first rule broken gives its code:
   - `vct` is the product-event `vct` (`CHAIN_BROKEN`);
   - `ma_san_pham`, `cong_doan`, `thoi_diem`, `dia_diem`, `mo_ta` are strings of
     1–500 characters (`MALFORMED`: an issuer bypassing `issueProductEvent`);
   - `ma_san_pham` = `formatProductCode(gtin, serial)` of the page (`CHAIN_BROKEN`);
   - `cong_doan` is the stage of its position: index 0 `san_xuat`, 1 `kiem_dinh`,
     2 `phan_phoi`, nothing at index 3 or later. This one rule covers wrong order,
     repeats, a missing first stage, gaps and branching (`CHAIN_BROKEN`);
   - index 0 has no `prev` claim; index n > 0 has `prev` = `productEventHash` of
     entry n − 1 exactly as received, whatever that entry's own result
     (`CHAIN_BROKEN`);
   - `thoi_diem` is an ISO 8601 UTC instant naming a real date, and not earlier
     than that of entry n − 1 when entry n − 1 passed steps 1–4 with a valid
     `thoi_diem` (equal allowed; otherwise not compared) (`CHAIN_BROKEN`).
4. Consequences: a tampered event N fails its own steps 1–4 (`SIGNATURE_INVALID`
   or `MALFORMED`, `product_chain` `SKIPPED`, no `event`), and N + 1 is
   `CHAIN_BROKEN` because its `prev` no longer matches N's bytes. A revoked or
   suspended event N fails only its `status` check; N + 1 still links, so the page
   shows red at N only. A stage signed by an organisation whose trust list entry
   lacks that `cong_doan` fails `issuer_trust` (`ISSUER_NOT_TRUSTED`, step 7) and
   its status list is not fetched.
5. `event` = `{ congDoan, thoiDiem, diaDiem, moTa, maSanPham, issuer }` when steps
   1–4 passed and the five claims are strings of 1–500 characters, even when a
   later check failed (a revoked event is still shown, in red). Values are handed
   out verbatim: the SDK neither interprets nor strips HTML; the page renders them
   as text (ADR-0012 security requirement 2).
6. `complete` = exactly three events, each with `product_chain` ok. `code` =
   `CHAIN_BROKEN` when any `product_chain` check failed (not skipped), else
   `null`. `ok` = `complete` and every event ok. A correctly linked partial chain
   (1 or 2 events) has every event ok, `complete: false`, `code: null`, `ok:
   false`: a product mid-way, not an error.

Known limits: the status list's `iat` is not exposed (the `StatusChecker`
interface returns only the answer), so the "giờ máy chưa đúng" warning (ADR-0012
requirement 5) compares the local clock with `serverTime` of the product entry;
the checks prove the record, not the box in hand (ADR-0012 "Giới hạn đã biết").

`sdk-server` (`product-chain.ts`):

- `appendProductEvent({ previous?, signer, hasher, random, clock, iss, status,
  claims: { maSanPham, congDoan, thoiDiem, diaDiem, moTa } })` → compact. Reads
  `previous` without verifying it, computes `prev`, and throws `TypeError` for a
  stage that does not follow the previous one (`san_xuat` when there is none),
  another `maSanPham`, a `thoiDiem` that is not an ISO UTC instant or is earlier
  than the previous one; everything else is `issueProductEvent`'s checks.
- `checkProductEventForStorage({ gtin, serial, existing, candidate }, options)` →
  `{ ok: true } | { ok: false, code, checks }`: `verifyProductChain` of `existing +
  candidate`; ok when the candidate's event is ok. `code` is the chain-level code
  or the candidate's first failing check. Problems of earlier events (one revoked
  since) do not block the candidate.

`sdk-client/product` (separate entry; the main entry imports only types from
`sdk-core`, and a bundle test keeps it that way):
`createProductVerifier({ apiBaseUrl, canonicalApiOrigin = 'https://api-identra.awncorp.vn',
rootCertificates, fetch?, now? })` → `{ load(gtin, serial) }`. One chain validator
(pinned roots), signed trust list registry (`<canonical>/trust-list`) and status
checker per verifier, all on `createMappedFetch(canonical → apiBaseUrl)` over a
browser `HttpFetch` that enforces `timeoutMs` over the whole exchange, a body cap
of 20 × 16 384 + 4 096 bytes, `redirect: 'error'`, `credentials: 'omit'`,
`referrerPolicy: 'no-referrer'`, `cache: 'no-store'`. `load` GETs
`<canonical>/v1/products/<gtin>/<serial percent-encoded as in the Digital Link>/events`
(timeout 5 s), requires `{ gtin, serial, events: [] }` echoing the request, runs
`verifyProductChain` and returns `{ state: 'ok' | 'not_found' | 'network_error' |
'invalid_response', gtin, serial, result?, verifiedAt, serverTime? }` (404 →
`not_found`; other non-200, timeout, network or redirect → `network_error`;
oversized, non-JSON or wrong shape → `invalid_response`). `serverTime` comes from
the HTTP `Date` header, which a cross-origin page can read only when the API
sends `Access-Control-Expose-Headers: Date`. No request is made other than the
events, the trust list and the status lists the policy allows.

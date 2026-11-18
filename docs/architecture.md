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
| `@identra/sdk-server` | Node | Key store, OpenID4VCI issuer (section 8), status list and trust list signing (section 7), OpenID4VP verifier (section 9), product-chain append check (section 10) | `@openid4vc/openid4vci`, `@openid4vc/openid4vp`, `@openid4vc/oauth2`, `dcql`, `jose` |
| `@identra/sdk-app` | React Native, Node (simulated wallet) | `@noble` crypto adapters, JWE, `WalletKeyStore`, credential vault, backup catalogue, the wallet object: OpenID4VCI client (section 8), OpenID4VP wallet (section 9) | `@noble/curves`, `@noble/hashes`, `@noble/ciphers`, `@openid4vc/openid4vci`, `@openid4vc/openid4vp`, `@openid4vc/oauth2`, `dcql` |
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
// Implementations MUST enforce timeoutMs (reject when it passes) and maxBytes (default 262 144)
// and MUST NOT follow redirects: sdk-core has no timer and reads text() whole.
type HttpFetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number; maxBytes?: number })
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
| 8 | `status` | Only when steps 6 and 7 passed, otherwise `SKIPPED` and the `StatusChecker` is not called (no request on behalf of an untrusted issuer, nor for a credential of a type the caller does not support). Rules below, then the checker's answer: `valid` passes, `revoked` / `suspended` map to their codes, anything else or an exception is `STATUS_UNAVAILABLE` | `REVOKED`, `SUSPENDED`, `STATUS_UNAVAILABLE` |
| 9 | `holder_binding` | Always listed by `verifyPresentation`; listed by `verifyStoredCredential` when the compact carries disclosures. Disclosures (ADR-0008 §6), any failure `DISCLOSURE_INVALID`: a top-level `_sd` exists; each disclosure is `[salt, name, value]` with string salt and name (array-element disclosures are refused); name not `_sd`, `...`, `_sd_alg` nor a metadata claim (`iss`, `vct`, `iat`, `nbf`, `exp`, `cnf`, `status`); no duplicate disclosure; digest referenced by the top-level `_sd`; no two disclosures with one name; no clash with a visible payload claim; no `_sd`, `_sd_alg` or `...` key inside a disclosed value. In `verifyPresentation`, the KB-JWT, any failure `KB_INVALID`: present and at most 4 096 bytes; credential has a valid P-256 `cnf.jwk`; header `typ` `kb+jwt` and `alg` `ES256`; signature by `cnf.jwk`; `sd_hash` = base64url(SHA-256(`<jwt>~<disclosures>~`)) recomputed by the verifier; `iat` within [now − 300 s − 60 s, now + 60 s] (both ends inclusive); `exp`, when present, a number > now − 60 s; `nbf`, when present, a number ≤ now + 60 s. Then `nonce` (`NONCE_MISMATCH`), then `aud` (`AUD_MISMATCH`), so an unsigned KB-JWT never yields a mismatch | `DISCLOSURE_INVALID`, `KB_INVALID`, `NONCE_MISMATCH`, `AUD_MISMATCH` |
| 10 | `product_chain` | Only in `verifyProductChain` (section 10), listed last for every event (alone at index 3 and later); `SKIPPED` when steps 1–4 failed. The event is a product event of the product being viewed, at its stage position, linked by `prev` to the event before it as received, with a `thoi_diem` that is a valid ISO instant, not later than its own `iat` + 60 s and not earlier than the previous valid step; the five claims are strings of 1–500 characters (`MALFORMED` otherwise) | `CHAIN_BROKEN`, `MALFORMED` |

Other codes: `CLIENT_ID_MISMATCH`, `VERIFIER_NOT_TRUSTED` (wallet checking a
presentation request), `DID_RESOLUTION_FAILED`, `KEY_NOT_FOUND` (`did:jwk`
helper only; the credential path no longer resolves DIDs, ADR-0015), `SKIPPED`,
and the wallet operation codes of section 8 (`OFFER_INVALID`, `URL_NOT_ALLOWED`,
`TX_CODE_WRONG`, `OFFER_EXPIRED`, `NETWORK_ERROR`, `ISSUER_ERROR`,
`CREDENTIAL_INVALID`, `CNF_MISMATCH`, `CLAIMS_INCOMPLETE`, `STORAGE_ERROR`,
`CREDENTIAL_NOT_FOUND`).

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
  UTC instant (`YYYY-MM-DDTHH:MM:SS[.sss]Z`, `parseUtcInstant`) not later than
  the event's `iat` + 60 s; has `status`; no `exp`. The issuer refuses a
  `ma_san_pham` that `parseProductCode` refuses and a `thoi_diem` that is not
  such an instant or is later than the time of issuance + 60 s (section 10).
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
  The `sdk-app` bundle test also runs a whole issuance there (section 8) and
  pins the web globals the wallet needs.
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
- `signer_not_before` (ADR-0019 §2): the server publishes every list with its
  signer certificate's notBefore, so after a trust-list signer is replaced the lists
  carry the new certificate's notBefore; the registry remembers
  the largest value of any verified list (and persists it with `seen`) and refuses
  lists of older signer certificates from then on.
- `createStatusListChecker({ fetch, verifier, chainValidator, trustRegistry, clock, maxAgeSeconds?, seen? })`
  (`StatusChecker`): refuses a non-https `uri` and an `idx` outside the list without a
  request; the injected fetch decides which hosts are reachable at all (the wallet
  admits only `/status/<n>` URLs, the server answers only its own lists and refuses
  every other status URL itself); `GET` with `timeoutMs: 5000` and `maxBytes`,
  HTTP 200 only; caches per `uri` by the rules
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
  allocations never get one index, and only returns an index whose value is 0, as
  `{ uri, n, idx }`;
  when the draws fail it moves to list `n + 1` (created), and throws
  `StatusListFullError` only when that fails too. The current list number is kept
  in memory and starts at 1 after a restart. `setStatus(issuer, n, idx, status,
  { storage }?)` runs on `storage` instead of the service's when given (a storage
  bound to the caller's database transaction), requires a reserved index
  (`StatusIndexNotAllocatedError`), uses `storage.save(…, expectedVersion)`
  (optimistic concurrency, 5 attempts), and keeps `revoked` final
  (`StatusRevokedError`). `token(issuer, n)` (`n` 1–999 999 999) is `null` for a
  list that does not exist (HTTP 404), is re-signed when the stored version changed
  or the token is an hour old, with `iat = max(now, lastIat + 1)` and `lastIat`
  stored with the list; at most 1000 tokens are cached. Signing rules (both list
  services): a new `iat` is never more than 5 s ahead of the clock while a held
  token can be served — under a burst the held token is served and the changes
  appear at the next allowed signing, so after a quiet moment a single change is
  visible at once and under sustained bursts a change waits at most about one
  second (one signing per second); with nothing held (after a restart) up to 60 s
  ahead is accepted, the skew verifiers allow. A stored `lastIat` more than 60 s
  ahead is ignored (`onError('last_iat_in_future', issuer)`, once per list), and
  this process keeps its own last `iat` so tokens still never repeat one. Before
  signing, the status certificate must be inside its validity: otherwise
  (`onError('signer_expired', issuer)`) the held token is served until its `exp`,
  then `token` throws. `current(issuer, n)` gives `{ iat, exp, signerNotAfter }`
  of the held token, or null (ADR-0014 §7).
- `createTrustListService({ source, keyStore, clock, signerNotBefore?, lastToken?, onError?, lastIatStore? })`
  validates the source with the core validator and re-signs when it changed or
  after an hour, with `iat = max(now, lastIat + 1)`; `lastIat` is in memory and,
  after a restart, taken from `lastIatStore.get()` (read once before the first
  signature; `set(iat)` after each one, and a failing store fails the call) and
  from `lastToken` when the server kept it (with neither, a restart within the
  same second as the last signature can repeat an `iat`, and clients then keep
  their copy until the next one). An invalid or failing source: the last good
  token is served unchanged until its `exp` and `onError('source_invalid' |
  'source_threw')` is called; with none, the call throws `Error('trust list
  source_invalid' | 'trust list source_threw')`. Neither carries validator detail
  nor the source's own error, which could quote file content. The signing rules
  of the status list service apply (5 s lead, `last_iat_in_future` for a
  `lastToken` or stored `iat` more than 60 s ahead, `signer_expired` for a signer
  certificate outside its validity; the error thrown with nothing held is
  `Error('trust list <reason>')`). Every token carries `signer_not_before` = the
  signer certificate's notBefore (ADR-0019 §2: after a signer replacement, every
  client that fetched the new list refuses lists of older signer certificates);
  `signerNotBefore` overrides it and may not be later. `current()` gives `{ iat,
  exp, issuers, verifiers, signerNotAfter }` of the held token, or null (ADR-0014 §7).
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

## 8. Issuance: OpenID4VCI 1.0, pre-authorized code (GĐ5)

ADR-0010; the HTTP routes are those of `identra-server/docs/vc-api.md` section 4.
The `@openid4vc/*` libraries (0.10.0) are imported in one adapter per package
(`sdk-server/src/issuance/library.ts`, `sdk-app/src/wallet/library.ts`); they
build and parse (zod) the protocol messages, never decide.

### Protocol state (`sdk-server`)

```ts
interface ProtocolStateStore {            // the server implements it on Redis
  put(key, value: string, ttlSeconds): Promise<void>;     // SET EX
  get(key): Promise<string | null>;
  take(key): Promise<string | null>;                       // GETDEL: atomic get-and-delete
  increment(key, ttlSeconds): Promise<number>;             // INCR, EXPIRE NX on a new key
}
createMemoryStateStore(clock)             // tests and development
```

Keys are `vci:<issuerUri>:<kind>:<id>`. Every single-use value is consumed with
`take`, so of two concurrent requests at most one succeeds. Secret-bearing values
never appear in a key name: codes, token ids and nonces are keyed by
base64url(SHA-256(value)).

| Kind | Value | TTL |
|---|---|---|
| `offer:<offerId>` | offer JSON (with the code), subject, configuration, PIN HMAC, expiry | 600 s; taken when the code is redeemed, the offer destroyed or cancelled |
| `code:<sha256(code)>` | offerId | 600 s; taken by the one successful token request |
| `attempts:<offerId>` | PIN attempt counter | 600 s |
| `status:<offerId>` | subject, created, expiry (written once) | 1800 s from creation |
| `issued:<offerId>` / `ended:<offerId>` | credentialId / `1`: separate keys, so no update overwrites another; `issued` wins | until the status expires |
| `token:<sha256(jti)>` | offerId, subject, configuration | 300 s; taken by the one credential request |
| `nonce:<sha256(c_nonce)>` | `1` | 300 s; taken by the proof that names it |

### Issuer (`sdk-server`)

```ts
generateIssuerKeys(random): Promise<IssuerKeys>   // ES256 access-token key, ECDH P-256 request key, PIN HMAC key: in memory
createCredentialIssuer({
  issuerUri, display: { vi, en }, signer /* vc: x5c, SAN = issuerUri */, allocateStatus,
  hasher, verifier, random, clock, store, keys,
  credentials: { 'bang-tot-nghiep-v1': { resolveClaims(subjectRef), onIssued(event) } },
  lifetimes?: { offerSeconds, accessTokenSeconds, nonceSeconds },  // tests: shorter only, defaults are the bounds
}): CredentialIssuer
```

| Operation | Route (vc-api.md §4) | Returns |
|---|---|---|
| `metadata()` | `GET /.well-known/openid-credential-issuer/issuers/:name` | `HttpResponse` |
| `authorizationServerMetadata()` | `GET /.well-known/oauth-authorization-server/issuers/:name` | `HttpResponse` |
| `jwks()` | `GET /issuers/:name/jwks` | `HttpResponse` (access-token key only) |
| `createOffer({ subjectRef, configurationId })` | portal `POST /v1/demo/school/offers` | `{ offerId, offerUri, txCode, expiresAt }` |
| `offer(offerId)` | `GET /issuers/:name/offers/:offerId` | `HttpResponse`, 404 when expired, used or unknown |
| `cancelOffer(offerId)` | portal (e.g. a new offer replaces the old one) | the code stops working, status `expired`; harmless on a used or unknown offer |
| `offerStatus(offerId)` | portal `GET /v1/demo/school/offers/:offerId` | `{ status, subjectRef, credentialId? }` or null |
| `token(request)` | `POST /issuers/:name/token` | `HttpResponse` |
| `nonce()` | `POST /issuers/:name/nonce` | `HttpResponse` |
| `credential(request)` | `POST /issuers/:name/credential` | `HttpResponse` |

`HttpRequest` is `{ headers /* lower-case names */, body /* raw text */ }`,
`HttpResponse` is `{ status, headers, body /* text */ }`, sent unchanged. Bad input
never throws; it gets the OAuth error of the specification with a fixed
description of ours. A failing dependency (state store, callback, signer) throws.

- Metadata: issuer identifier with a path (well-known path insertion);
  `nonce_endpoint`; `credential_request_encryption` (one ECDH-ES key with `kid`)
  and `credential_response_encryption` (`ECDH-ES`; `A256GCM`, `A128GCM`), neither
  required; pre-authorized grant with anonymous access; display names in
  Vietnamese and English; the seven diploma claims with labels
  (`CREDENTIAL_CONFIGURATIONS`).
- Offer: by reference, `openid-credential-offer://?credential_offer_uri=<issuerUri>/offers/<offerId>`;
  offerId 128 bits, pre-authorized code 256 bits; 10 minutes. `tx_code` is 6
  digits, drawn without modulo bias (32-bit draws at or above 4 294 000 000 are
  drawn again), returned once, stored only as HMAC-SHA-256 under the issuer's
  256-bit PIN key, which lives in process memory only (`IssuerKeys.pinKey`), so
  the state store alone does not give the PIN away; compared with
  `timingSafeEqual`. Status readable 30 minutes.
- Token: form-encoded, no repeated parameter, `grant_type` present
  (`invalid_request`) and the pre-authorized code grant (`unsupported_grant_type`),
  code and `tx_code` present (`invalid_request`).
  Unknown, expired, used code or wrong PIN: `invalid_grant`, identical. Each
  attempt is counted (`increment`) before the comparison; attempt 6 and later
  are refused unseen, a wrong 5th attempt destroys the offer. The code is then
  `take`n: of concurrent requests with the right PIN exactly one gets a token.
  Access token: JWS `typ: at+jwt`, `kid`, `iss` = `aud` = issuerUri, `iat`, `exp`
  (300 s), random `jti`; one credential per token. Token responses carry
  `Cache-Control: no-store` and `Pragma: no-cache`.
- Nonce: 128-bit `c_nonce`, 300 s, single use, `Cache-Control: no-store`.
- Credential, in this order: access token (`Bearer`, signature by the in-memory
  key, `typ`, `kid`, `iss`, `aud`, `exp`, record present; else `401 invalid_token`
  with `WWW-Authenticate`); body ≤ 64 KB; the library parses and, for
  `application/jwt`, decrypts (jose, `ECDH-ES`, `A128GCM`/`A256GCM`, the
  advertised `kid` only); the draft-era singular `proof` member is refused
  (`invalid_credential_request`); `credential_configuration_id` = the token's; response
  encryption, when asked, needs an encrypted request, a valid P-256 public `jwk`
  with `alg: ECDH-ES` and `A256GCM`/`A128GCM` (`invalid_encryption_parameters`);
  exactly one `jwt` proof (`invalid_proof`); the proof (below); its `c_nonce`, of
  the form the issuer hands out (22 base64url characters), taken (`invalid_nonce`);
  the token taken (`invalid_token`). A failure up to
  here spends nothing but a taken nonce.
- Proof (`proof.ts`, our own code on `decodeJws` / `verifyJws`): ≤ 4 KB; `typ`
  `openid4vci-proof+jwt`; `alg` ES256; header `jwk` a valid on-curve P-256 public
  key with no private member and no `kid` / `x5c` / `x5u` / `jku` /
  `trust_chain` / `key_attestation` next to it, and no `alg` other than ES256,
  `use` other than `sig` or `key_ops` without `verify` inside it; signature by that key; `aud` = issuerUri (a
  string); `iat` within [now − 360 s, now + 60 s]; non-empty `nonce`.
- Order of effects after the token is taken: `resolveClaims` (null:
  `credential_request_denied`, nothing allocated) → `allocateStatus` →
  `issueDiploma` (`iss` = issuerUri, `cnf.jwk` = the proof key) → the response
  is built (and encrypted) → `onIssued({ offerId, subjectRef, statusUri,
  statusIdx, cnfThumbprint, issuedAt })` → offer status `issued` (a failure here
  is ignored: the credential exists and is recorded) → response. Anything that
  throws before `onIssued` returns leaves no record; the offer is not marked
  issued; an allocated status index stays reserved (never reused, never set);
  the token is spent, so the user scans a new offer.
- Restart: the three in-memory keys are generated at start; a restart
  invalidates outstanding tokens (≤ 300 s), the encryption key a wallet read just
  before, and the PINs of pending offers (≤ 10 minutes of offers: the user asks
  for a new one).

### Wallet (`sdk-app`)

```ts
createWallet({ keyStore, vault, fetch, random, clock, trustedRoots, trustListUrl,
               supportedVcts? /* [diploma] */, seen?, verifier? /* noble */, hasher? /* noble */,
               allowedOrigins? /* exact origins of offers and presentation requests */ })
wallet.offers.resolve(qrText) → { ok: true, offer: ResolvedOffer /* incl. issuerOrigin */ } | WalletFailure
wallet.offers.accept(offer, { txCode }) → { ok: true, credentialId, vct, issuerName, status: 'valid' | 'unknown' } | WalletFailure
wallet.credentials.list() → CredentialSummary[]            // metadata only, no decryption
wallet.credentials.get(id) → { ok: true, credential: CredentialDetails } | WalletFailure
wallet.credentials.refreshStatus(id) → { ok: true, status, checks } | WalletFailure
wallet.credentials.remove(id) → { ok: true } | WalletFailure   // row and key
// WalletFailure = { ok: false, code: WalletErrorCode, checks? }
```

`createWallet` builds the chain validator, the trust registry and the status
checker once. Network: every request goes through `guardFetch` (one wrapper):
https only, no userinfo, an allow-list, 10 s timeout (enforced with a timer and
passed down as `timeoutMs`), a 3xx is refused (never followed), response size
capped (`maxBytes` per call, never above the guard's ceiling: offer, metadata,
credential response and request object 64 KB, token and nonce responses and
the presentation response 16 KB, trust list 256 KB, status list 128 KB;
`Content-Length` first, then the text read), both passed down to the app's
fetch, which must abort the request at `timeoutMs` and stop reading at
`maxBytes` (the guard's own timer cannot stop a transfer; HttpFetch contract).
Hosts: https only, never an IP literal, `localhost` / `*.localhost`, a name
without a dot or ending in one; with `allowedOrigins`, offers and presentation
requests on any other origin are refused before any request. Protocol requests of an offer may reach only the
origin of its `credential_offer_uri`; list requests only the configured trust
list URL and URLs ending in `/status/<n>` (which the credential policy has
already reduced to `<iss>/status/<n>`).

- `resolve`: the QR text must be exactly `openid-credential-offer://?credential_offer_uri=<https URL>`
  (`OFFER_INVALID`; non-https `URL_NOT_ALLOWED`); offer 404 → `OFFER_EXPIRED`;
  `credential_issuer`, credential, nonce, token endpoints and authorization
  servers on the offer's origin (`URL_NOT_ALLOWED`); OpenID4VCI 1.0 metadata,
  one configuration, pre-authorized grant, request and response encryption with
  ECDH-ES, `dc+sd-jwt`, a supported `vct`, `jwt` proofs with ES256, `jwk`
  binding (`OFFER_INVALID`). No key is created and nothing is stored.
- `accept`: token with the PIN (`invalid_grant`: the offer is fetched again; still
  there → `TX_CODE_WRONG`, retryable on the same resolved offer; gone →
  `OFFER_EXPIRED`) → `c_nonce` → a NEW key from the key store (one per
  credential) → proof → credential request asking for a response encrypted to an
  ephemeral key from `RandomSource` (the library encrypts the request to the
  issuer and refuses a plain response) → exactly one credential string
  (`ISSUER_ERROR`) → `verifyStoredCredential` passes completely, or fails ONLY
  because the trust list (`issuer_trust` `TRUST_LIST_UNAVAILABLE`, `status`
  `SKIPPED`) or the status list (`STATUS_UNAVAILABLE`) could not be read — then
  the credential is kept with status `unknown` and `refreshStatus` settles it
  later (`CREDENTIAL_INVALID` with `checks` for anything else, an untrusted
  issuer included) → `iss` = the offer's issuer (`ISSUER_MISMATCH`) → `vct` = the
  configuration's → `cnf.jwk` thumbprint = the new key's (`CNF_MISMATCH`) → every
  claim of the type (`REQUIRED_CLAIMS`) is exactly one disclosure with a non-empty
  string value and absent from the plain payload, so it can be withheld
  (`CLAIMS_INCOMPLETE`) → `vault.save` and the status (`STORAGE_ERROR`). Any
  failure after the key was created deletes the key, but only once no row needs
  it: if a saved row cannot be removed, row and key are both kept.
- `remove` deletes the key first, then the row (`vault.removeWithKey`): a row
  without its key is detectable, a key without its row is not; calling it again
  completes an interrupted removal.
- `refreshStatus` re-runs `verifyStoredCredential`: `valid`, `revoked`,
  `suspended`, else `unknown` (status or trust list could not be checked, or
  another check failed; ADR-0013 section 4); cached in the vault row, where the
  column value is `unavailable` (the wallet API says `unknown` only).
- Key store: a `SecretStorageError` (`KEY_INVALIDATED`, `CANCELLED`, `LOCKED`)
  thrown by the app's storage adapter becomes a `WalletKeyError` of that code and
  then the wallet codes `KEY_INVALIDATED`, `USER_CANCELLED`, `DEVICE_LOCKED`;
  `KEY_NOT_FOUND` stays itself; anything else is `STORAGE_ERROR`.
- Codes (`WalletErrorCodes`, entries of `ErrorCodes`): `OFFER_INVALID`,
  `URL_NOT_ALLOWED`, `TX_CODE_WRONG`, `OFFER_EXPIRED`, `NETWORK_ERROR`,
  `ISSUER_ERROR`, `CREDENTIAL_INVALID`, `ISSUER_MISMATCH`, `CNF_MISMATCH`,
  `CLAIMS_INCOMPLETE`, `STORAGE_ERROR`, `CREDENTIAL_NOT_FOUND`, plus the key and
  presentation codes of section 9.

Known limitations:

- The access token is a bearer token, sent and returned in clear inside TLS. A
  party that reads the traffic between Cloudflare and the origin, or Cloudflare
  itself, sees the PIN, the pre-authorized code and the token and can win the
  race for the credential with a key of its own. ADR-0016 accepts for 12/12 that
  Cloudflare reads PINs and issuance codes; sender-constrained tokens (DPoP) and
  wallet attestation are GĐ8 items (ADR-0015).
- The offer record holds the pre-authorized code (it is served in the offer); a
  reader of the state store can redeem it only with the PIN, which needs the
  in-memory PIN key to check offline.
- A redirect followed by the app's own fetch is invisible to `guardFetch`; the
  app's `HttpFetch` must not follow redirects (React Native's fetch always does:
  open point for the app).
- Library schemas refuse some input before our checks: an unsigned proof JWT is
  `invalid_credential_request`, an http URL in issuer metadata is `ISSUER_ERROR`.
- Server-side key material (access-token key, request-encryption key, jose's
  ephemeral keys and IVs) comes from WebCrypto, not from the injected
  `RandomSource`; identifiers, codes, PINs, nonces and PIN keys do.

## 9. Presentation: OpenID4VP 1.0, cross-device, `direct_post.jwt` (GĐ6)

ADR-0011 (points 2, 3, 8 replaced by ADR-0015 sections 5 and 6), ADR-0008 sections
4–6; the HTTP routes are those of `identra-server/docs/vc-api.md` section 6.
Adapters: `sdk-server/src/presentation/library.ts` (`@openid4vc/openid4vp`,
`dcql`, `jose`) and `sdk-app/src/wallet/library.ts`.

### Verifier (`sdk-server`)

```ts
createPresentationVerifier({
  apiOrigin,                    // https://api-identra.awncorp.vn
  signer,                       // the `request` signer, x5c [leaf, issuing CA]
  verification: { verifier, hasher, chainValidator, trustRegistry, statusChecker, supportedVcts },
  random, clock, store,
  scenarios: { 'ung-tuyen': { vct, claimSets: [[...], [...]], purpose: { vi, en } } },
}): Promise<PresentationVerifier>
// .clientId, .name
// .createSession({ scenario }) → { id, requestId, qr, expiresAt, serverTime } | null (unknown scenario)
// .requestObject(requestId) → HttpResponse   GET  /oid4vp/request/:requestId
// .handleResponse(requestId, request) → HttpResponse   POST /oid4vp/response/:requestId
// .session(id) → SessionResource | null      GET  /v1/verification/sessions/:id
```

- Construction validates the request chain (profile `request`) and looks its
  fingerprint up in the trust list once: purpose `request` and the certificate's
  organisation, or it throws. `client_id` = `x509_hash:<fingerprint>`; `name` =
  the trust-list `ten`. The query of each scenario is built once (one `dc+sd-jwt`
  credential query `credential` of `vct`, one claim per name, `claim_sets` in
  order of preference, `credential_sets[0].purpose`) and validated by `dcql`; no
  HTTP input reaches it.
- Session: `id` and `requestId` independent 128-bit values; `nonce` and `state`
  256 bits; 5 minutes; an ephemeral ECDH P-256 key whose private JWK lives only in
  the state store (`key:<requestId>`, taken when the session is final). The
  request object is signed once by `signJws` (`typ: oauth-authz-req+jwt`, `x5c`
  from the signer): `response_type: vp_token`, `client_id`, `response_mode:
  direct_post.jwt`, `response_uri`, `nonce`, `state`, `dcql_query`,
  `client_metadata` (`jwks` with the session key, `alg: ECDH-ES`, `use: enc`, a
  `kid`; `encrypted_response_enc_values_supported` `A256GCM`, `A128GCM`;
  `vp_formats_supported`), `aud`, `iat`, `exp` (+300 s). QR:
  `openid4vp://?client_id=<client_id>&request_uri=<apiOrigin>/oid4vp/request/<requestId>`.
- `requestObject` serves the JWT until the session is final (then 404) and
  marks the session `request_retrieved`.
- `handleResponse`, in this order, anything wrong → `400 invalid_request` with a
  fixed description and nothing changes: request known and unexpired; form-encoded
  body ≤ 64 KB with exactly one parameter, `response`, holding a compact JWE (no
  `vp_token`/`state` in the clear, no signed-only JWT: no downgrade); the session
  key still there; the library decrypts (jose, ECDH-ES, A128GCM/A256GCM, that key
  only), checks `state` and parses `vp_token`; then the open marker is `take`n:
  exactly one response per session is processed, a concurrent or later one is
  400 and cannot touch the result. Processing: exactly one presentation for the
  one credential id (else a `structure` / `MALFORMED` result); `verifyPresentation`
  with `audience` = client_id and the session `nonce`; then `query`: `dcql`
  evaluates the VERIFIED claims against the query, the first satisfied claim set
  wins (`QUERY_NOT_SATISFIED` otherwise). The stored result is `{ ok, checks:
  [{ id, ok, code }], claims?, issuer?, verifiedAt }`: claims and issuer only when
  ok, claims = the string claims of the satisfied claim set only; any other
  disclosed claim is dropped, not stored and not a failure. Answer `200 {}`.
- `session(id)`: `status` = `verified` / `failed` from the result, else `expired`
  after 5 minutes, else `request_retrieved` / `pending`; `result` absent until
  final; `verifier.name`; `expiresAt` with `serverTime`. Deleted 30 minutes after
  creation, or after verification when that is later.

State: `vp:<client_id>:session:<id>` (1800 s, rewritten at verification),
`request:<requestId>`, `key:<requestId>`, `open:<requestId>` (300 s each),
`retrieved:<id>` and `result:<id>` (1800 s).

### Wallet (`sdk-app`)

```ts
wallet.presentations.resolve(qrText) → { ok: true, request: ResolvedPresentation } | WalletFailure
// ResolvedPresentation = { clientId, verifier: { trusted: true, ten, maToChuc } | { trusted: false },
//   warning?: 'VERIFIER_NOT_TRUSTED', purpose?, expiresAt,
//   matches: [{ credentialId, vct, issuerName, claimSets: [{ index, claims: string[] }] }] }
wallet.presentations.submit(request, { credentialId, claimSetIndex, allowUntrusted? }) → { ok: true } | WalletFailure
wallet.presentations.decline(request) → { ok: true }      // local only, no network call
```

- QR: exactly `openid4vp://?client_id=x509_hash:<43 base64url>&request_uri=<https URL>`
  and nothing else: no `request` by value, no `request_uri_method` (the library's
  POST body is wrong in 0.10.0, so GET only; pinned by a test), no other client
  identifier prefix (`REQUEST_INVALID`; non-https `URL_NOT_ALLOWED`).
- The request object is fetched with GET from the QR's origin only (64 KB). The
  library calls our check as its `verifyJws`; it decides, in order: `alg` ES256
  (`ALG_NOT_ALLOWED`); `typ` `oauth-authz-req+jwt`; `x5c` chain with profile
  `request` to the pinned root (`CERT_*`); signature (`SIGNATURE_INVALID`);
  `x509_hash:<fingerprint>` = QR `client_id` = JWT `client_id`
  (`CLIENT_ID_MISMATCH`); `response_mode` `direct_post.jwt`; `response_uri` https
  on the QR's origin (`URL_NOT_ALLOWED`); `nonce` ≥ 16 characters; `exp` >
  now − 60 s (`REQUEST_EXPIRED`), `iat` ≤ now + 60 s; exactly one ECDH-ES
  encryption key, a valid on-curve P-256 public JWK; `A256GCM` (preferred) or
  `A128GCM`; one `dc+sd-jwt` credential query whose claims are single top-level
  names. Anything else is `REQUEST_INVALID`. The library then checks the
  `x509_hash` itself (it demands a `getX509CertificateMetadata` callback that it
  does not use for that prefix: a stub, pinned by a test). Time checks use the
  injected clock.
- Trust: the fingerprint in the trust list with purpose `request` and the
  certificate's organisation → `verifier: { trusted: true, ten, maToChuc }`;
  absent → `{ trusted: false }` and `warning: VERIFIER_NOT_TRUSTED` (red warning,
  ADR-0011 point 3); no trust list → `TRUST_LIST_UNAVAILABLE` (fail closed).
- Matching: `dcql` over the vault's credentials of the query's `vct` values (the
  claims are the stored disclosures); per credential the satisfiable claim sets
  in the verifier's order. No matching credential → `matches: []`. Nothing is
  signed and no key is read in `resolve`.
- `submit`: `allowUntrusted: true` required for an untrusted verifier
  (`VERIFIER_NOT_TRUSTED`); request not expired on the wallet clock
  (`REQUEST_EXPIRED`); `createPresentation` with exactly the chosen claim set's
  names, KB-JWT `aud` = client_id, `nonce`, `iat` = now, signed by the
  credential's own key (where the platform prompts: `USER_CANCELLED`,
  `KEY_INVALIDATED`, `DEVICE_LOCKED`, `KEY_NOT_FOUND`, `STORAGE_ERROR`); JWE
  (noble, ECDH-ES, the verifier's `kid`) of `{ vp_token: { <id>: [presentation] },
  state }`; POST `response=<jwe>` form-encoded to `response_uri`; 200 → ok,
  anything else `VERIFIER_ERROR`. No other network call: the credential's status
  is not refreshed first. The verifier's verdict is not returned to the wallet
  (cross-device: the website shows it).

Known limitations:

- DCQL `claims` with nested paths, `values`, several credential queries or
  `credential_sets` options are refused by the wallet (`REQUEST_INVALID`); the
  Identra scenarios use none.
- `purpose` is the verifier's own text, shown as sent.

## 10. Product chain (GĐ6b, ADR-0012)

GS1 identifiers (`sdk-core`, `product/gs1.ts`; GS1 General Specifications 7.9.1,
3.5.2, figure 7.11-1; GS1 Digital Link URI syntax 4.2). Identra prints and accepts
exactly `/01/<GTIN-14>/21/<serial>`: lot or other key qualifiers, GTIN-8/12/13,
trailing slashes, raw sub-delimiters and lower-case percent-escapes are refused on
purpose, so each product has exactly one accepted path.

- GTIN: exactly 14 digits with a valid check digit (`gs1CheckDigit`: weights 3, 1,
  3, … from the right). Serial, AI (21): 1–20 characters of set 82; refused also
  when it contains `%` followed by two hex digits (it would look percent-encoded,
  so element string and path stay one-to-one) and when it is `.` or `..` (a dot
  segment to every URL parser).
- `parseProductCode('(01)<GTIN>(21)<serial>')` / `formatProductCode(gtin, serial)`;
  `parseDigitalLinkPath('/01/<GTIN>/21/<serial>')` / `formatDigitalLinkPath`.
  The path parser accepts only what the formatter writes (at most 82 characters):
  a serial character is raw only when it is `A–Z a–z 0–9 - . _`, every other
  set-82 character is an upper-case percent-escape, and an escape of a raw
  character (`%41`) is refused. Parsers return `{ gtin, serial }` or `null`;
  formatters throw `TypeError`.

`productEventHash(compact, hasher)` = base64url(SHA-256(the exact compact string
including its trailing `~`)), the `prev` of the next event (a fixed test vector
pins the wire format).

`verifyProductChain({ gtin, serial, events }, options)` (`options` = the
dependencies of `verifyStoredCredential` without `supportedVcts`, which is fixed to
the product-event `vct`) never throws for bad `events` (`TypeError` for an invalid
`gtin` / `serial` or options: parse the URL first) and returns:

```ts
interface ProductChainResult {
  state: 'verified' | 'in_progress' | 'failed';   // the one verdict a page uses
  ok: boolean;                                     // state === 'verified'
  complete: boolean;                               // state === 'verified'
  code: ErrorCode | null;                          // null unless failed (see 6)
  missingStages: CongDoan[];                       // the stages to come when in_progress, else []
  events: Array<{ index: number; ok: boolean; checks: Check[]; event?: ProductEventView }>;
}
interface ProductEventView { congDoan; thoiDiem; diaDiem; moTa; maSanPham: string; issuer: { maToChuc; ten } }
```

1. Before any work: `events` not an array, empty, or with a non-string entry →
   `MALFORMED`; more than 20 entries or more than 20 × 16 384 characters in total
   → `TOO_LARGE`. Then `state: 'failed'`, `events: []`, nothing is hashed or fetched.
2. Events are verified one after another with `verifyStoredCredential`, so each
   status list and the trust list are fetched at most once per chain (the caches
   answer later events). Each event's checks are followed by `product_chain`. An
   event at index 3 or later has only `product_chain` `CHAIN_BROKEN` (no stage
   exists after `phan_phoi`): it is not parsed, hashed or verified.
3. `product_chain` is `SKIPPED` when the event's steps 1–4 failed. Otherwise the
   first rule broken gives its code:
   - `vct` is the product-event `vct` (`CHAIN_BROKEN`);
   - `ma_san_pham`, `cong_doan`, `thoi_diem`, `dia_diem`, `mo_ta` are strings of
     1–500 characters (`MALFORMED`: an issuer bypassing `issueProductEvent`);
   - `ma_san_pham` = `formatProductCode(gtin, serial)` of the page (`CHAIN_BROKEN`);
   - `cong_doan` is the stage of its position: index 0 `san_xuat`, 1 `kiem_dinh`,
     2 `phan_phoi`. This one rule covers wrong order, repeats, a missing first
     stage, gaps and branching (`CHAIN_BROKEN`);
   - index 0 has no `prev` claim; index n > 0 has `prev` = `productEventHash` of
     entry n − 1 exactly as received, whatever that entry's own result
     (`CHAIN_BROKEN`);
   - `thoi_diem` is an ISO 8601 UTC instant naming a real date (years 0000–9999),
     not later than the event's own `iat` + 60 s (and `iat` is at most now + 60 s,
     step 5), and not earlier than the `thoi_diem` of entry n − 1 when that
     entry's own `product_chain` passed (equal allowed; otherwise not compared, so
     a broken or future-dated step never blocks the honest steps after it)
     (`CHAIN_BROKEN`). There is no lower bound.
4. Consequences: a tampered event N fails its own steps 1–4 (`SIGNATURE_INVALID`
   or `MALFORMED`, `product_chain` `SKIPPED`), and N + 1 is `CHAIN_BROKEN` because
   its `prev` no longer matches N's bytes. A revoked or suspended event N fails
   only its `status` check; N + 1 still links, so the page shows red at N only. A
   stage signed by an organisation whose trust list entry lacks that `cong_doan`
   fails `issuer_trust` (`ISSUER_NOT_TRUSTED`, step 7) and its status list is not
   fetched; so does a stage of a credential type other than the product event
   (`credential_type`, step 6).
5. `event` is returned only when every check but `status` passed: steps 1–7 and
   `product_chain` ok, `status` ok or `REVOKED` / `SUSPENDED` /
   `STATUS_UNAVAILABLE` (a revoked step is shown in red, with who signed it).
   Text of an untrusted issuer, of an organisation removed from the trust list, or
   of a broken link is never handed out. Values are verbatim: the SDK neither
   interprets nor strips HTML; the page renders them as text (ADR-0012 security
   requirement 2).
6. `state`: `verified` = three events, every event ok; `in_progress` = one or two
   events, every event ok (a correct prefix: a product mid-way, not an error;
   `missingStages` lists the rest); `failed` = anything else, with `code` the
   list-level code of 1 or else the first failing check's code of the first
   failing event.

`sdk-server` (`product-chain.ts`):

- `appendProductEvent({ gtin, serial, existing, signer, hasher, random, clock, iss,
  status, claims: { congDoan, thoiDiem, diaDiem, moTa }, verify })` → compact.
  Runs `verifyProductChain` on `existing` first (with `verify`) and throws
  `ProductChainRefusedError { index, code }` unless every stored event is fully
  ok: a forged, broken, revoked, suspended or unverifiable predecessor is never
  extended, and a complete chain is refused with index 3 and `CHAIN_BROKEN`
  (index `null` for a list-level code). Then `TypeError` for a stage that is not
  the next one or a `thoiDiem` earlier than the last stored one; `ma_san_pham`
  comes from `gtin` / `serial`, `prev` from the last stored compact, and
  `issueProductEvent` checks the rest.
- `checkProductEventForStorage({ gtin, serial, existing, candidate }, options)` →
  `{ ok: true } | { ok: false, code, index, checks }`: `verifyProductChain` of
  `existing + candidate` must be `in_progress` or `verified`, i.e. the stored
  events fully ok and the candidate extending them. Otherwise the first failing
  event (stored or candidate) with its first failing code and its checks; `index`
  `null` and no checks for a list-level code.

`sdk-client/product` (separate entry; the main entry imports only types from
`sdk-core`, and a bundle test keeps it that way):
`createProductVerifier({ apiBaseUrl, canonicalApiOrigin = 'https://api-identra.awncorp.vn',
rootCertificates, fetch?, now? })` → `{ load(gtin, serial) }`. One chain validator
(pinned roots), signed trust list registry (`<canonical>/trust-list`) and status
checker per verifier, on `createMappedFetch(canonical → apiBaseUrl)` over a
browser `HttpFetch` that enforces `timeoutMs` over the whole exchange, a body cap
of 20 × 16 384 + 4 096 bytes, `redirect: 'error'`, `credentials: 'omit'`,
`referrerPolicy: 'no-referrer'`, `cache: 'no-store'`. The registry and the checker
get a fetch that refuses, before any mapping, every URL other than
`<canonical>/trust-list` and `<canonical>/issuers/…`: a trusted certificate whose
SAN (and so `iss` and status URI) names another host causes no request there
(`STATUS_UNAVAILABLE`). `load` GETs `<canonical>/v1/products/<gtin>/<serial
percent-encoded as in the Digital Link>/events` (timeout 5 s), requires `{ gtin,
serial, events: [], serverTime? }` echoing the request, runs `verifyProductChain`
and returns `{ state: 'ok' | 'not_found' | 'network_error' | 'invalid_response',
gtin, serial, result?, verifiedAt, serverTime?, clockSkewSeconds? }` (404 →
`not_found`; other non-200, timeout, network or redirect → `network_error`;
oversized, non-JSON, wrong shape or a `serverTime` that is not a `parseUtcInstant`
instant → `invalid_response`). `serverTime` (the store's clock, from the envelope)
and `clockSkewSeconds` (local now − serverTime) are a hint only, for the "giờ máy
chưa đúng" message (ADR-0012 requirement 5) next to certificates that look not yet
valid or a trust list that looks expired; no check uses them (the status list's
`iat` is not exposed by the `StatusChecker` interface).

Known limits:

- Replay and truncation by the store are undetectable by design: the store
  chooses which events it returns, so it can serve an older valid chain or drop
  the latest events, and the page then shows an earlier state (`in_progress`).
  It cannot hide a revocation this way: status lists are fetched and verified
  separately.
- A copied QR: the chain proves the record, not the box in hand (ADR-0012 "Giới
  hạn đã biết").
- No binding between a GTIN company prefix and an organisation: any organisation
  allowed to sign `san_xuat` can start a chain for any GTIN. To be closed with a
  `gtin_prefix` scope in the trust list.
- ECDSA signatures are malleable ((r, s) and (r, n − s) both verify): anyone can
  re-encode event N into different bytes that still verify, and N + 1's `prev`
  then no longer matches, so the blame lands on N + 1 (`CHAIN_BROKEN`).
- The product entry bundle is 684 KB minified (168 KB gzip), two thirds of it
  `zod` pulled in by `@owf/token-status-list` (ADR-0017).

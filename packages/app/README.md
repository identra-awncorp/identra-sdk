# @identra/sdk-app

Wallet building blocks for the Identra app (React Native 0.85 / Hermes) and for the simulated
wallet used in Node end-to-end tests. Pure JavaScript on `@noble/curves`, `@noble/hashes` and
`@noble/ciphers`, plus `@openid4vc/*` 0.10.0 and `dcql` for the protocols; no `crypto.subtle`,
`Buffer`, `process`, global `fetch` or Node built-in. Only ES256 (P-256) exists.

- `nobleVerifier`, `nobleHasher`, `createNobleSigner`, `generateSecretKey`: the `Verifier` /
  `Hasher` / `Signer` contracts of `@identra/sdk-core` (docs/architecture.md section 2). The
  verifier accepts low-S and high-S and never throws; the signer is deterministic (RFC 6979) and
  returns low-S r||s.
- `createDerSigningAdapter`: wraps a hardware keystore that returns DER signatures.
- `encryptJwe`, `decryptJwe`: compact JWE, `ECDH-ES` with `A128GCM` / `A256GCM`, for OpenID4VCI
  response encryption and OpenID4VP `direct_post.jwt`.
- `createSoftwareKeyStore`: `WalletKeyStore`, one P-256 key per credential (ADR-0009).
- `createCredentialVault`: credentials sealed with AES-256-GCM in a `credentials` table
  (`CREDENTIALS_TABLE_DDL`).
- `buildCatalogue`, `serializeCatalogue`, `parseCatalogue`, `diffCatalogue`, `mergeCatalogue`: the
  backup catalogue (document type and issuer only).
- `createWallet`: the wallet object (docs/architecture.md section 8). `wallet.offers.resolve` /
  `accept` receive a credential over OpenID4VCI 1.0 (pre-authorized code, PIN, encrypted request
  and response) and store it only after `verifyStoredCredential` passes, the issuer matches the
  offer and `cnf.jwk` is the new key; `wallet.credentials.list` / `get` / `refreshStatus` /
  `remove` (status `valid` / `revoked` / `suspended` / `unknown` / `invalid`; `refreshStatus` also
  returns the checks, `checkedAt` and `lastValidAt`). `accept` failures say whether the same offer can
  still complete (`retryable`): after the PIN was accepted, a cancelled biometric prompt, a locked
  device, a request with no answer or a failing vault write is resumed by calling `accept` again on the
  same resolved offer (the PIN is not needed again); call `offers.discard(offer)` when the user gives up.
  The `credentials` table's CHECK constraint gained `invalid`: recreate an existing table;
  `wallet.presentations.resolve` / `submit` / `decline` answer an OpenID4VP 1.0 request
  (section 9). Failures are `{ ok: false, code }` with a code of `WalletErrorCodes`. `submit` failing
  with `{ ok: false, code: 'DID_RESOLUTION_UNAVAILABLE', delivered: true }` (only for a credential of
  the DID path in a wallet with `dpki`: the verifier could not reach its issuer registry now) means
  the verifier RECEIVED the presentation: record it in the sharing history. The request stays usable,
  pinned to that choice: offer "try again in a moment" and call `submit` again with the SAME
  `credentialId` and `claimSetIndex` (a fresh presentation of the same claims is signed and sent);
  any other choice is `REQUEST_INVALID` and forgets that object without sending anything. The pin
  belongs to the request (the QR's `client_id` and `request_uri`), not to the object: for 600 s
  from the delivery, every `resolve` of the same QR by this wallet instance (a remounted screen, the
  "open request" button again, a `decline` then a re-scan) returns
  `pinned: { credentialId, claimSetIndex, sends }` (else `pinned: null`): show the locked retry
  screen with only that choice. At most `MAX_PRESENTATION_SENDS` (3) sends per request in all, so only
  the 503s that answer the first two say "try again" (`DID_RESOLUTION_UNAVAILABLE`); the 503 that
  answers the third send is already `VERIFIER_ERROR`, and `resolve` of that QR is then `REQUEST_INVALID`. At most
  `MAX_PRESENTATION_PINS` (32) pins are held at once. The memory is in the wallet instance only:
  after a restart the same QR resolves unpinned; to keep the lock across restarts, use the sharing
  history record (QR `request_uri`, verifier, credential, claim set, time). The same 503 for an
  X.509 credential, or in a wallet without `dpki`, is `VERIFIER_ERROR`.

## What the app provides

| Interface | React Native | Node / tests |
|---|---|---|
| `RandomSource` (`bytes(n)`) | `expo-crypto` `getRandomValues(new Uint8Array(n))` (not `getRandomBytes`, which can fall back to `Math.random` in development builds on the old bridge) | `webCryptoRandom` from `@identra/sdk-core/webcrypto` |
| `SecretStorage` for wallet keys | `expo-secure-store`, `requireAuthentication: true`, a this-device-only keychain class | `createInMemorySecretStorage()` |
| `SecretStorage` for the vault data key | `expo-secure-store` WITHOUT `requireAuthentication`, readable while the device is unlocked, this device only | `createInMemorySecretStorage()` |
| `CredentialRepository` | `expo-sqlite`, table from `CREDENTIALS_TABLE_DDL` | `createInMemoryCredentialRepository()` |
| `Clock` (`now()`) | `{ now: () => new Date() }` | a fixed clock |
| `HttpFetch` for `createWallet` | `expo/fetch` with `redirect: 'manual'` (or `'error'`), honouring `timeoutMs` and `maxBytes` | global `fetch` with `redirect: 'manual'`, `createMappedFetch` for a local server |

Wrap `expo/fetch` on React Native, not the built-in fetch: the built-in one always follows
redirects and has no body stream to stop a large response early; `expo/fetch` honours `redirect`
and streams the body. The app's fetch must abort the request when `timeoutMs` passes (the body read
included) and stop reading as soon as the body passes `maxBytes`: the wallet's own timer and size
check cannot stop a transfer that the fetch keeps reading. The wallet wraps the app's fetch once (https only, the QR's origin only,
10 s timeout, no redirect, `maxBytes` per call: 64 KB for offers, metadata, credential responses and
request objects, 16 KB for token, nonce and presentation responses, 128 KB for a status list, 256 KB
for the trust list) and passes `timeoutMs` and `maxBytes` down; it cannot see a redirect the app's
fetch followed by itself. It never contacts an IP literal, `localhost` or a host without a dot;
set `allowedOrigins: ['https://api-identra.awncorp.vn']` in `createWallet` so that QR codes naming
any other origin are refused before any request.

DID trust path (ADR-0020, docs/architecture.md section 11): pass `dpki: { resolver, trustRegistry }`
to `createWallet`, built by the app from the deployment's gateway URL and network with
`createCertNetDidResolver({ gatewayUrl, network, fetch, clock })` and
`createCertNetTrustRegistry({ gatewayUrl, network, fetch })` of `@identra/sdk-core` (the same
`HttpFetch` rules apply; the gateway must allow CORS on its two read routes for the web wallet).
Pass `dpki.network` too (the network the resolver was built for): an offer declaring a DID of another
network is then `TRUST_PATH_UNSUPPORTED` at `resolve`, before the PIN is used.
Without `dpki`, offers of DID issuers are refused at `resolve` with `TRUST_PATH_UNSUPPORTED` (a
malformed `identra_issuer_did`, or one longer than `MAX_DID_LENGTH` = 128 characters, is `OFFER_INVALID`), and `refreshStatus` of a DID credential stored
earlier is `unknown`. `ResolvedOffer.issuerDid` is the DID the issuer's metadata declares, not yet
verified, or null for an X.509 issuer: show it instead of the self-declared display name. A credential of that path is stored with
`issuer_did`: add the nullable column to an existing table (`ALTER TABLE credentials ADD COLUMN
issuer_did TEXT`) and store it in `insert`; rows without it read as X.509. Views carry `trustPath`
and `issuerDid`; on the DID path `issuerName` is always null: show the shortened DID, never the
issuer's web origin as a name.

The data key must not require biometrics: ADR-0009 section 3 asks only that it be readable while
the device is unlocked, and on Android a biometric re-enrolment permanently invalidates a key
created with `requireAuthentication`, which would make every credential unreadable. The
per-credential signing keys do require biometrics.

`SecretStorage.get` must resolve `null` only when the item does not exist and should reject when
the storage cannot be read (device locked, prompt cancelled). Reject with
`new SecretStorageError('KEY_INVALIDATED' | 'CANCELLED' | 'LOCKED')` when the platform says why
(Android key invalidated by a biometric change, prompt dismissed, device locked): the key store
reports that code (`WalletKeyError`) and the wallet maps it to `KEY_INVALIDATED`, `USER_CANCELLED`
or `DEVICE_LOCKED`; a hardware signer may reject `sign()` the same way.
`vault.dataKeyState()` (never writes) and `vault.getMeta(id)` (no decryption) replace reading
`DATA_KEY_NAME` or the repository directly. The vault no longer trusts a `null`
blindly: only `save()` into an empty repository creates the data key; with rows present a missing
key is `DATA_KEY_MISSING` and nothing is written. Use one vault per data-key storage (concurrent
first saves are serialised per `SecretStorage` object).

The SQLite file must be excluded from the phone backup; the serialized catalogue goes into a file
that is backed up (ADR-0009 section 5). On a restored phone the rows come back without the data
key: the vault reports `DATA_KEY_MISSING`; once the app has decided with the user that this is a
new device, call `resetForNewDevice()`, then `diffCatalogue` to list the documents to request
again. Back up `mergeCatalogue(previous, vault.list(), removed)` after every change, not
`buildCatalogue(vault.list())`: on a restored phone the first document received again must not
drop the others still to request. `purgeUndecryptable()` deletes only rows sealed under a different data key and returns the
rows that fail for any other reason, which it keeps.

`remove()` deletes the row and leaves its wallet key in secure storage; prefer
`removeWithKey()`, which deletes the key first and the row second, so that an interrupted removal
leaves a detectable keyless row (call it again to finish) rather than an orphaned key. iOS keychain items survive an uninstall of the app.

## Globals React Native must provide

Measured by `test/bundle.test.ts`, which runs a whole issuance (`offers.resolve` + `accept`) and a
presentation (`presentations.resolve` + `submit`) from an esbuild `--platform=neutral` bundle in a
`node:vm` realm with no `crypto`, `Buffer`, `process` or `fetch`, and checks that the flow fails
without each of these:

| Global | Needed by |
|---|---|
| `TextEncoder`, `TextDecoder` | `@sd-jwt/*`, the OpenID4VC libraries (Hermes in RN 0.85 has no `TextDecoder`: polyfill) |
| `atob` | zod inside the OpenID4VC libraries (base64 checks, e.g. the request object's `x5c`) |
| `URL`, `URLSearchParams` | the OpenID4VC libraries (read at load: the bundle does not load without `URL`), the wallet's origin checks |
| `Headers`, `Response` | the fetch layer of the OpenID4VC libraries |
| `setTimeout`, `clearTimeout` | the wallet's request timeout |

React Native's own `URL` is incomplete; install a full polyfill (e.g. `react-native-url-polyfill`)
and check `new URL(u).origin` on the device. `globalThis.crypto` is referenced (noble's default RNG
and the libraries' defaults) but never read or called: every random byte comes from the injected
`RandomSource`. Minified size of the main entry: about 990 KB (sdk-app 35 KB, `@noble/*` 50 KB,
`@openid4vc/*` 126 KB, zod 454 KB, the rest sdk-core, `dcql` and their dependencies).
`AbortSignal` is referenced by `@openid4vc/openid4vp` but not needed by the wallet's flows.

## Randomness

All randomness comes from the injected `RandomSource`; sdk-app code never reads a global RNG, and
no sdk-app operation calls `crypto.getRandomValues` (tested with a counting `crypto` object). This
holds for sdk-app code and its operations only: noble's prebuilt curve modules, pulled in by
sdk-core's dependencies, touch `globalThis.crypto` when they are imported under a bundler that
does not tree-shake (Metro). Every draw refuses all-equal output and a repeat of the previous
block (`RandomSourceError`); that catches the typical broken polyfill, it is not a health test.

## Side channels

Scalar multiplication runs a fixed number of point operations with an oblivious table scan, and
modular inversion uses Fermat's method. Blinding is off. No nonce-length timing dependence was
measured on V8 for signing; ECDH timing depends on scalar length, which is harmless for ephemeral
keys and constant for a static key. JavaScript BigInt arithmetic and Hermes are not constant-time
and Hermes is unmeasured. There is no protection against power or EM analysis. Secret keys exist
as JavaScript strings and BigInts until garbage collection. The residual risk is low next to
memory disclosure of the software-stored key.

## Status

Tested on Node 24 and in a `node:vm` realm that has only ECMAScript built-ins plus the globals
listed above. **Not yet run on a physical device or emulator.** A hardware-backed
`WalletKeyStore` (Secure Enclave / StrongBox) is a later drop-in behind the same interface.

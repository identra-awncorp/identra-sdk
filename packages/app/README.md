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
- `buildCatalogue`, `serializeCatalogue`, `parseCatalogue`, `diffCatalogue`: the backup
  catalogue (document type and issuer only).
- `createWallet`: the wallet object (docs/architecture.md section 8). `wallet.offers.resolve` /
  `accept` receive a credential over OpenID4VCI 1.0 (pre-authorized code, PIN, encrypted request
  and response) and store it only after `verifyStoredCredential` passes, the issuer matches the
  offer and `cnf.jwk` is the new key; `wallet.credentials.list` / `get` / `refreshStatus` /
  `remove`. Failures are `{ ok: false, code }` with a code of `WalletErrorCodes`.

## What the app provides

| Interface | React Native | Node / tests |
|---|---|---|
| `RandomSource` (`bytes(n)`) | `expo-crypto` `getRandomBytes` | `webCryptoRandom` from `@identra/sdk-core/webcrypto` |
| `SecretStorage` for wallet keys | `expo-secure-store`, `requireAuthentication: true`, a this-device-only keychain class | `createInMemorySecretStorage()` |
| `SecretStorage` for the vault data key | `expo-secure-store` WITHOUT `requireAuthentication`, readable while the device is unlocked, this device only | `createInMemorySecretStorage()` |
| `CredentialRepository` | `expo-sqlite`, table from `CREDENTIALS_TABLE_DDL` | `createInMemoryCredentialRepository()` |
| `Clock` (`now()`) | `{ now: () => new Date() }` | a fixed clock |
| `HttpFetch` for `createWallet` | `expo/fetch` (streams the body), `redirect: 'manual'`, honouring `timeoutMs` | global `fetch` with `redirect: 'manual'`, `createMappedFetch` for a local server |

The wallet wraps the app's fetch once (https only, the offer's origin only, 10 s timeout, no
redirect, 64 KB for protocol messages and 256 KB for the trust list). It cannot see a redirect the
app's fetch followed by itself, so that fetch must not follow redirects; React Native's built-in
fetch always follows them, which is an open point for the app.

The data key must not require biometrics: ADR-0009 section 3 asks only that it be readable while
the device is unlocked, and on Android a biometric re-enrolment permanently invalidates a key
created with `requireAuthentication`, which would make every credential unreadable. The
per-credential signing keys do require biometrics.

`SecretStorage.get` must resolve `null` only when the item does not exist and should reject when
the storage cannot be read (device locked, prompt cancelled). The vault no longer trusts a `null`
blindly: only `save()` into an empty repository creates the data key; with rows present a missing
key is `DATA_KEY_MISSING` and nothing is written. Use one vault per data-key storage (concurrent
first saves are serialised per `SecretStorage` object).

The SQLite file must be excluded from the phone backup; the serialized catalogue goes into a file
that is backed up (ADR-0009 section 5). On a restored phone the rows come back without the data
key: the vault reports `DATA_KEY_MISSING`; once the app has decided with the user that this is a
new device, call `resetForNewDevice()`, then `diffCatalogue` to list the documents to request
again. `purgeUndecryptable()` deletes only rows sealed under a different data key and returns the
rows that fail for any other reason, which it keeps.

`remove()` deletes the row and leaves its wallet key in secure storage; prefer
`removeWithKey()`. iOS keychain items survive an uninstall of the app.

## Globals React Native must provide

Measured by `test/bundle.test.ts`, which runs a whole issuance (`offers.resolve` + `accept`) from
an esbuild `--platform=neutral` bundle in a `node:vm` realm with no `crypto`, `Buffer`, `process`
or `fetch`, and checks that the issuance fails without each of these:

| Global | Needed by |
|---|---|
| `TextEncoder`, `TextDecoder` | `@sd-jwt/*`, the OpenID4VC libraries (Hermes in RN 0.85 has no `TextDecoder`: polyfill) |
| `atob` | zod inside the OpenID4VC libraries (base64 checks) |
| `URL`, `URLSearchParams` | the OpenID4VC libraries (read at load: the bundle does not load without `URL`), the wallet's origin checks |
| `Headers`, `Response` | the fetch layer of the OpenID4VC libraries |
| `setTimeout`, `clearTimeout` | the wallet's request timeout |

React Native's own `URL` is incomplete; install a full polyfill (e.g. `react-native-url-polyfill`)
and check `new URL(u).origin` on the device. `globalThis.crypto` is referenced (noble's default RNG
and the libraries' defaults) but never read or called: every random byte comes from the injected
`RandomSource`. Minified size of the main entry: about 860 KB (sdk-app 26 KB, `@noble/*` 50 KB,
`@openid4vc/*` 84 KB, zod 454 KB, the rest sdk-core and its dependencies).

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

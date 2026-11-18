# @identra/sdk-app

Wallet building blocks for the Identra app (React Native 0.85 / Hermes) and for the simulated
wallet used in Node end-to-end tests. Pure JavaScript on `@noble/curves`, `@noble/hashes` and
`@noble/ciphers`; no `crypto.subtle`, `Buffer`, `process`, `fetch` or Node built-in. Only ES256
(P-256) exists.

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

## What the app provides

| Interface | React Native | Node / tests |
|---|---|---|
| `RandomSource` (`bytes(n)`) | `expo-crypto` `getRandomBytes` | `webCryptoRandom` from `@identra/sdk-core/webcrypto` |
| `SecretStorage` (`get`, `set`, `delete`) | `expo-secure-store`, `requireAuthentication: true`, a this-device-only keychain class | `createInMemorySecretStorage()` |
| `CredentialRepository` | `expo-sqlite`, table from `CREDENTIALS_TABLE_DDL` | `createInMemoryCredentialRepository()` |
| `Clock` (`now()`) | `{ now: () => new Date() }` | a fixed clock |

`SecretStorage.get` must resolve `null` only when the item does not exist and must reject when
the storage cannot be read (device locked, biometric prompt cancelled). The vault treats `null`
as "no data key yet" and creates a new one, which makes every stored credential unreadable. The
key store and the vault may be given different `SecretStorage` instances (for example the data
key without a biometric prompt per read).

The SQLite file must be excluded from the phone backup; the serialized catalogue goes into a file
that is backed up (ADR-0009 section 5). After a restore, call `purgeUndecryptable()`, then
`diffCatalogue` to list the documents to request again.

## Globals React Native must provide

The sdk-app code itself needs none beyond ECMAScript (with `BigInt`). The bundle includes the
whole `@identra/sdk-core` main entry, whose dependencies reference `TextEncoder` and
`TextDecoder`; Hermes in RN 0.85 has no `TextDecoder`, so install a polyfill at start-up. The
bundle test (`test/bundle.test.ts`) lists every other global the bundle references; none of them
is needed for the operations it runs.

## Status

Tested on Node 24 and in a `node:vm` realm that has only ECMAScript built-ins plus `TextEncoder`
/ `TextDecoder`. **Not yet run on a physical device or emulator.** A hardware-backed
`WalletKeyStore` (Secure Enclave / StrongBox) is a later drop-in behind the same interface.

# Identra SDK

Identra SDK is the shared SDK family for demo SSI flows across the Identra
ecosystem. It is designed to run in three distinct environments:

- `identra-website`: web demo, verifier UI, QR/deep-link generation, session polling.
- `identra-app`: mobile wallet, credential receipt, credential storage, VP creation.
- `identra-server`: issuer/verifier backend, demo DID registry, issuance, verification.

The goal of the current version is to establish package boundaries, module
ownership, shared type contracts, and import demos. Real cryptography, QR image
rendering, secure storage, Prisma, Redis, NestJS adapters, and the future CerNet
resolver should be implemented incrementally in later steps.

## Design Intent

Identra is building its own SSI ecosystem, where the CerNet blockchain will
eventually become the DID registry and trust infrastructure layer. Before CerNet
is ready, this SDK lets the team run demos with the following model:

```text
identra-website  -> @identra/sdk-client
identra-app      -> @identra/sdk-app
identra-server   -> @identra/sdk-server
shared contracts -> @identra/sdk-core
```

Important principles:

- The demo may simplify infrastructure, but it should not break the SSI model.
- DID Documents, VCs, VPs, proofs, credential offers, and presentation requests
  should keep a standards-friendly shape so they can be upgraded later.
- `sdk-core` must remain pure TypeScript and must not depend on web, React Native,
  NestJS, Prisma, Redis, filesystem, or runtime-specific APIs.
- Holder private keys must not live in `sdk-client` or verifier website code.
- The server may hold demo issuer keys, but it should not sign VPs on behalf of
  holders.

## Workspace Structure

```text
identra-sdk/
  package.json
  tsconfig.base.json
  examples/
    client-demo.mjs
    app-demo.mjs
    server-demo.mjs
  packages/
    core/
      src/
        types/
        validation/
        demo/
    client/
      src/
    app/
      src/
    server/
      src/
```

The workspace exposes four package entrypoints:

```text
@identra/sdk-core
@identra/sdk-client
@identra/sdk-app
@identra/sdk-server
```

In this repository they are npm workspaces. App, website, and server code should
import them by package name, not by relative paths.

## Install

```bash
npm install
```

On Windows PowerShell, use `npm.cmd` if script execution policy blocks `npm`:

```powershell
npm.cmd install
```

## Build

```bash
npm run build
```

PowerShell:

```powershell
npm.cmd run build
```

This builds packages in dependency order:

```text
core -> client
core -> app
core -> server
```

## Demo Import Test

```bash
npm test
```

PowerShell:

```powershell
npm.cmd test
```

The test script runs:

```text
examples/client-demo.mjs
examples/app-demo.mjs
examples/server-demo.mjs
```

These scripts verify that the three platform packages can be imported through
`node_modules/@identra/*`, exactly like real consumers will import them.

## Local Consumer Testing

You do not need to publish the SDK to npm to test it in `identra-website`,
`identra-app`, or `identra-server`.

Use local `file:` dependencies while all projects live under the same parent
folder. See:

```text
docs/local-file-dependency-testing.md
```

## Package Responsibilities

### `@identra/sdk-core`

Platform-neutral SSI primitives.

Current responsibilities:

- DID Document types.
- DID resolver and registry interfaces.
- W3C-like Verifiable Credential types.
- W3C-like Verifiable Presentation types.
- Demo proof format.
- Credential offer format.
- Presentation request format.
- Pure validation helpers.
- Signer and verifier interfaces.
- Demo fixtures and demo proof helpers.

Current exports include:

```ts
import {
  createDemoDidDocument,
  createDemoCredentialOffer,
  createDemoPresentationRequest,
  createDemoSigner,
  createDemoVerifier,
  validateDidDocument,
  validateCredential,
  validatePresentation,
  validateCredentialOffer,
  validatePresentationRequest,
  type DidResolver,
  type DidRegistry,
  type IdentraDidDocument,
  type IdentraVerifiableCredential,
  type IdentraVerifiablePresentation,
  type IdentraCredentialOffer,
  type IdentraPresentationRequest,
  type Signer,
  type Verifier
} from '@identra/sdk-core';
```

`sdk-core` must stay free of:

- React, React Native, Expo.
- NestJS, Express, Prisma, Redis.
- Browser-only APIs like `window`, `localStorage`, DOM, or Canvas.
- Node-only APIs like `fs`, `crypto`, or process-level globals.

Those concerns belong in adapter packages.

### `@identra/sdk-client`

Client SDK for `identra-website` and web demos.

Current responsibilities:

- Create presentation requests.
- Create QR/deep-link payloads.
- Track verification sessions through the server API.
- Keep holder private keys out of website/client code.

Current entrypoint:

```ts
import { createIdentraClient } from '@identra/sdk-client';

const client = createIdentraClient({
  apiBaseUrl: 'http://localhost:4000',
  deepLinkScheme: 'identra',
  fetch: window.fetch.bind(window)
});

const request = client.createPresentationRequest({
  verifierDid: 'did:identra:demo:verifier',
  descriptors: [
    {
      id: 'degree-proof',
      name: 'Degree proof',
      schema: ['UniversityDegreeCredential']
    }
  ],
  state: 'demo-state'
});

const qrPayload = client.createPresentationQrPayload(request);
const deepLink = client.createPresentationDeepLink(request);
```

Notes:

- `fetch` is optional at construction time, but required for methods that call
  server APIs.
- The QR payload is currently a deep link string. A real QR image renderer should
  live in website/app UI, not in core.
- This package should never create or store holder private keys.

### `@identra/sdk-app`

Mobile wallet SDK for `identra-app`.

Current responsibilities:

- Accept credential offers.
- Store credentials through a storage adapter.
- List credentials.
- Create VPs from selected credentials.
- Sign VPs with the holder signer.
- Resolve DIDs through an injected resolver.

Current entrypoint:

```ts
import { createDemoDidDocument } from '@identra/sdk-core';
import {
  createDemoHolderSigner,
  createIdentraAppSdk,
  InMemoryCredentialStore
} from '@identra/sdk-app';

const holderDid = 'did:identra:demo:holder';

const resolver = {
  async resolve(did: string) {
    return {
      didDocument: did === holderDid ? createDemoDidDocument(holderDid) : null,
      didDocumentMetadata: {},
      didResolutionMetadata: did === holderDid
        ? { contentType: 'application/did+json' }
        : { error: 'notFound' }
    };
  }
};

const appSdk = createIdentraAppSdk({
  resolver,
  signer: createDemoHolderSigner({ holderDid }),
  credentialStore: new InMemoryCredentialStore()
});
```

Example VP creation:

```ts
const credentials = await appSdk.listCredentials();

const presentation = await appSdk.createPresentation({
  holder: holderDid,
  credentials,
  request
});
```

Future app adapters:

- `SecureStoreCredentialStore` for Expo/React Native secure storage.
- `BiometricGate` before signing or sharing.
- `QrScannerAdapter` for QR parsing.
- `CerNetDidResolver` once CerNet is available.
- Real holder signer backed by device key material.

### `@identra/sdk-server`

Server SDK for `identra-server`.

Current responsibilities:

- Demo DID document registry.
- DID resolution.
- Credential offer creation.
- Presentation request creation.
- Verification session creation.
- VC issuance.
- VC verification.
- VP verification.

Current entrypoint:

```ts
import { createDemoDidDocument } from '@identra/sdk-core';
import { createIdentraServerSdk } from '@identra/sdk-server';

const serverSdk = createIdentraServerSdk();

await serverSdk.registerDidDocument(
  createDemoDidDocument('did:identra:demo:issuer')
);

const credential = await serverSdk.issueCredential({
  issuerDid: 'did:identra:demo:issuer',
  subjectDid: 'did:identra:demo:holder',
  type: 'UniversityDegreeCredential',
  claims: {
    degree: 'Software Engineering',
    gpa: '3.85 / 4.0'
  }
});

const result = await serverSdk.verifyCredential(credential);
```

Future server adapters:

- `PrismaDidRegistry`.
- `PrismaCredentialRepository`.
- `RedisVerificationSessionStore`.
- `NestIdentraSdkModule`.
- `CerNetDidRegistry`.
- `CerNetDidResolver`.
- Real issuer signer using a server KMS or HSM-like boundary.

## Demo Protocol Profiles

The current SDK uses demo protocol names:

```text
identra-demo-oid4vci
identra-demo-oid4vp
```

They are intentionally named as demo profiles. They are inspired by OpenID4VCI
and OpenID4VP, but they are not full implementations of those specifications yet.

Current credential offer shape:

```ts
interface IdentraCredentialOffer {
  protocol: 'identra-demo-oid4vci';
  credential_issuer: string;
  credential_configuration_ids: string[];
  grants?: {
    pre_authorized_code?: {
      preAuthorizedCode?: string;
      txCodeRequired?: boolean;
    };
  };
  metadata?: Record<string, unknown>;
}
```

Current presentation request shape:

```ts
interface IdentraPresentationRequest {
  protocol: 'identra-demo-oid4vp';
  client_id: string;
  response_type: 'vp_token';
  response_mode: 'direct_post' | 'fragment';
  nonce: string;
  presentation_definition: PresentationDefinition;
  redirect_uri?: string;
  response_uri?: string;
  state?: string;
  metadata?: Record<string, unknown>;
}
```

When the demo matures, these can evolve toward a stricter OpenID4VCI/OID4VP
profile without changing the high-level package boundaries.

## Demo Proof Format

The current proof format is:

```text
IdentraDemoProof2026
```

It is deterministic enough for demos and import tests, but it is not a
cryptographic signature.

Current proof fields:

```ts
interface IdentraProof {
  type: 'IdentraDemoProof2026' | string;
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod' | 'authentication';
  proofValue: string;
  domain?: string;
  challenge?: string;
}
```

Use it only to prove the flow:

```text
issuer signs VC
holder signs VP
server verifies proof shape and payload binding
```

Future proof implementations should be added behind `Signer` and `Verifier`
interfaces, for example:

- Ed25519 Data Integrity signer/verifier.
- JWT VC signer/verifier.
- SD-JWT VC signer/verifier.
- CerNet-backed trust verification.

## Standard Alignment

This SDK is not trying to implement all SSI standards in the first step. It is
designed so future implementation can align with:

- W3C DID Core for DID Document shape and resolution concepts.
- W3C Verifiable Credentials Data Model for VC/VP shape.
- VC Data Integrity or JOSE/COSE for proof/signature.
- OpenID4VCI for credential issuance transport.
- OpenID4VP for presentation transport.
- Presentation Exchange style input descriptors.

The important design choice is that platform packages use shared `sdk-core`
types. That prevents website, app, and server code from drifting into three
incompatible credential formats.

## Demo Flows

### Issuance Demo

```text
1. Server creates credential offer.
2. Website renders the offer as QR/deep link.
3. App scans or opens the offer.
4. App validates the offer with sdk-app.
5. Server issues VC with sdk-server.
6. App stores VC through credential store.
```

Current SDK pieces:

```text
sdk-server.createCredentialOffer()
sdk-client.createPresentationQrPayload()        currently for VP request
sdk-app.acceptCredentialOffer()
sdk-server.issueCredential()
sdk-app.storeCredential()
```

Credential-offer QR/deep-link helpers are not implemented yet. They should be
added to `sdk-client` or a shared transport helper once the exact demo route is
decided.

### Presentation Demo

```text
1. Website/verifier creates presentation request.
2. Website renders request as QR/deep link.
3. App opens request.
4. User selects credential.
5. App creates VP and signs it with holder signer.
6. Server verifies VP proof and credential proof.
7. Website displays verification result.
```

Current SDK pieces:

```text
sdk-client.createPresentationRequest()
sdk-client.createPresentationQrPayload()
sdk-app.createPresentation()
sdk-server.verifyPresentation()
sdk-server.createVerificationSession()
sdk-client.getVerificationSession()
```

### DID Resolution Demo

```text
1. Server registers demo DID Document.
2. SDK resolves DID through server-backed registry.
3. Later, CerNet resolver replaces server-backed resolver.
```

Current SDK pieces:

```text
sdk-server.registerDidDocument()
sdk-server.resolveDid()
sdk-app.resolveDid()
DidResolver interface in sdk-core
```

## Import Examples

### Website

```ts
import { createIdentraClient } from '@identra/sdk-client';

const client = createIdentraClient({
  apiBaseUrl: import.meta.env.VITE_IDENTRA_SERVER_URL,
  fetch: window.fetch.bind(window)
});
```

### Mobile App

```ts
import { createIdentraAppSdk } from '@identra/sdk-app';

const appSdk = createIdentraAppSdk({
  resolver,
  signer,
  credentialStore
});
```

### Server

```ts
import { createIdentraServerSdk } from '@identra/sdk-server';

const identraSdk = createIdentraServerSdk({
  didRegistry,
  issuerSigner,
  verifier,
  sessionStore
});
```

## Development Commands

```bash
npm install
npm run build
npm test
npm audit --audit-level=moderate
```

PowerShell:

```powershell
npm.cmd install
npm.cmd run build
npm.cmd test
npm.cmd audit --audit-level=moderate
```

## Versioning

Current package version:

```text
0.0.0
```

Until the SDK API stabilizes, treat all package APIs as internal and subject to
change. Before using this SDK in app/server/website code, prefer adding a small
integration demo first so import behavior stays visible.

## Security Notes

The current SDK is for demos only.

Do not treat these as production-safe yet:

- `IdentraDemoProof2026`
- `createDemoSigner`
- `createDemoVerifier`
- `InMemoryCredentialStore`
- `InMemoryDidRegistry`
- `InMemoryVerificationSessionStore`

Production direction:

- Holder signing must happen in `identra-app`, using device-protected key
  material.
- Issuer signing can happen in `identra-server`, but should later be isolated
  behind a KMS/HSM-like interface.
- Verifier must validate nonce, audience/domain, holder binding, credential
  status, issuer trust, expiration, revocation, and schema constraints.
- Server-backed DID registry is temporary until CerNet is ready.
- Sensitive claims should not be logged.

## Implementation Roadmap

Suggested order:

1. Add real HTTP adapters between website, app, and server.
2. Add credential-offer QR/deep-link helpers.
3. Add Prisma-backed DID registry in `sdk-server`.
4. Add Redis-backed verification session store in `sdk-server`.
5. Add Expo secure credential store in `sdk-app`.
6. Add real Ed25519 signer/verifier behind current interfaces.
7. Add VC/VP canonicalization or JWT/SD-JWT profile.
8. Add stricter OpenID4VCI/OID4VP-compatible request/response objects.
9. Add CerNet DID resolver and DID registry adapters.
10. Add conformance fixtures shared by all packages.

## Contribution Rules

When adding SDK functionality:

- Put shared types and pure validation in `sdk-core`.
- Put website-only behavior in `sdk-client`.
- Put React Native holder behavior in `sdk-app`.
- Put issuer/verifier/server storage behavior in `sdk-server`.
- Add a demo script or test fixture for every public entrypoint.
- Do not import platform packages from `sdk-core`.
- Do not duplicate VC/VP/DID types in platform packages.

Dependency direction must stay:

```text
sdk-core
  -> no internal Identra SDK dependency

sdk-client
sdk-app
sdk-server
  -> sdk-core
```

Avoid this:

```text
sdk-core -> sdk-server
sdk-client -> sdk-app
sdk-app -> sdk-server
sdk-server -> sdk-app
```

## Troubleshooting

### `workspace:*` is not supported

This workspace intentionally uses package dependency version `0.0.0` instead of
`workspace:*` because some local npm setups reject the workspace protocol. Npm
workspaces still link packages locally by matching package name and version.

### PowerShell blocks `npm`

Use:

```powershell
npm.cmd run build
```

instead of:

```powershell
npm run build
```

### Import fails in examples

Run:

```bash
npm install
npm run build
npm test
```

The examples import from package names, so `node_modules/@identra/*` symlinks and
`dist` outputs must exist.

### TypeScript build fails after changing core

Run the root build so project references rebuild in order:

```bash
npm run build
```

Do not build a platform package alone after changing exported core types unless
`packages/core` has already been rebuilt.

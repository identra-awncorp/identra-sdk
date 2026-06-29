# Local File Dependency Testing

This guide explains how to test Identra SDK locally without publishing packages
to npm.

Use this approach while the SDK is still evolving and all projects live in the
same parent folder:

```text
Identra/
  identra-sdk/
  identra-website/
  identra-app/
  identra-server/
```

## When To Use This

Use local `file:` dependencies when:

- You want to test SDK imports in website, app, and server.
- You do not want to publish packages to npm yet.
- You want each project to keep its own `package.json`.
- You are not ready to convert the whole repository into one root workspace.

## Package Mapping

Use the SDK package that matches each runtime:

```text
identra-website -> @identra/sdk-client + @identra/sdk-core
identra-app     -> @identra/sdk-app    + @identra/sdk-core
identra-server  -> @identra/sdk-server + @identra/sdk-core
```

`@identra/sdk-core` is listed explicitly in each project so shared types can be
imported directly when needed.

## Step 1: Build The SDK

From the SDK folder:

```powershell
cd C:\Users\Lenovo\Desktop\Identra\identra-sdk
npm.cmd install
npm.cmd run build
npm.cmd test
```

Expected result:

```text
client-demo ok ...
app-demo ok ...
server-demo ok ...
```

The local consumers import compiled files from each package's `dist` folder, so
run `npm.cmd run build` whenever SDK source files change.

## Step 2: Add SDK To `identra-website`

Open:

```text
C:\Users\Lenovo\Desktop\Identra\identra-website\package.json
```

Add:

```json
{
  "dependencies": {
    "@identra/sdk-client": "file:../identra-sdk/packages/client",
    "@identra/sdk-core": "file:../identra-sdk/packages/core"
  }
}
```

Keep the existing dependencies. Only add these two entries.

Then install:

```powershell
cd C:\Users\Lenovo\Desktop\Identra\identra-website
npm.cmd install
```

Minimal import test:

```ts
import { createIdentraClient } from '@identra/sdk-client';

const identraClient = createIdentraClient({
  apiBaseUrl: 'http://localhost:4000',
  deepLinkScheme: 'identra',
  fetch: window.fetch.bind(window)
});

const request = identraClient.createPresentationRequest({
  verifierDid: 'did:identra:demo:verifier',
  descriptors: [{ id: 'degree-proof', schema: ['UniversityDegreeCredential'] }]
});

console.log(request.protocol);
```

Run the website checks:

```powershell
npm.cmd run lint
npm.cmd run build
```

## Step 3: Add SDK To `identra-app`

Open:

```text
C:\Users\Lenovo\Desktop\Identra\identra-app\package.json
```

Add:

```json
{
  "dependencies": {
    "@identra/sdk-app": "file:../identra-sdk/packages/app",
    "@identra/sdk-core": "file:../identra-sdk/packages/core"
  }
}
```

Keep the existing dependencies. Only add these two entries.

Then install:

```powershell
cd C:\Users\Lenovo\Desktop\Identra\identra-app
npm.cmd install
```

Minimal import test:

```ts
import { createDemoDidDocument } from '@identra/sdk-core';
import {
  createDemoHolderSigner,
  createIdentraAppSdk,
  InMemoryCredentialStore
} from '@identra/sdk-app';

const holderDid = 'did:identra:demo:holder';

const appSdk = createIdentraAppSdk({
  signer: createDemoHolderSigner({ holderDid }),
  credentialStore: new InMemoryCredentialStore(),
  resolver: {
    async resolve(did) {
      return {
        didDocument: did === holderDid ? createDemoDidDocument(holderDid) : null,
        didDocumentMetadata: {},
        didResolutionMetadata: did === holderDid
          ? { contentType: 'application/did+json' }
          : { error: 'notFound' }
      };
    }
  }
});

const credentials = await appSdk.listCredentials();
console.log(credentials.length);
```

Run the app checks:

```powershell
npm.cmd run typecheck
npm.cmd test
```

If you run the app with Expo Metro and it does not pick up SDK changes, restart
Metro with cache reset:

```powershell
npm.cmd start -- --clear
```

## Step 4: Add SDK To `identra-server`

Open:

```text
C:\Users\Lenovo\Desktop\Identra\identra-server\package.json
```

Add:

```json
{
  "dependencies": {
    "@identra/sdk-server": "file:../identra-sdk/packages/server",
    "@identra/sdk-core": "file:../identra-sdk/packages/core"
  }
}
```

Keep the existing dependencies. Only add these two entries.

Then install:

```powershell
cd C:\Users\Lenovo\Desktop\Identra\identra-server
npm.cmd install
```

Minimal import test:

```ts
import { createDemoDidDocument } from '@identra/sdk-core';
import { createIdentraServerSdk } from '@identra/sdk-server';

const identraSdk = createIdentraServerSdk();

await identraSdk.registerDidDocument(
  createDemoDidDocument('did:identra:demo:issuer')
);

const credential = await identraSdk.issueCredential({
  issuerDid: 'did:identra:demo:issuer',
  subjectDid: 'did:identra:demo:holder',
  type: 'UniversityDegreeCredential',
  claims: {
    degree: 'Software Engineering'
  }
});

console.log(credential.id);
```

Run the server checks:

```powershell
npm.cmd run lint
npm.cmd run build
```

## Development Loop

When SDK source changes:

```powershell
cd C:\Users\Lenovo\Desktop\Identra\identra-sdk
npm.cmd run build
npm.cmd test
```

Then restart the consuming project:

```text
website: restart Vite dev server
app:     restart Expo/Metro, use --clear if needed
server:  restart NestJS dev server
```

You usually do not need to run `npm.cmd install` in the consuming projects after
every SDK source edit. Run it again when:

- SDK package dependencies change.
- SDK package `package.json` changes.
- The local file dependency was newly added or removed.
- Node module resolution appears stale.

## Important Notes

### Build Output Is Required

Each SDK package exports files from `dist`:

```json
{
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts"
}
```

If a consumer cannot import an SDK package, rebuild the SDK first:

```powershell
cd C:\Users\Lenovo\Desktop\Identra\identra-sdk
npm.cmd run build
```

### Do Not Edit SDK Files In `node_modules`

The consuming projects install local package snapshots or links under
`node_modules`. Always edit files in:

```text
C:\Users\Lenovo\Desktop\Identra\identra-sdk\packages\...
```

Then rebuild the SDK.

### Keep Package Boundaries

Use the correct package for each project:

```text
website imports @identra/sdk-client
app imports     @identra/sdk-app
server imports  @identra/sdk-server
all may import  @identra/sdk-core
```

Avoid importing platform packages across runtimes:

```text
website should not import @identra/sdk-app
app should not import @identra/sdk-server
server should not import @identra/sdk-app
```

## Troubleshooting

### PowerShell blocks `npm`

Use `npm.cmd`:

```powershell
npm.cmd run build
```

### TypeScript cannot find `@identra/sdk-*`

Run install in the consuming project:

```powershell
npm.cmd install
```

Then rebuild SDK:

```powershell
cd C:\Users\Lenovo\Desktop\Identra\identra-sdk
npm.cmd run build
```

### Runtime says `dist/index.js` does not exist

Build SDK:

```powershell
cd C:\Users\Lenovo\Desktop\Identra\identra-sdk
npm.cmd run build
```

### Metro or Vite still sees old SDK code

Restart the dev server.

For Expo:

```powershell
npm.cmd start -- --clear
```

For Vite:

```powershell
npm.cmd run dev
```

### Local dependency feels stale

Reinstall dependencies in the consumer:

```powershell
npm.cmd install
```

If it still looks stale, remove the specific SDK package folder from the
consumer's `node_modules/@identra` and install again. Do not edit files inside
`node_modules`.

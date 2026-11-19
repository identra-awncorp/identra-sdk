// React Native proxy check (ADR-0004 "Bổ sung 2026-11-19"): the core main entry bundles with
// esbuild --platform=neutral, and the bundle validates a chain inside a node:vm realm that has
// only ECMAScript built-ins plus TextEncoder / TextDecoder / atob / btoa: no crypto, Buffer,
// process or fetch. Signatures are checked by the injected pure-JS (noble) verifier.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import vm from 'node:vm';
import * as esbuild from 'esbuild';
import { createCertificateChainValidator } from '@identra/sdk-core';
import { nobleHasher, nobleVerifier } from './helpers/noble.js';
import { b64, ca, leaf, NOW, x5c } from './helpers/pki.js';
import { restrictedRealm } from './helpers/realm.js';

const testDist = new URL('.', import.meta.url).pathname;
const options: esbuild.BuildOptions = { bundle: true, platform: 'neutral', mainFields: ['module', 'main'], write: false, logLevel: 'silent' };

test('the core main entry bundles for a neutral platform without any Node built-in', async () => {
  const r = await esbuild.build({ ...options, format: 'esm', entryPoints: ['@identra/sdk-core'], absWorkingDir: testDist, metafile: true });
  const metafile = r.metafile!;
  const inputs = Object.keys(metafile.inputs);
  assert.ok(inputs.some((p) => p.includes('micro-key-producer')));
  assert.deepEqual(inputs.filter((p) => p.startsWith('node:') || !p.includes('/')), []);
  assert.deepEqual(Object.values(metafile.outputs)[0]!.imports, []);
  // The guard itself: a neutral build refuses a Node built-in.
  await assert.rejects(esbuild.build({ ...options, stdin: { contents: "import 'node:crypto';", resolveDir: testDist } }));
});


test('the bundle validates certificate chains in a realm without crypto, Buffer, process or fetch', async () => {
  const entry = `
    import { createCertificateChainValidator, base64Decode } from '@identra/sdk-core';
    import { nobleVerifier, nobleHasher } from './helpers/noble.js';
    export async function run(json) {
      const input = JSON.parse(json);
      const validator = createCertificateChainValidator({ trustedRoots: [base64Decode(input.root)], verifier: nobleVerifier, hasher: nobleHasher });
      const out = [];
      for (const c of input.cases) {
        const r = await validator.validate({ x5c: c.x5c, profile: c.profile, now: new Date(input.now), expectedIssuerUri: c.iss });
        out.push([r.code, r.fingerprint ?? null, r.leaf?.subject.O ?? null]);
      }
      return JSON.stringify(out);
    }`;
  const built = await esbuild.build({ ...options, format: 'iife', globalName: 'IdentraBundle', stdin: { contents: entry, resolveDir: testDist } });
  const code = built.outputFiles![0]!.text;

  const cases = [
    { x5c: x5c('vc'), profile: 'vc', iss: 'https://api-identra.awncorp.vn/issuers/truong-mau' },
    { x5c: x5c('utf8'), profile: 'vc', iss: 'https://api-identra.awncorp.vn/issuers/truong-mau' },
    { x5c: [b64(leaf('trust-list'))], profile: 'trust-list' },
    { x5c: x5c('evil-vc', 'evil-issuing'), profile: 'vc', iss: 'https://api-identra.awncorp.vn/issuers/truong-mau' },
    { x5c: x5c('expired'), profile: 'vc', iss: 'https://api-identra.awncorp.vn/issuers/truong-mau' },
  ];
  const input = JSON.stringify({ root: b64(ca('root')), now: NOW.toISOString(), cases });

  const ctx = restrictedRealm();
  assert.equal(vm.runInContext('[typeof crypto, typeof Buffer, typeof process, typeof fetch, typeof require, typeof window].join()', ctx), Array(6).fill('undefined').join());
  vm.runInContext(code, ctx);
  const got: unknown[][] = JSON.parse(await vm.runInContext(`IdentraBundle.run(${JSON.stringify(input)})`, ctx));

  // Reference: the same validation in the full Node realm.
  const validator = createCertificateChainValidator({ trustedRoots: [ca('root')], verifier: nobleVerifier, hasher: nobleHasher });
  const expected: unknown[][] = [];
  for (const c of cases) {
    const r = await validator.validate({ x5c: c.x5c, profile: c.profile as 'vc', now: NOW, expectedIssuerUri: c.iss as string });
    expected.push([r.code, r.fingerprint ?? null, r.leaf?.subject.O ?? null]);
  }
  assert.deepEqual(got, expected);
  assert.deepEqual(got.map((r) => r[0]), [null, null, null, 'CERT_CHAIN_UNTRUSTED', 'CERT_EXPIRED']);
  assert.equal(got[1]?.[2], 'Trường Mẫu TEST');
});

// Platform access in the neutral bundle of the core main entry, attributed to the module it comes
// from (esbuild marks each module with a "// <path>" comment). Our modules must have none; the
// third-party occurrences are listed exactly, so a new one cannot slip in unnoticed.
const PLATFORM_PATTERNS: Record<string, RegExp> = {
  'Date.now': /\bDate\.now\b/,
  'new Date()': /\bnew Date\(\)/,
  'Math.random': /\bMath\.random\b/,
  'crypto.subtle': /\bcrypto\.subtle\b/,
  'getRandomValues': /\bgetRandomValues\b/,
  'process.': /\bprocess\./,
  Buffer: /\bBuffer\b/,
  'performance.': /\bperformance\./,
  'Reflect.construct': /\bReflect\.construct\b/,
  'import(': /\bimport\(/,
  fetch: /\bfetch\(/,
  // Code from strings (a CSP without 'unsafe-eval' refuses it): direct, called without new, or aliased.
  'new Function': /\bnew Function\b/,
  'Function(': /(?<![.\w]|new )Function\(/,
  '= Function': /=\s*Function\s*;/,
  eval: /(?<![.\w])eval\(/,
};
const THIRD_PARTY_PLATFORM_ACCESS: Record<string, number> = {
  'Math.random @ zod': 1, // zod's random-id helper; not reached by sdk-core
  'new Date() @ @owf/identity-common': 1, // its "now" default; sdk-core always passes the time
  'new Date() @ @owf/jose': 1,
  'new Date() @ @owf/cose': 1,
  'Buffer @ cbor-x': 3, // feature probes (typeof Buffer), absent in the vm realm
  'import( @ zod': 1, // a comment in zod's source, not code
  // Network paths of SdJwtVcInstance.verify (status list, type metadata): sdk-core never calls verify.
  'fetch @ @owf/identity-common': 2,
  'fetch @ @sd-jwt/sd-jwt-vc': 2,
  // cbor-x (in @owf/cose): a probe at import and record readers; not on any sdk-core path (no CBOR is decoded).
  'new Function @ cbor-x': 2,
  // zod's parser compiler and its probe: never run, sdk-core sets zod's `jitless` before any schema
  // is built (src/zod-config.ts; zod-jitless.test.ts counts the Function calls at run time).
  '= Function @ zod': 3,
};

test('no platform access from our modules in the core bundle; third-party occurrences are exactly the known ones', async () => {
  const r = await esbuild.build({ ...options, format: 'esm', entryPoints: ['@identra/sdk-core'], absWorkingDir: testDist });
  let module = '?';
  const ours: string[] = [];
  const thirdParty: Record<string, number> = {};
  for (const line of r.outputFiles![0]!.text.split('\n')) {
    const marker = /^\/\/ (\S+\.m?js)$/.exec(line);
    if (marker) {
      module = marker[1]!;
      continue;
    }
    for (const [name, re] of Object.entries(PLATFORM_PATTERNS)) {
      if (!re.test(line)) continue;
      const pkg = /node_modules\/((?:@[^/]+\/)?[^/]+)/.exec(module)?.[1];
      if (pkg) thirdParty[`${name} @ ${pkg}`] = (thirdParty[`${name} @ ${pkg}`] ?? 0) + 1;
      else ours.push(`${name} in ${module}: ${line.trim()}`);
    }
  }
  assert.deepEqual(ours, []);
  assert.deepEqual(thirdParty, THIRD_PARTY_PLATFORM_ACCESS);
});

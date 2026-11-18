// React Native proxy for GĐ7a: status list decoding, the trust registry and the status checker,
// bundled with esbuild --platform=neutral and run in a node:vm realm without crypto, Buffer, process
// or fetch (the HTTP fetch is injected). Reports every non-ECMAScript global the bundle looks up,
// i.e. what @owf/token-status-list and pako need.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import vm from 'node:vm';
import * as esbuild from 'esbuild';
import { createStatusList, createStatusListToken } from '@identra/sdk-core';
import { b64, ca, NOW } from './helpers/pki.js';
import { ECMASCRIPT_GLOBALS, restrictedRealm } from './helpers/realm.js';
import { FP, statusSigner, TRUST_URL, trustToken } from './helpers/lists.js';
import { ISS } from './helpers/sdjwt.js';

const testDist = new URL('.', import.meta.url).pathname;
const options: esbuild.BuildOptions = { bundle: true, platform: 'neutral', mainFields: ['module', 'main'], write: false, logLevel: 'silent' };

const ENTRY = `
  import { createCertificateChainValidator, createSignedTrustListRegistry, createStatusListChecker, decodeStatusList, base64Decode } from '@identra/sdk-core';
  import { nobleVerifier, nobleHasher } from './helpers/noble.js';
  export async function run(json) {
    const i = JSON.parse(json);
    const now = new Date(i.now);
    const clock = { now: () => now };
    const fetch = async (url) => {
      const body = i.bodies[url];
      if (body === undefined) throw new Error('unreachable');
      return { status: 200, headers: { get: () => null }, text: async () => body };
    };
    const chainValidator = createCertificateChainValidator({ trustedRoots: [base64Decode(i.root)], verifier: nobleVerifier, hasher: nobleHasher });
    const trustRegistry = createSignedTrustListRegistry({ url: i.trustUrl, fetch, verifier: nobleVerifier, chainValidator, clock });
    const checker = createStatusListChecker({ fetch, verifier: nobleVerifier, chainValidator, trustRegistry, clock });
    const issuer = { maToChuc: 'VATVN-0100000001' };
    const decoded = decodeStatusList(i.claim);
    return JSON.stringify({
      decoded: [decoded.getStatus(41), decoded.getStatus(42), decoded.getStatus(43)],
      entry: await trustRegistry.lookup(i.fingerprint),
      answers: [await checker.check({ uri: i.statusUri, idx: 41 }, issuer), await checker.check({ uri: i.statusUri, idx: 42 }, issuer), await checker.check({ uri: i.statusUri, idx: 43 }, issuer)],
    });
  }`;

test('status list decode, trust registry lookup and status check run in a realm without crypto, Buffer, process or fetch', async (t) => {
  const built = await esbuild.build({ ...options, format: 'iife', globalName: 'IdentraBundle', stdin: { contents: ENTRY, resolveDir: testDist } });
  const code = built.outputFiles![0]!.text;
  const list = createStatusList();
  list.setStatus(42, 1);
  list.setStatus(43, 2);
  const statusUri = `${ISS}/status/1`;
  const input = JSON.stringify({
    now: NOW.toISOString(), root: b64(ca('root')), trustUrl: TRUST_URL, statusUri, fingerprint: FP.vc, claim: list.encode(),
    bodies: { [TRUST_URL]: await trustToken(), [statusUri]: await createStatusListToken({ list, uri: statusUri, signer: await statusSigner(), now: NOW }) },
  });

  const ctx = restrictedRealm();
  assert.equal(vm.runInContext('[typeof crypto, typeof Buffer, typeof process, typeof fetch, typeof require, typeof window].join()', ctx), Array(6).fill('undefined').join());
  const touched: Set<string> = vm.runInContext(
    `(() => { const seen = new Set();
      globalThis.__probe = new Proxy({}, {
        has: (_, k) => { if (typeof k === 'string') seen.add(k); return typeof k === 'string' && k in globalThis; },
        get: (_, k) => (k === Symbol.unscopables ? undefined : globalThis[k]),
        set: (_, k, v) => { globalThis[k] = v; return true; },
      });
      return seen; })()`,
    ctx,
  );
  vm.runInContext(`with (__probe) { ${code} }`, ctx);
  ctx['__input'] = input;
  const out = JSON.parse(await vm.runInContext('IdentraBundle.run(__input)', ctx));
  assert.deepEqual(out.decoded, [0, 1, 2]);
  assert.equal(out.entry?.maToChuc, 'VATVN-0100000001');
  assert.equal(out.entry?.mucDich, 'vc');
  assert.deepEqual(out.answers, ['valid', 'revoked', 'suspended']);

  const nonEcma = [...touched].filter((k) => !ECMASCRIPT_GLOBALS.has(k) && !['__probe', '__input', 'IdentraBundle'].includes(k)).sort();
  const present = nonEcma.filter((k) => vm.runInContext(`typeof globalThis[${JSON.stringify(k)}]`, ctx) !== 'undefined');
  const probedOnly = nonEcma.filter((k) => !present.includes(k));
  t.diagnostic(`non-ECMAScript globals used: ${present.join(', ')}`);
  t.diagnostic(`looked up but absent (feature detection): ${probedOnly.join(', ') || '(none)'}`);
  for (const forbidden of ['crypto', 'Buffer', 'process', 'fetch']) assert.equal(present.includes(forbidden), false, forbidden);
  assert.deepEqual(present, ['TextDecoder', 'TextEncoder']);
});

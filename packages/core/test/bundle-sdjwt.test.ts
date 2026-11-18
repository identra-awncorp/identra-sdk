// React Native proxy for SD-JWT VC: issue -> present -> verify, bundled with esbuild
// --platform=neutral and run in a node:vm realm without crypto, Buffer, process or fetch.
// Reports every non-ECMAScript global the bundle looks up and the minified size of the core entry.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import vm from 'node:vm';
import { gzipSync } from 'node:zlib';
import * as esbuild from 'esbuild';
import { hexEncode } from '@identra/sdk-core';
import { webCryptoRandom } from '@identra/sdk-core/webcrypto';
import { b64, ca, NOW, pemFile, x5c } from './helpers/pki.js';
import { ECMASCRIPT_GLOBALS, restrictedRealm } from './helpers/realm.js';
import { AUD, DIPLOMA, ISS, NONCE, STATUS, TRUST_ENTRY } from './helpers/sdjwt.js';

const testDist = new URL('.', import.meta.url).pathname;
const options: esbuild.BuildOptions = { bundle: true, platform: 'neutral', mainFields: ['module', 'main'], write: false, logLevel: 'silent' };

const ENTRY = `
  import { issueDiploma, createPresentation, verifyPresentation, createCertificateChainValidator, base64Decode, hexDecode, VCT } from '@identra/sdk-core';
  import { nobleVerifier, nobleHasher, nobleSigner } from './helpers/noble.js';
  export async function run(json) {
    const i = JSON.parse(json);
    const pool = hexDecode(i.randomHex);
    let offset = 0;
    const random = { bytes(n) { const b = pool.slice(offset, offset + n); offset += n; if (b.length !== n) throw new Error('random pool exhausted'); return b; } };
    const now = new Date(i.now);
    const clock = { now: () => now };
    const issuer = { ...nobleSigner(hexDecode(i.issuerD)), x5c: i.x5c };
    const holder = nobleSigner(hexDecode(i.holderD));
    const compact = await issueDiploma({ signer: issuer, hasher: nobleHasher, random, clock, iss: i.iss, cnfJwk: holder.publicJwk, status: i.status, claims: i.claims });
    const presentation = await createPresentation({ compact, disclose: ['ho_ten', 'nganh'], holderSigner: holder, audience: i.aud, nonce: i.nonce, now, hasher: nobleHasher });
    const chainValidator = createCertificateChainValidator({ trustedRoots: [base64Decode(i.root)], verifier: nobleVerifier, hasher: nobleHasher });
    const options = {
      verifier: nobleVerifier, hasher: nobleHasher, chainValidator, supportedVcts: [VCT.diploma], now,
      trustRegistry: { async lookup() { return i.entry; } },
      statusChecker: { async check() { return 'valid'; } },
      presentation: { nonce: i.nonce, audience: i.aud },
    };
    const good = await verifyPresentation(presentation, options);
    const bad = await verifyPresentation(presentation, { ...options, presentation: { nonce: 'other', audience: i.aud } });
    return JSON.stringify({ codes: good.checks.map((c) => c.code), claims: good.credential?.claims ?? null, badNonce: bad.checks.at(-1).code });
  }`;

async function issuerSecretHex(): Promise<string> {
  const der = Buffer.from(pemFile('test/leaf/vc.key.pem').replace(/-----[A-Z ]+-----|\s/g, ''), 'base64');
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  return Buffer.from((await crypto.subtle.exportKey('jwk', key)).d!, 'base64url').toString('hex');
}

test('issue -> present -> verify runs in a realm without crypto, Buffer, process or fetch', async (t) => {
  const built = await esbuild.build({ ...options, format: 'iife', globalName: 'IdentraBundle', stdin: { contents: ENTRY, resolveDir: testDist } });
  const code = built.outputFiles![0]!.text;
  const holderD = hexEncode(webCryptoRandom.bytes(32));
  const input = JSON.stringify({
    randomHex: hexEncode(webCryptoRandom.bytes(4096)), now: NOW.toISOString(), issuerD: await issuerSecretHex(), holderD,
    x5c: x5c('vc'), root: b64(ca('root')), iss: ISS, status: STATUS, claims: DIPLOMA, aud: AUD, nonce: NONCE, entry: TRUST_ENTRY,
  });

  const ctx = restrictedRealm();
  assert.equal(vm.runInContext('[typeof crypto, typeof Buffer, typeof process, typeof fetch, typeof require, typeof window].join()', ctx), Array(6).fill('undefined').join());
  // Every free identifier the bundle resolves against the global scope is recorded: the bundle runs
  // inside \`with (probe)\`, which catches real uses and \`typeof X\` feature probes alike.
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
  assert.deepEqual(out.codes, Array(9).fill(null));
  assert.deepEqual(out.claims, { ho_ten: DIPLOMA.ho_ten, nganh: DIPLOMA.nganh });
  assert.equal(out.badNonce, 'NONCE_MISMATCH');

  const nonEcma = [...touched].filter((k) => !ECMASCRIPT_GLOBALS.has(k) && !['__probe', '__input', 'IdentraBundle'].includes(k)).sort();
  const present = nonEcma.filter((k) => vm.runInContext(`typeof globalThis[${JSON.stringify(k)}]`, ctx) !== 'undefined');
  const probedOnly = nonEcma.filter((k) => !present.includes(k));
  t.diagnostic(`non-ECMAScript globals used: ${present.join(', ')}`);
  t.diagnostic(`looked up but absent (feature detection): ${probedOnly.join(', ') || '(none)'}`);
  for (const forbidden of ['crypto', 'Buffer', 'process', 'fetch']) assert.equal(present.includes(forbidden), false, forbidden);
  assert.deepEqual(present, EXPECTED_GLOBALS);

  // TextDecoder is a real requirement (of @sd-jwt/*), not a probe: React Native needs the polyfill.
  const bare = restrictedRealm({ textDecoder: false });
  vm.runInContext(code, bare);
  bare['__input'] = input;
  await assert.rejects(vm.runInContext('IdentraBundle.run(__input)', bare) as Promise<unknown>);
});

// What the bundle (sdk-core + @sd-jwt/* + micro-key-producer + noble) needs beyond ECMAScript.
const EXPECTED_GLOBALS = ['TextDecoder', 'TextEncoder'];

test('minified size of the core main entry', async (t) => {
  const r = await esbuild.build({ ...options, format: 'esm', minify: true, entryPoints: ['@identra/sdk-core'], absWorkingDir: testDist, metafile: true });
  const bytes = r.outputFiles![0]!.contents;
  const byPackage: Record<string, number> = {};
  for (const [path, input] of Object.entries(Object.values(r.metafile!.outputs)[0]!.inputs)) {
    const name = /node_modules\/((?:@[^/]+\/)?[^/]+)/.exec(path)?.[1] ?? '@identra/sdk-core';
    byPackage[name] = (byPackage[name] ?? 0) + input.bytesInOutput;
  }
  t.diagnostic(`core entry: ${(bytes.length / 1024).toFixed(1)} KB minified, ${(gzipSync(bytes).length / 1024).toFixed(1)} KB gzip`);
  t.diagnostic(`by package (KB): ${Object.entries(byPackage).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${(v / 1024).toFixed(1)}`).join(', ')}`);
  assert.ok(bytes.length > 0);
});

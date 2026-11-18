// Identra SDK micro-benchmarks. `node bench/run.mjs [--json] [--only=<substring>] [--min-ms=<n>]`.
// See bench/README.md. Every benchmarked verification asserts ok === true before and after timing.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { utf8Encode, verifyPresentation, verifyProductChain, verifyStatusListToken, verifyTrustListToken } from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { createNobleSigner, decryptJwe, encryptJwe, generateSecretKey, nobleVerifier } from '@identra/sdk-app';
import { bench, options, table } from './harness.mjs';
import { buildWorld, GTIN, ISS, SERIAL } from './world.mjs';

const args = process.argv.slice(2);
const flag = (name) => args.find((a) => a === `--${name}` || a.startsWith(`--${name}=`))?.split('=')[1] ?? (args.includes(`--${name}`) ? true : undefined);
const only = flag('only');
if (flag('min-ms')) options.minMs = Number(flag('min-ms'));
const t0 = process.hrtime.bigint();
const BACKENDS = ['webcrypto', 'noble'];
const label = { webcrypto: 'WebCrypto', noble: 'noble' };

const w = await buildWorld();
const results = [];
async function add(name, backend, fn, check) {
  if (only && !`${name} ${backend}`.toLowerCase().includes(only.toLowerCase())) return;
  process.stderr.write(`  ${name} [${backend}] ...`);
  const r = await bench({ name, backend, fn, check });
  results.push(r);
  process.stderr.write(` ${Math.round(r.opsPerSec).toLocaleString('en-US')} ops/s\n`);
}
/** The check of a verification: ok === true, and (when `calls` is given) no fetch happened since the first check. */
const okCheck = (fn, served, extra = () => {}) => {
  let baseline;
  return async () => {
    const r = await fn();
    assert.equal(r.ok, true, `verification failed: ${JSON.stringify(r.checks ?? r)}`);
    extra(r);
    if (served) {
      baseline ??= served.calls.length;
      assert.equal(served.calls.length, baseline, 'a list was refetched: the cache is not warm');
    }
  };
};

// --- 1. ES256 primitives -------------------------------------------------------------------------
const message = webCryptoRandom.bytes(512); // about the size of a JWS signing input
const wcKeys = await generateWebCryptoKeyPair();
const signers = {
  webcrypto: await createWebCryptoSigner({ privateKey: wcKeys.privateKey, publicJwk: wcKeys.publicJwk }),
  noble: createNobleSigner(generateSecretKey(webCryptoRandom)),
};
const verifiers = { webcrypto: webCryptoVerifier, noble: nobleVerifier };
const signatures = { webcrypto: await signers.webcrypto.sign(message), noble: await signers.noble.sign(message) };
for (const b of BACKENDS) {
  await add('ES256 sign (512 B)', b, () => signers[b].sign(message), async () => {
    assert.equal(await webCryptoVerifier.verify(signers[b].publicJwk, message, await signers[b].sign(message)), true);
  });
}
for (const b of BACKENDS) {
  await add('ES256 verify (512 B)', b, () => verifiers[b].verify(signers[b].publicJwk, message, signatures[b]), async () => {
    assert.equal(await verifiers[b].verify(signers[b].publicJwk, message, signatures[b]), true);
    assert.equal(await verifiers[b].verify(signers[b].publicJwk, utf8Encode('other'), signatures[b]), false);
  });
}

// --- 2. certificate chain validation (vc profile: leaf + issuing CA, pinned root) -------------------
for (const b of BACKENDS) {
  const validate = () => w.backends[b].chainValidator.validate({ x5c: w.vcX5c, profile: 'vc', now: w.NOW, expectedIssuerUri: ISS });
  await add('chain validate (vc: leaf + CA -> root)', b, validate, okCheck(validate));
}

// --- 3. issue a diploma (7 disclosures + decoys, x5c) ---------------------------------------------
await add('issueDiploma (7 claims, x5c)', 'webcrypto', w.issue, async () => {
  const c = await w.issue();
  assert.ok(c.endsWith('~') && c.split('~').length >= 9);
});

// --- 4. presentation with KB-JWT, 2 of 7 claims, noble holder key --------------------------------
await add('createPresentation (2 of 7, KB-JWT)', 'noble', () => w.present(), async () => {
  const r = await verifyPresentation(await w.present(), w.verifyOptions('webcrypto'));
  assert.equal(r.ok, true);
});

// --- 5. verifyPresentation end to end -------------------------------------------------------------
const claimsCheck = (r) => {
  assert.equal(r.credential?.claims?.ho_ten, 'Nguyễn Văn A');
  assert.equal(r.credential?.claims?.nganh, 'Khoa học máy tính');
  assert.equal('ngay_sinh' in r.credential.claims, false);
};
for (const b of BACKENDS) {
  const opts = w.verifyOptions(b);
  const run = () => verifyPresentation(w.presentation, opts);
  await add('verifyPresentation (in-memory trust + status)', b, run, okCheck(run, undefined, claimsCheck));
}
for (const b of BACKENDS) {
  const lists = w.realLists(b);
  const opts = w.verifyOptions(b, lists);
  const run = () => verifyPresentation(w.presentation, opts);
  await add('verifyPresentation (real signed lists, warm cache)', b, run, okCheck(run, lists.served, claimsCheck));
}
for (const b of BACKENDS) {
  const name = 'verifyPresentation (real signed lists, COLD: 1st call)';
  if (only && !`${name} ${b}`.toLowerCase().includes(only.toLowerCase())) continue;
  // Fresh registry + checker (empty caches) each time; the code is already JIT-warm. Median of 3.
  const times = [];
  let fetched;
  for (let i = 0; i < 3; i++) {
    const lists = w.realLists(b);
    const s = process.hrtime.bigint();
    const r = await verifyPresentation(w.presentation, w.verifyOptions(b, lists));
    times.push(Number(process.hrtime.bigint() - s) / 1e6);
    assert.equal(r.ok, true, 'cold verification failed');
    fetched = lists.served.calls.length;
    const again = await verifyPresentation(w.presentation, w.verifyOptions(b, lists));
    assert.equal(again.ok, true);
    assert.equal(lists.served.calls.length, fetched, 'second call refetched');
  }
  times.sort((x, y) => x - y);
  results.push({ name, backend: b, cold: true, n: 1, opsPerSec: 1000 / times[1], meanMs: times[1], p50Ms: times[1], p95Ms: NaN, p99Ms: NaN, spreadPct: ((times[2] - times[0]) / times[1]) * 100, runsMs: times, fetches: fetched });
  process.stderr.write(`  ${name} [${b}] ... ${times[1].toFixed(2)} ms (${fetched} fetches)\n`);
}

// --- 6. status list (131 072 x 2 bit, ~1% set) ---------------------------------------------------
await add('status list: build (1% set) + sign token', 'webcrypto', () => w.signStatusList(w.fillList()), async () => {
  const token = await w.signStatusList(w.fillList());
  assert.ok(typeof token === 'string' && token.split('.').length === 3);
});
for (const b of BACKENDS) {
  const verify = () => verifyStatusListToken(w.statusToken, { uri: `${ISS}/status/1`, issuer: { maToChuc: w.trustContent.issuers[0].ma_to_chuc }, ...w.backends[b], trustRegistry: w.memoryTrust, now: w.NOW });
  await add('status list: verify + decode token', b, verify, okCheck(verify, undefined, (r) => {
    assert.equal(r.list.getStatus(w.credIdx), 0);
    assert.ok([...Array(2000).keys()].some((i) => r.list.getStatus(i) !== 0));
  }));
}

// --- 7. trust list (5 organisations) -------------------------------------------------------------
await add('trust list: sign token (5 organisations)', 'webcrypto', w.signTrustList, async () => assert.ok((await w.signTrustList()).split('.').length === 3));
for (const b of BACKENDS) {
  const verify = () => verifyTrustListToken(w.trustToken, { chainValidator: w.backends[b].chainValidator, verifier: w.backends[b].verifier, now: w.NOW });
  await add('trust list: verify token', b, verify, okCheck(verify, undefined, (r) => assert.equal(r.payload.issuers.length + r.payload.verifiers.length, 5)));
}

// --- 8. product chain, 3 events, WebCrypto, warm caches ------------------------------------------
{
  const lists = w.realLists('webcrypto');
  const opts = w.productOptions(lists);
  const run = () => verifyProductChain({ gtin: GTIN, serial: SERIAL, events: w.events }, opts);
  await add('verifyProductChain (3 events, real lists, warm)', 'webcrypto', run, async () => {
    const r = await run();
    assert.equal(r.ok, true, `product chain failed: ${JSON.stringify(r)}`);
    assert.equal(r.state, 'verified');
    assert.equal(r.events.length, 3);
    lists.served.baseline ??= lists.served.calls.length;
    assert.equal(lists.served.calls.length, lists.served.baseline, 'a list was refetched');
  });
}

// --- 9. wallet JWE, ~3 KB ------------------------------------------------------------------------
let jweLength;
{
  const secretKey = generateSecretKey(webCryptoRandom);
  const recipient = createNobleSigner(secretKey).publicJwk;
  const plaintext = webCryptoRandom.bytes(3072);
  const encrypt = () => encryptJwe({ recipientPublicJwk: recipient, enc: 'A256GCM', plaintext, random: webCryptoRandom });
  const jwe = encrypt();
  jweLength = jwe.length;
  const roundTrip = (j) => assert.deepEqual(decryptJwe({ jwe: j, recipientSecretKey: secretKey }).plaintext, plaintext);
  await add('encryptJwe (ECDH-ES + A256GCM, 3 KB)', 'noble', encrypt, async () => roundTrip(encrypt()));
  await add('decryptJwe (ECDH-ES + A256GCM, 3 KB)', 'noble', () => decryptJwe({ jwe, recipientSecretKey: secretKey }), async () => roundTrip(jwe));
}

// --- environment, sizes, output ------------------------------------------------------------------
const sh = (cmd, a) => { try { return execFileSync(cmd, a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return undefined; } };
const sys = (p) => { try { return readFileSync(p, 'utf8').trim(); } catch { return undefined; } };
const sizes = {
  'issued diploma compact (7 disclosures + decoys, x5c)': w.credential.length,
  'presentation (2 of 7 claims + KB-JWT)': w.presentation.length,
  'status-list token (131 072 x 2 bit, 1% set)': w.statusToken.length,
  'trust-list token (5 organisations)': w.trustToken.length,
  'wallet JWE (3 KB plaintext)': jweLength,
};
const totalSeconds = Number(process.hrtime.bigint() - t0) / 1e9;
const env = {
  cpu: os.cpus()[0].model, logicalCores: os.cpus().length, node: process.version, v8: process.versions.v8, openssl: process.versions.openssl,
  os: `${os.type()} ${os.release()} (${os.arch()})`, memoryGiB: +(os.totalmem() / 2 ** 30).toFixed(1),
  governor: sys('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor'), loadAvgAtEnd: os.loadavg().map((x) => +x.toFixed(2)),
  sdkCommit: sh('git', ['-C', new URL('..', import.meta.url).pathname, 'rev-parse', '--short', 'HEAD']),
  pinnedClock: w.NOW.toISOString(), minMsPerRun: options.minMs, runsPerCase: 3,
};
const peakRssMiB = +(process.resourceUsage().maxRSS / 1024).toFixed(1);

console.log(`## Identra SDK benchmarks\n\n${table(results)}\n`);
console.log('### Environment\n');
for (const [k, v] of Object.entries(env)) console.log(`- ${k}: ${Array.isArray(v) ? v.join(' ') : v}`);
console.log(`- peak RSS of the whole run: ${peakRssMiB} MiB`);
console.log(`- total run time: ${totalSeconds.toFixed(0)} s\n`);
console.log('### Sizes (bytes)\n');
for (const [k, v] of Object.entries(sizes)) console.log(`- ${k}: ${v.toLocaleString('en-US')}`);

if (flag('json')) {
  const out = new URL('results.json', import.meta.url);
  writeFileSync(out, `${JSON.stringify({ env, peakRssMiB, totalSeconds, sizes, results }, null, 2)}\n`);
  console.error(`wrote ${out.pathname}`);
}

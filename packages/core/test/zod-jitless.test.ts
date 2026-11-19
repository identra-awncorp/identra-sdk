// F5-2: zod (inside the @sd-jwt, @owf and @openid4vc libraries) never constructs code from strings.
// A child process with --disallow-code-generation-from-strings (a CSP without 'unsafe-eval')
// replaces the Function constructor with a recording proxy BEFORE any SDK module loads, imports
// every package entry, then issues, presents and verifies a credential and verifies a product
// chain (with its status lists and trust list fetched and checked).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

const helpers = new URL('./helpers/', import.meta.url).href;
const ENTRIES = ['@identra/sdk-core', '@identra/sdk-core/webcrypto', '@identra/sdk-core/text', '@identra/sdk-app', '@identra/sdk-client', '@identra/sdk-client/product', '@identra/sdk-server'];
const proxy = `
const calls = [];
const Real = Function;
const record = () => calls.push(new Error().stack.split('\\n').slice(2).find((l) => l.includes('node_modules/') || l.includes('/dist/')) ?? '?');
globalThis.Function = new Proxy(Real, {
  construct: (t, a) => (record(), Reflect.construct(t, a)),
  apply: (t, self, a) => (record(), Reflect.apply(t, self, a)),
});
`;
const script = `${proxy}
for (const entry of ${JSON.stringify(ENTRIES)}) await import(entry);
const core = await import('@identra/sdk-core');
const { webCryptoHasher } = await import('@identra/sdk-core/webcrypto');
const S = await import('${helpers}sdjwt.js');
const P = await import('${helpers}product.js');
const { NOW } = await import('${helpers}pki.js');
const holder = await S.holderKey();
const compact = await core.issueDiploma({ ...(await S.issuerContext()), iss: S.ISS, cnfJwk: holder.publicJwk, status: S.STATUS, claims: S.DIPLOMA });
const presented = await core.createPresentation({ compact, disclose: ['ho_ten', 'nganh'], holderSigner: holder, audience: S.AUD, nonce: S.NONCE, now: NOW, hasher: webCryptoHasher });
const presentation = await core.verifyPresentation(presented, S.presentationOptions());
const world = await P.productWorld();
const chain = await core.verifyProductChain({ gtin: P.GTIN, serial: P.SERIAL, events: await world.chain(3) }, world.options());
let codegen = 'allowed';
try { new Real('return 1'); } catch (e) { codegen = e.constructor.name; }
console.log(JSON.stringify({ presentation: presentation.ok, chain: chain.state, statusChecked: chain.events.every((e) => e.checks.some((c) => c.id === 'status' && c.ok)), codegen, calls }));
`;

const run = (code: string) => {
  const r = spawnSync(process.execPath, ['--disallow-code-generation-from-strings', '--input-type=module', '-e', code], { encoding: 'utf8', cwd: new URL('.', import.meta.url).pathname });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout.trim().split('\n').at(-1)!) as { calls: string[] } & Record<string, unknown>;
};
const packages = (calls: string[]) => calls.map((c) => /node_modules\/((?:@[^/]+\/)?[^/]+)/.exec(c)?.[1] ?? c);

test('each entry imported alone, first: no Function call from zod (each sets jitless itself)', () => {
  for (const entry of ENTRIES) {
    const out = run(`${proxy}\nawait import('${entry}');\nconsole.log(JSON.stringify({ calls }));`);
    assert.ok(packages(out.calls).every((p) => p === 'cbor-x'), `${entry}: ${out.calls.join(' ')}`);
  }
});

test('with code generation from strings disabled, every entry imports and the flows work with no Function call from zod', () => {
  const out = run(script);
  assert.deepEqual([out.presentation, out.chain, out.statusChecked, out.codegen], [true, 'verified', true, 'EvalError']);
  assert.deepEqual(out.calls.filter((c) => c.includes('/zod/')), [], 'zod constructed no function');
  // The one remaining site: cbor-x's probe at import (it catches the refusal), listed in bundle.test.ts.
  assert.deepEqual(packages(out.calls), ['cbor-x']);
});

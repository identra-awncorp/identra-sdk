// React Native proxy check (ADR-0004 "Bổ sung 2026-11-19"): the sdk-app main entry bundles with
// esbuild --platform=neutral and runs sign / verify, JWE, key store, vault, catalogue and a whole
// OpenID4VCI issuance (wallet.offers.resolve + accept against an in-process fetch) inside a
// node:vm realm holding only ECMAScript built-ins plus the web globals listed in WEB_GLOBALS: no
// crypto object at all, no Buffer, process or fetch. This is a proxy, not Hermes on a phone.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import vm from 'node:vm';
import * as esbuild from 'esbuild';
import { Linter } from 'eslint';
import { base64UrlDecode, base64UrlEncode, utf8Decode, utf8Encode } from '@identra/sdk-core';
import { CompactEncrypt, compactDecrypt, importJWK } from 'jose';
import { createNobleSigner, generateSecretKey } from '@identra/sdk-app';
import { base64Encode } from '@identra/sdk-core';
import { countingRandom } from './helpers/random.js';
import { createWorld, dispatch, inProcessListener, NOW, ORIGIN, rootDer, TRUST_URL } from './helpers/world.js';

const testDist = new URL('.', import.meta.url).pathname;
const options: esbuild.BuildOptions = { bundle: true, platform: 'neutral', mainFields: ['module', 'main'], write: false, logLevel: 'silent' };

/** The names a fresh realm starts with, minus the two that are not ECMAScript. */
const ECMASCRIPT_GLOBALS = new Set(Object.getOwnPropertyNames(vm.runInNewContext('globalThis')).filter((n) => n !== 'console' && n !== 'WebAssembly'));

/**
 * What React Native must provide besides ECMAScript, beyond TextEncoder (defined in the realm, like
 * Hermes): the wallet's OpenID4VC libraries need atob (zod), URL, URLSearchParams, Headers and
 * Response; TextDecoder is for @sd-jwt/*; setTimeout / clearTimeout enforce the wallet's timeouts.
 * The test fails when the set the bundle actually reads changes, so a library upgrade shows here.
 */
const WEB_GLOBALS = { TextDecoder, atob, URL, URLSearchParams, Headers, Response, setTimeout, clearTimeout };

/** ECMAScript built-ins plus TextEncoder (defined in the realm) and WEB_GLOBALS from Node. */
function restrictedRealm(extra: Record<string, unknown> = {}): vm.Context {
  const ctx = vm.createContext({});
  vm.runInContext(
    `{ const u = unescape, e = encodeURIComponent, U8 = Uint8Array, S = String;
      globalThis.TextEncoder = class TextEncoder {
        get encoding() { return 'utf-8'; }
        encode(s = '') { const b = u(e(S(s))); const o = new U8(b.length); for (let i = 0; i < b.length; i++) o[i] = b.charCodeAt(i); return o; }
      }; }
     delete globalThis.console; delete globalThis.WebAssembly;`,
    ctx,
  );
  Object.assign(ctx, WEB_GLOBALS, extra);
  return ctx;
}

// Runs inside the realm. Randomness is a deterministic test generator: there is no crypto object.
const ENTRY = `
  import * as app from '@identra/sdk-app';
  import { base64Decode, base64UrlDecode, base64UrlEncode, utf8Encode, utf8Decode, decodeJws, verifyJws } from '@identra/sdk-core';
  function testRandom(seed) {
    let state = seed >>> 0;
    return { bytes(n) { const o = new Uint8Array(n); for (let i = 0; i < n; i++) { state = (Math.imul(state ^ (state >>> 15), 0x2c1b3c6d) + 0x9e3779b9) >>> 0; o[i] = state >>> 24; } return o; } };
  }
  export async function run(json) {
    const input = JSON.parse(json);
    const random = testRandom(input.seed);
    const out = {};
    // ES256: RFC 7515 A.3, then a fresh key
    const a3 = decodeJws(input.rfcJws, 16384);
    out.rfcA3 = (await verifyJws(a3.jws, input.rfcJwk, app.nobleVerifier)) === null;
    const signer = app.createNobleSigner(app.generateSecretKey(random));
    const data = utf8Encode('in the realm');
    const sig = await signer.sign(data);
    out.signVerify = await app.nobleVerifier.verify(signer.publicJwk, data, sig);
    out.tampered = await app.nobleVerifier.verify(signer.publicJwk, utf8Encode('in the realm!'), sig);
    out.outerSignatureOk = await app.nobleVerifier.verify(input.outer.publicJwk, utf8Encode(input.outer.data), base64UrlDecode(input.outer.sig));
    out.sha256 = base64UrlEncode(await app.nobleHasher.sha256(utf8Encode('abc')));
    // JWE: round trip, decrypt a jose JWE, encrypt one for jose
    const rk = app.generateSecretKey(random);
    const rpub = app.createNobleSigner(rk).publicJwk;
    const jwe = app.encryptJwe({ recipientPublicJwk: rpub, enc: 'A256GCM', plaintext: utf8Encode('{"vp_token":"x"}'), random, header: { kid: 'k' } });
    out.jweRoundTrip = utf8Decode(app.decryptJwe({ jwe, recipientSecretKey: rk }).plaintext);
    out.fromJose = utf8Decode(app.decryptJwe({ jwe: input.joseJwe, recipientSecretKey: base64UrlDecode(input.joseRecipientD) }).plaintext);
    out.forJose = app.encryptJwe({ recipientPublicJwk: input.outer.publicJwk, enc: 'A128GCM', plaintext: utf8Encode('for jose'), random });
    try { app.decryptJwe({ jwe: jwe.slice(0, -2) + (jwe.endsWith('AA') ? 'AQ' : 'AA'), recipientSecretKey: rk }); out.jweTamper = 'accepted'; } catch (e) { out.jweTamper = e.code; }
    // Key store
    const secrets = new Map();
    const keys = app.createSoftwareKeyStore({ secrets: app.createInMemorySecretStorage(secrets), random });
    const { keyId, publicJwk } = await keys.create();
    const ks = await keys.signer(keyId);
    out.keyStore = await app.nobleVerifier.verify(publicJwk, data, await ks.sign(data));
    await keys.delete(keyId);
    try { await keys.signer(keyId); out.keyDeleted = false; } catch (e) { out.keyDeleted = e.code; }
    // Vault and catalogue
    const rows = new Map();
    const vault = app.createCredentialVault({ repository: app.createInMemoryCredentialRepository(rows), secrets: app.createInMemorySecretStorage(), random, clock: { now: () => new Date(input.now) } });
    const id = await vault.save({ compact: input.compact, vct: 'https://v.example/vct', issuer: 'https://i.example', keyId });
    out.vaultRoundTrip = (await vault.open(id)) === input.compact;
    out.vaultCiphertextHasPlaintext = JSON.stringify([...rows.values()]).includes(input.compact);
    await vault.setStatus(id, 'valid', new Date(input.now));
    out.listed = await vault.list();
    out.catalogue = app.serializeCatalogue(app.buildCatalogue(out.listed));
    return JSON.stringify(out);
  }
  // A whole issuance, wallet side, with the default noble crypto; the issuer answers through hostFetch.
  export async function issue(json, hostFetch) {
    const input = JSON.parse(json);
    const random = testRandom(input.seed);
    const clock = { now: () => new Date(input.now) };
    const secrets = new Map();
    const rows = new Map();
    const keyStore = app.createSoftwareKeyStore({ secrets: app.createInMemorySecretStorage(secrets), random });
    const vault = app.createCredentialVault({ repository: app.createInMemoryCredentialRepository(rows), secrets: app.createInMemorySecretStorage(), random, clock });
    const wallet = app.createWallet({ keyStore, vault, fetch: hostFetch, random, clock, trustedRoots: [base64Decode(input.root)], trustListUrl: input.trustListUrl });
    const resolved = await wallet.offers.resolve(input.offerUri);
    if (!resolved.ok) return JSON.stringify({ resolved });
    const accepted = await wallet.offers.accept(resolved.offer, { txCode: input.txCode });
    const details = accepted.ok ? await wallet.credentials.get(accepted.credentialId) : null;
    return JSON.stringify({ accepted, claims: details && details.ok ? details.credential.claims : null, rows: rows.size, keys: secrets.size });
  }`;

/** An issuer world answering in-process, an offer, and the realm's input for issue(). */
async function issuanceInput(seed: number) {
  const listener = inProcessListener();
  const world = await createWorld(listener);
  const { offerUri, txCode } = await world.offer();
  const hostFetch = async (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => {
    assert.ok(url.startsWith(`${ORIGIN}/`), url);
    const headers = Object.fromEntries(Object.entries(init?.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    const r = await dispatch(listener.routes, { method: init?.method ?? 'GET', path: url.slice(ORIGIN.length).split('?')[0]!, headers, body: init?.body ?? '' });
    const rh = Object.fromEntries(Object.entries(r.headers).map(([k, v]) => [k.toLowerCase(), v]));
    return { status: r.status, headers: { get: (n: string) => rh[n.toLowerCase()] ?? null }, text: async () => r.body };
  };
  const input = JSON.stringify({ seed, now: NOW.toISOString(), root: base64Encode(rootDer()), trustListUrl: TRUST_URL, offerUri, txCode });
  return { input, hostFetch, world };
}

test('the sdk-app main entry bundles for a neutral platform without any Node built-in', async () => {
  const r = await esbuild.build({ ...options, format: 'esm', entryPoints: ['@identra/sdk-app'], absWorkingDir: testDist, metafile: true, minify: true });
  const inputs = Object.keys(r.metafile!.inputs);
  assert.ok(inputs.some((p) => p.includes('@noble/ciphers')));
  assert.deepEqual(inputs.filter((p) => p.startsWith('node:') || !p.includes('/')), []);
  assert.deepEqual(inputs.filter((p) => /node_modules\/(jose|expo-[^/]*|react-native)\//.test(p)), []);
  assert.deepEqual(Object.values(r.metafile!.outputs)[0]!.imports, []);
  await assert.rejects(esbuild.build({ ...options, stdin: { contents: "import 'node:crypto';", resolveDir: testDist } }));

  const output = Object.values(r.metafile!.outputs)[0]!;
  const bytes = (match: (p: string) => boolean) => Object.entries(output.inputs).reduce((n, [p, v]) => n + (match(p) ? v.bytesInOutput : 0), 0);
  console.log(
    `# minified sdk-app main entry: ${r.outputFiles![0]!.text.length} bytes from ${Object.values(output.inputs).filter((v) => v.bytesInOutput > 0).length} files;` +
      ` sdk-app ${bytes((p) => p.startsWith('../dist/'))}, @noble/* ${bytes((p) => p.includes('@noble/'))}, @openid4vc/* ${bytes((p) => p.includes('@openid4vc/'))},` +
      ` zod ${bytes((p) => p.includes('/zod/'))}, sdk-core and its other dependencies the rest`,
  );
});

test('the bundle runs in a realm without crypto, Buffer, process or fetch; the globals it touches', async () => {
  const built = await esbuild.build({ ...options, format: 'iife', globalName: 'IdentraBundle', stdin: { contents: ENTRY, resolveDir: testDist } });
  const code = built.outputFiles![0]!.text;

  // Values from the full Node realm, for the interop parts.
  const outerKey = generateSecretKey(countingRandom());
  const outer = createNobleSigner(outerKey);
  const outerData = 'signed outside';
  const joseRecipient = generateSecretKey(countingRandom());
  const joseJwe = await new CompactEncrypt(utf8Encode('from jose'))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM' })
    .encrypt(await importJWK(createNobleSigner(joseRecipient).publicJwk, 'ECDH-ES'));
  const input = JSON.stringify({
    seed: 12345,
    now: '2026-11-19T08:00:00.000Z',
    compact: 'eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ4In0.c2ln~WyJzIiwiaG9fdGVuIiwiQSJd~',
    rfcJws:
      'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q',
    rfcJwk: { kty: 'EC', crv: 'P-256', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0' },
    outer: { publicJwk: outer.publicJwk, data: outerData, sig: base64UrlEncode(await outer.sign(utf8Encode(outerData))) },
    joseJwe,
    joseRecipientD: base64UrlEncode(joseRecipient),
  });

  // Every runtime read of a globalThis property goes through this proxy.
  const runtimeReads = new Set<string>();
  const ctx = restrictedRealm({ __record: (k: string) => runtimeReads.add(k) });
  assert.equal(vm.runInContext('[typeof crypto, typeof Buffer, typeof process, typeof fetch, typeof require, typeof window, typeof btoa, typeof console].join()', ctx), Array(8).fill('undefined').join());
  vm.runInContext(
    `globalThis.__load = function (globalThis) { ${code}; return IdentraBundle; };
     globalThis.__bundle = __load(new Proxy(globalThis, { get(t, k) { if (typeof k === 'string') __record(k); return Reflect.get(t, k); } }));`,
    ctx,
  );
  const got = JSON.parse(await vm.runInContext(`__bundle.run(${JSON.stringify(input)})`, ctx));
  const issuance = await issuanceInput(777);
  ctx['__hostFetch'] = issuance.hostFetch;
  const issued = JSON.parse(await vm.runInContext(`__bundle.issue(${JSON.stringify(issuance.input)}, __hostFetch)`, ctx));
  assert.equal(issued.accepted.ok, true, JSON.stringify(issued));
  assert.equal(issued.accepted.issuerName, 'Trường Mẫu (TEST)');
  assert.equal(issued.claims.ho_ten, 'Nguyễn Văn A');
  assert.deepEqual([issued.rows, issued.keys], [1, 1]);
  assert.equal(issuance.world.issued.length, 1);

  assert.equal(got.rfcA3, true);
  assert.equal(got.signVerify, true);
  assert.equal(got.tampered, false);
  assert.equal(got.outerSignatureOk, true);
  assert.equal(got.sha256, 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0');
  assert.equal(got.jweRoundTrip, '{"vp_token":"x"}');
  assert.equal(got.fromJose, 'from jose');
  assert.equal(utf8Decode((await compactDecrypt(got.forJose, await importJWK({ ...outer.publicJwk, d: base64UrlEncode(outerKey) }, 'ECDH-ES'))).plaintext), 'for jose');
  assert.equal(got.jweTamper, 'JWE_DECRYPTION_FAILED');
  assert.equal(got.keyStore, true);
  assert.equal(got.keyDeleted, 'KEY_NOT_FOUND');
  assert.equal(got.vaultRoundTrip, true);
  assert.equal(got.vaultCiphertextHasPlaintext, false);
  assert.equal(got.listed.length, 1);
  assert.equal(got.listed[0].status_cache, 'valid');
  assert.equal(got.catalogue, '{"version":1,"items":[{"vct":"https://v.example/vct","issuer":"https://i.example"}]}');
  assert.equal(base64UrlDecode(got.listed[0].id).length, 16);

  // Static: every free identifier and globalThis member the bundle references, executed or not.
  const linter = new Linter();
  const messages = linter.verify(code, {
    languageOptions: { ecmaVersion: 'latest', sourceType: 'script', globals: Object.fromEntries([...ECMASCRIPT_GLOBALS].map((g) => [g, 'readonly' as const])) },
    rules: { 'no-undef': ['error', { typeof: true }] },
  });
  assert.deepEqual(messages.filter((m) => m.ruleId !== 'no-undef'), []);
  const freeIdentifiers = [...new Set(messages.map((m) => /'(.+)' is not defined/.exec(m.message)![1]!))].sort();
  const members = [...new Set([...code.matchAll(/\bglobalThis\s*\.\s*([A-Za-z_$][\w$]*)/g)].map((m) => m[1]!))].filter((n) => !ECMASCRIPT_GLOBALS.has(n)).sort();
  const runtime = [...runtimeReads].filter((n) => !ECMASCRIPT_GLOBALS.has(n) && n !== 'IdentraBundle').sort();
  console.log(`# non-ECMAScript globals referenced as identifiers: ${freeIdentifiers.join(', ') || 'none'}`);
  console.log(`# non-ECMAScript globalThis members referenced: ${members.join(', ') || 'none'}`);
  console.log(`# non-ECMAScript globalThis members read at run time: ${runtime.join(', ') || 'none'}`);
  // Read through globalThis at run time: zod's own registry, and Buffer behind a typeof check (absent here).
  assert.deepEqual(runtime, ['Buffer', '__zod_globalConfig', '__zod_globalRegistry']);
  // Never referenced at all. Buffer, btoa, Blob, File, navigator and console are referenced (behind
  // typeof checks) by the dependency trees of sdk-core and of the OpenID4VC libraries; the runs above
  // show nothing here needs them. `globalThis.fetch` is the libraries' default when no fetch callback
  // is given; the wallet always gives one, and the realm has no fetch.
  for (const name of ['process', 'require', 'window', 'document', 'global', 'module', 'exports']) {
    assert.equal(freeIdentifiers.includes(name) || members.includes(name), false, name);
  }
  assert.equal(freeIdentifiers.includes('fetch'), false);
});

test('every web global the realm provides is needed: without any one of them, loading or the issuance fails', async () => {
  const built = await esbuild.build({ ...options, format: 'iife', globalName: 'IdentraBundle', stdin: { contents: ENTRY, resolveDir: testDist } });
  const code = built.outputFiles![0]!.text;
  const missing: string[] = [];
  for (const name of [...Object.keys(WEB_GLOBALS), 'TextEncoder']) {
    const ctx = restrictedRealm();
    vm.runInContext(`delete globalThis.${name};`, ctx);
    const issuance = await issuanceInput(779);
    ctx['__hostFetch'] = issuance.hostFetch;
    const outcome = await (async () => {
      vm.runInContext(code, ctx);
      return JSON.parse(await vm.runInContext(`IdentraBundle.issue(${JSON.stringify(issuance.input)}, __hostFetch)`, ctx)).accepted?.ok === true;
    })().catch(() => false);
    if (!outcome) missing.push(name);
  }
  console.log(`# globals the wallet needs (issuance fails without each): ${missing.join(', ')}`);
  assert.deepEqual(missing, [...Object.keys(WEB_GLOBALS), 'TextEncoder']);
});

test('with a counting crypto object present, the sdk-app operations never call getRandomValues', async () => {
  const built = await esbuild.build({ ...options, format: 'iife', globalName: 'IdentraBundle', stdin: { contents: ENTRY, resolveDir: testDist } });
  const outerKey = generateSecretKey(countingRandom());
  const outer = createNobleSigner(outerKey);
  const joseRecipient = generateSecretKey(countingRandom());
  const joseJwe = await new CompactEncrypt(utf8Encode('from jose')).setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' }).encrypt(await importJWK(createNobleSigner(joseRecipient).publicJwk, 'ECDH-ES'));
  let calls = 0;
  const ctx = restrictedRealm({
    crypto: {
      getRandomValues<T extends ArrayBufferView>(a: T): T {
        calls++;
        return a;
      },
    },
  });
  vm.runInContext(built.outputFiles![0]!.text, ctx);
  const atLoad = calls;
  const input = JSON.stringify({
    seed: 1,
    now: '2026-11-19T08:00:00.000Z',
    compact: 'a.b.c~',
    rfcJws: 'eyJhbGciOiJFUzI1NiJ9.e30.' + base64UrlEncode(new Uint8Array(64)),
    rfcJwk: outer.publicJwk,
    outer: { publicJwk: outer.publicJwk, data: 'x', sig: base64UrlEncode(await outer.sign(utf8Encode('x'))) },
    joseJwe,
    joseRecipientD: base64UrlEncode(joseRecipient),
  });
  JSON.parse(await vm.runInContext(`IdentraBundle.run(${JSON.stringify(input)})`, ctx));
  const issuance = await issuanceInput(778);
  ctx['__hostFetch'] = issuance.hostFetch;
  assert.equal(JSON.parse(await vm.runInContext(`IdentraBundle.issue(${JSON.stringify(issuance.input)}, __hostFetch)`, ctx)).accepted.ok, true);
  console.log(`# getRandomValues calls: ${atLoad} at bundle load, ${calls - atLoad} during the sdk-app operations and an issuance`);
  assert.equal(calls - atLoad, 0);
});

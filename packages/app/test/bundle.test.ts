// React Native proxy check (ADR-0004 "Bổ sung 2026-11-19"): the sdk-app main entry bundles with
// esbuild --platform=neutral and runs sign / verify, JWE, key store, vault and catalogue inside a
// node:vm realm holding only ECMAScript built-ins plus TextEncoder / TextDecoder: no crypto object
// at all, no Buffer, process, fetch, atob or btoa. This is a proxy, not Hermes on a phone.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import vm from 'node:vm';
import * as esbuild from 'esbuild';
import { Linter } from 'eslint';
import { base64UrlDecode, base64UrlEncode, utf8Decode, utf8Encode } from '@identra/sdk-core';
import { CompactEncrypt, compactDecrypt, importJWK } from 'jose';
import { createNobleSigner, generateSecretKey } from '@identra/sdk-app';
import { countingRandom } from './helpers/random.js';

const testDist = new URL('.', import.meta.url).pathname;
const options: esbuild.BuildOptions = { bundle: true, platform: 'neutral', mainFields: ['module', 'main'], write: false, logLevel: 'silent' };

/** The names a fresh realm starts with, minus the two that are not ECMAScript. */
const ECMASCRIPT_GLOBALS = new Set(Object.getOwnPropertyNames(vm.runInNewContext('globalThis')).filter((n) => n !== 'console' && n !== 'WebAssembly'));

/** ECMAScript built-ins plus TextEncoder (defined in the realm, like Hermes) and TextDecoder (React Native needs a polyfill). */
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
  Object.assign(ctx, { TextDecoder }, extra);
  return ctx;
}

// Runs inside the realm. Randomness is a deterministic test generator: there is no crypto object.
const ENTRY = `
  import * as app from '@identra/sdk-app';
  import { base64UrlDecode, base64UrlEncode, utf8Encode, utf8Decode, decodeJws, verifyJws } from '@identra/sdk-core';
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
  }`;

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
      ` sdk-app ${bytes((p) => p.startsWith('../dist/'))}, @noble/* ${bytes((p) => p.includes('@noble/'))}, sdk-core and its dependencies the rest`,
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
  assert.equal(vm.runInContext('[typeof crypto, typeof Buffer, typeof process, typeof fetch, typeof require, typeof window, typeof atob, typeof console].join()', ctx), Array(8).fill('undefined').join());
  vm.runInContext(
    `globalThis.__load = function (globalThis) { ${code}; return IdentraBundle; };
     globalThis.__bundle = __load(new Proxy(globalThis, { get(t, k) { if (typeof k === 'string') __record(k); return Reflect.get(t, k); } }));`,
    ctx,
  );
  const got = JSON.parse(await vm.runInContext(`__bundle.run(${JSON.stringify(input)})`, ctx));

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
  // Never referenced at all. Buffer, atob, btoa, Blob, File, URL, navigator and console are
  // referenced (behind typeof checks) by sdk-core's dependency tree (@sd-jwt/*, @owf/*, cbor-x,
  // pako, zod), not by sdk-app; the run above shows nothing here needs them.
  for (const name of ['process', 'fetch', 'require', 'window', 'document', 'global', 'module', 'exports']) {
    assert.equal(freeIdentifiers.includes(name) || members.includes(name), false, name);
  }
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
  console.log(`# getRandomValues calls: ${atLoad} at bundle load, ${calls - atLoad} during the sdk-app operations`);
  assert.equal(calls - atLoad, 0);
});

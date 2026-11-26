// Trust list: strict payload validation, the token (signed directly by a pinned root), and the
// registry (lookup, validity window, purpose mapping, caching with a fake clock and fetch).
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  createSignedTrustListRegistry, createTrustListToken, TrustListUnavailableError, validateTrustListContent, validateTrustListPayload,
  VCT, verifyTrustListToken, type SeenStore, type TrustListContent,
} from '@identra/sdk-core';
import { webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { b64, ca, leaf, NOW } from './helpers/pki.js';
import {
  demoContent, fakeClock, FP, LATER_SIGNER_NOT_BEFORE, laterTrustListSigner, ok, ORG, otherOrgStatus, scriptedFetch, servedRegistry, TRUST_URL, trustListSigner, trustToken,
} from './helpers/lists.js';
import { issuerSigner, NOW_S, rawJws, validator } from './helpers/sdjwt.js';

const base = await demoContent();
const clone = (): TrustListContent => JSON.parse(JSON.stringify(base));
const invalid = (mutate: (c: TrustListContent & Record<string, unknown>) => void, detail: RegExp) => {
  const c = clone() as TrustListContent & Record<string, unknown>;
  mutate(c);
  const r = validateTrustListContent(c);
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.detail, detail);
};
const any = (v: unknown) => v as never;
const rec = (v: unknown) => v as Record<string, unknown>;

describe('payload validation', () => {
  test('the demo content is valid', () => assert.equal(validateTrustListContent(base).ok, true));
  test('unknown purpose, and a purpose that does not fit its section', () => {
    invalid((c) => (c.issuers[0]!.chung_thu[0]!.muc_dich = any('sign')), /not a known purpose/);
    invalid((c) => (c.issuers[0]!.chung_thu[0]!.muc_dich = any('request')), /does not fit this section/);
    invalid((c) => (c.verifiers[0]!.chung_thu[0]!.muc_dich = any('vc')), /does not fit this section/);
    invalid((c) => (c.verifiers[0]!.chung_thu[0]!.muc_dich = any('status')), /does not fit this section/);
  });
  test('malformed fingerprints', () => {
    for (const sha256 of [FP.vc.slice(1), `${FP.vc}A`, `${FP.vc.slice(0, -1)}+`, `${FP.vc.slice(0, -1)}=`, `${FP.vc.slice(0, -1)}B`, 42]) {
      invalid((c) => (c.issuers[0]!.chung_thu[0]!.sha256 = any(sha256)), /not a base64url SHA-256 fingerprint/);
    }
  });
  test('the same fingerprint twice anywhere is ambiguous', () => {
    invalid((c) => (c.issuers[0]!.chung_thu[1]!.sha256 = FP.vc), /listed more than once/);
    invalid((c) => (c.issuers[1]!.chung_thu[0]!.sha256 = FP.vc), /listed more than once/);
    invalid((c) => (c.verifiers[0]!.chung_thu[0]!.sha256 = FP.vc), /listed more than once/);
  });
  test('non-array fields', () => {
    invalid((c) => (c.issuers = any({})), /issuers must be an array/);
    invalid((c) => (c.verifiers = any('x')), /verifiers must be an array/);
    invalid((c) => (c.issuers[0]!.chung_thu = any(c.issuers[0]!.chung_thu[0])), /chung_thu must be an array/);
    invalid((c) => (c.issuers[0]!.vct = any(VCT.diploma)), /vct must be an array/);
    invalid((c) => (c.issuers[1]!.cong_doan = any('san_xuat')), /cong_doan must be an array/);
  });
  test('other shapes', () => {
    invalid((c) => (c['extra'] = 1), /unknown field/);
    invalid((c) => (rec(c.issuers[0])['scope'] = 1), /issuers\[0\] has an unknown field/);
    invalid((c) => (rec(c.issuers[0]!.chung_thu[0])['note'] = 1), /unknown field/);
    invalid((c) => (c.issuers[0]!.chung_thu = []), /must not be empty/);
    invalid((c) => (c.issuers[0]!.ma_to_chuc = '0100000001'), /VATVN-<tax code>/);
    invalid((c) => (c.verifiers[0]!.ma_to_chuc = any(5)), /ma_to_chuc must be a non-empty string/);
    invalid((c) => (c.issuers[0]!.ten = ''), /ten must be a non-empty string/);
    invalid((c) => (c.issuers[0]!.vct = [any(1)]), /vct\[0\]/);
    invalid((c) => (c.issuers[1]!.cong_doan = ['dong_goi']), /not a known stage/);
    invalid((c) => (c.issuers = Array(1001).fill(c.issuers[0])), /more than 1000/);
    invalid((c) => ((c.issuers = Array(500).fill(c.issuers[0])), (c.verifiers = Array(501).fill(c.verifiers[0]))), /more than 1000 entries/);
    invalid((c) => (c.issuers[1]!.ma_to_chuc = c.issuers[0]!.ma_to_chuc), /issuers\[1\]\.ma_to_chuc is listed more than once in issuers/);
    invalid((c) => (c.verifiers = [c.verifiers[0]!, { ...c.verifiers[0]!, chung_thu: [{ sha256: 'B'.repeat(42) + 'A', muc_dich: 'request' }] }]), /ma_to_chuc is listed more than once in verifiers/);
    invalid((c) => (c.issuers[0]!.vct = []), /vct must not be empty/);
    const both = clone();
    both.verifiers[0]!.ma_to_chuc = both.issuers[0]!.ma_to_chuc;
    assert.equal(validateTrustListContent(both).ok, true, 'one organisation may be issuer and verifier');
    assert.equal(validateTrustListContent(null).ok, false);
  });
  test('ISO 8601 instants', () => {
    invalid((c) => delete rec(c.issuers[0])['validFrom'], /validFrom is not an ISO 8601 UTC instant/);
    invalid((c) => (c.issuers[0]!.validFrom = '2026-01-01'), /validFrom is not an ISO 8601/);
    invalid((c) => (c.issuers[0]!.validFrom = '2026-01-01T00:00:00+07:00'), /validFrom is not an ISO 8601/);
    invalid((c) => (c.issuers[0]!.validFrom = '2026-02-30T00:00:00Z'), /validFrom is not a valid instant/);
    invalid((c) => (c.issuers[0]!.validUntil = c.issuers[0]!.validFrom), /validFrom must be before validUntil/);
    invalid((c) => (c.verifiers[0]!.validFrom = '2026-01-01T00:00:00Z'), /validUntil is not an ISO 8601/);
    const ok = clone();
    ok.verifiers[0]!.validFrom = '2026-01-01T00:00:00.000Z';
    ok.verifiers[0]!.validUntil = '2027-01-01T00:00:00Z';
    assert.equal(validateTrustListContent(ok).ok, true);
  });
  test('payload numbers', () => {
    const p = { iat: NOW_S, exp: NOW_S + 86_400, ttl: 3600, ...clone() };
    assert.equal(validateTrustListPayload(p).ok, true);
    assert.equal(validateTrustListPayload({ ...p, signer_not_before: NOW_S - 86_400 }).ok, true);
    for (const patch of [{ iat: 1.5 }, { exp: '1' }, { ttl: 0 }, { ttl: undefined }, { other: 1 }, { signer_not_before: 0 }, { signer_not_before: '1' }]) {
      assert.equal(validateTrustListPayload({ ...p, ...patch }).ok, false, JSON.stringify(patch));
    }
  });
});

describe('trust list token', async () => {
  const signer = await trustListSigner();
  const opts = (now = NOW) => ({ chainValidator: validator, verifier: webCryptoVerifier, now });
  const payload = (o = {}) => ({ iat: NOW_S, exp: NOW_S + 86_400, ttl: 3600, ...clone(), ...o });
  const reason = async (token: unknown, now = NOW) => {
    const r = await verifyTrustListToken(token, opts(now));
    return r.ok ? 'ok' : `${r.reason}: ${r.detail}`;
  };

  test('a good token: header and payload', async () => {
    const t = await trustToken();
    const h = JSON.parse(Buffer.from(t.split('.')[0]!, 'base64url').toString());
    assert.deepEqual(h, { alg: 'ES256', typ: 'identra-trust-list+jwt', x5c: [b64(leaf('trust-list'))] });
    const r = await verifyTrustListToken(t, opts());
    assert.ok(r.ok);
    assert.deepEqual(r.payload, payload());
  });
  test('a token signed by a certificate of the Issuing CA is refused', async () => {
    const vc = await issuerSigner();
    assert.match(await reason(await rawJws({ alg: 'ES256', typ: 'identra-trust-list+jwt', x5c: [vc.x5c![0]] }, payload(), vc)), /^chain: .*CERT_CHAIN_UNTRUSTED/);
    assert.match(await reason(await rawJws({ alg: 'ES256', typ: 'identra-trust-list+jwt', x5c: vc.x5c }, payload(), vc)), /^chain: .*CERT_CHAIN_MALFORMED/);
    await assert.rejects(createTrustListToken({ ...clone(), signer: vc, now: NOW }), /exactly its own certificate/);
  });
  test('a valid trust-list certificate together with a DID kid is malformed (one trust path per token, ADR-0020 section 2)', async () => {
    const h = { alg: 'ES256', typ: 'identra-trust-list+jwt', x5c: signer.x5c };
    assert.match(await reason(await rawJws({ ...h, kid: 'did:certnet:local:a1b2c3d4e5f67890#key-1' }, payload(), signer)), /^malformed: the header carries both x5c and a DID kid/);
    assert.equal(await reason(await rawJws({ ...h, kid: 'key-1' }, payload(), signer)), 'ok', 'a kid that is no DID changes nothing');
  });
  test('two certificates in x5c are refused', async () => {
    const x5c = [b64(leaf('trust-list')), b64(ca('root'))];
    assert.match(await reason(await rawJws({ alg: 'ES256', typ: 'identra-trust-list+jwt', x5c }, payload(), signer)), /^chain: .*CERT_CHAIN_MALFORMED/);
    await assert.rejects(createTrustListToken({ ...clone(), signer: { ...signer, x5c }, now: NOW }), TypeError);
  });
  test('typ, alg, signature, size, times and payload', async () => {
    const h = { alg: 'ES256', typ: 'identra-trust-list+jwt', x5c: signer.x5c };
    assert.match(await reason(await rawJws({ ...h, typ: 'statuslist+jwt' }, payload(), signer)), /^typ/);
    assert.match(await reason(await rawJws({ ...h, alg: 'none' }, payload(), signer)), /^alg/);
    assert.match(await reason((await trustToken()).slice(0, -4) + 'AAAA'), /^signature/);
    assert.match(await reason('a'.repeat(256 * 1024 + 1)), /^too_large/);
    assert.match(await reason(await trustToken(undefined, new Date(NOW.getTime() + 61_000))), /^not_yet_valid/);
    assert.match(await reason(await trustToken(), new Date(NOW.getTime() + 86_460_000)), /^expired/);
    assert.match(await reason(await rawJws(h, payload({ exp: undefined }), signer)), /^claims: exp is missing/);
    const dup = clone();
    dup.issuers[0]!.chung_thu[1]!.sha256 = FP.vc;
    assert.match(await reason(await rawJws(h, payload(dup), signer)), /^claims: .*listed more than once/);
  });
});

describe('registry lookup', async () => {
  const { fingerprint: otherStatus } = await otherOrgStatus();
  test('purpose mapping from the matched certificate', async () => {
    const { registry } = await servedRegistry();
    assert.deepEqual(await registry.lookup(FP.vc), { maToChuc: ORG.truongMau, ten: 'Trường Mẫu (TEST)', mucDich: 'vc', vct: [VCT.diploma] });
    assert.deepEqual(await registry.lookup(FP.status), { maToChuc: ORG.truongMau, ten: 'Trường Mẫu (TEST)', mucDich: 'status', vct: [VCT.diploma] });
    assert.deepEqual(await registry.lookup(FP.vcProduct), {
      maToChuc: ORG.nhaSanXuat, ten: 'Nhà Sản Xuất (TEST)', mucDich: 'vc', vct: [VCT.productEvent], congDoan: ['san_xuat'],
    });
    assert.equal((await registry.lookup(otherStatus))?.mucDich, 'status');
    assert.deepEqual(await registry.lookup(FP.request), { maToChuc: ORG.nhaTuyenDung, ten: 'Nhà Tuyển Dụng Mẫu (TEST)', mucDich: 'request' });
    assert.equal(await registry.lookup('A'.repeat(43)), null);
    assert.equal(await registry.lookup(any(undefined)), null);
  });
  test('validity window [validFrom - 60 s, validUntil + 60 s], inclusive', async () => {
    const c = clone();
    c.verifiers[0]!.validFrom = '2026-03-01T00:00:00Z';
    c.verifiers[0]!.validUntil = '2026-09-01T00:00:00Z';
    const { registry } = await servedRegistry(await trustToken(c));
    const at = (s: string) => new Date(s);
    assert.equal(await registry.lookup(FP.vc, at('2025-12-31T23:58:59.999Z')), null);
    assert.ok(await registry.lookup(FP.vc, at('2025-12-31T23:59:00Z')), 'validFrom - 60 s skew');
    assert.ok(await registry.lookup(FP.vc, at('2029-01-01T00:01:00Z')), 'validUntil + 60 s skew');
    assert.equal(await registry.lookup(FP.vc, at('2029-01-01T00:01:00.001Z')), null);
    assert.ok(await registry.lookup(FP.vc), 'default: clock.now()');
    assert.equal(await registry.lookup(FP.request, at('2026-02-28T23:58:59Z')), null);
    assert.ok(await registry.lookup(FP.request, at('2026-06-01T00:00:00Z')));
    const { registry: open } = await servedRegistry();
    assert.ok(await open.lookup(FP.request, at('2099-01-01T00:00:00Z')), 'a verifier without a window');
  });
  test('an entry is a copy', async () => {
    const { registry } = await servedRegistry();
    (await registry.lookup(FP.vc))!.vct!.push('https://evil.example/vct');
    assert.deepEqual((await registry.lookup(FP.vc))!.vct, [VCT.diploma]);
  });
});

describe('registry cache', async () => {
  const setup = async (o: { maxAgeSeconds?: number } = {}) => {
    const clock = fakeClock();
    const s = scriptedFetch({ [TRUST_URL]: ok(await trustToken()) });
    const registry = createSignedTrustListRegistry({ url: TRUST_URL, fetch: s.fetch, verifier: webCryptoVerifier, chainValidator: validator, clock, ...o });
    return { clock, registry, ...s };
  };
  test('nothing is fetched until the first lookup; then fresh for ttl 3600 s', async () => {
    const w = await setup();
    assert.equal(w.calls.length, 0);
    assert.equal(w.registry.current(), null);
    await w.registry.lookup(FP.vc);
    w.clock.advance(3599);
    await w.registry.lookup(FP.status);
    assert.deepEqual(w.calls, [{ url: TRUST_URL, timeoutMs: 5000, maxBytes: 262_144 }]);
    assert.deepEqual(w.registry.current(), { iat: NOW_S, exp: NOW_S + 86_400, ttl: 3600, issuers: 2, verifiers: 1 });
    w.clock.advance(1);
    w.routes[TRUST_URL] = ok(await trustToken(undefined, w.clock.now()));
    await w.registry.lookup(FP.vc);
    assert.equal(w.calls.length, 2);
    assert.equal(w.registry.current()?.iat, NOW_S + 3600);
  });
  test('no copy: TrustListUnavailableError', async () => {
    const w = await setup();
    w.routes[TRUST_URL] = { status: 503, body: '' };
    await assert.rejects(w.registry.lookup(FP.vc), TrustListUnavailableError);
    assert.equal(await w.registry.refresh(), false);
    assert.equal(w.calls.length, 2);
  });
  test('refetch failure: the held copy until exp (+60 s), then TrustListUnavailableError', async () => {
    const w = await setup();
    await w.registry.lookup(FP.vc);
    w.routes[TRUST_URL] = new Error('host unreachable');
    w.clock.advance(86_400 + 59);
    assert.ok(await w.registry.lookup(FP.vc));
    w.clock.advance(1);
    await assert.rejects(w.registry.lookup(FP.vc), TrustListUnavailableError);
    assert.equal(w.calls.length, 3);
  });
  test('an older iat never replaces the held copy; an invalid one neither', async () => {
    const w = await setup();
    const c = clone();
    c.issuers = c.issuers.slice(1);
    w.routes[TRUST_URL] = ok(await trustToken(c, new Date(NOW.getTime() + 30_000)));
    await w.registry.lookup(FP.vc);
    assert.equal(await w.registry.lookup(FP.vc), null, 'the newer list without Truong Mau');
    w.routes[TRUST_URL] = ok(await trustToken(undefined, NOW));
    assert.equal(await w.registry.refresh(), true);
    assert.equal(await w.registry.lookup(FP.vc), null, 'the older list was refused');
    w.routes[TRUST_URL] = ok((await trustToken(undefined, w.clock.now())).slice(0, -4) + 'AAAA');
    w.clock.advance(3600);
    assert.equal(await w.registry.lookup(FP.vc), null);
    assert.equal(w.calls.length, 3);
  });
  test('maxAgeSeconds 0 refetches on every lookup; refresh() forces a fetch', async () => {
    const w = await setup({ maxAgeSeconds: 0 });
    await w.registry.lookup(FP.vc);
    await w.registry.lookup(FP.vc);
    assert.equal(w.calls.length, 2);
    const v = await setup();
    await v.registry.lookup(FP.vc);
    assert.equal(await v.registry.refresh(), true);
    assert.equal(v.calls.length, 2);
  });
  test('concurrent lookups share one fetch', async () => {
    const w = await setup();
    await Promise.all([FP.vc, FP.status, FP.request].map((fp) => w.registry.lookup(fp)));
    assert.equal(w.calls.length, 1);
  });
  test('only an https url', () => {
    assert.throws(() => createSignedTrustListRegistry({ url: 'http://x/trust-list', fetch: async () => any(0), verifier: webCryptoVerifier, chainValidator: validator, clock: fakeClock() }), TypeError);
  });
});

describe('ADR-0019: lifetime caps, signer_not_before, persistence', async () => {
  const old = await trustListSigner();
  const later = await laterTrustListSigner();
  const h = (signer: typeof old) => ({ alg: 'ES256', typ: 'identra-trust-list+jwt', x5c: signer.x5c });
  const memory = () => {
    const store = new Map<string, number>();
    const seen: SeenStore = { get: async (k) => store.get(k) ?? null, set: async (k, v) => void store.set(k, v) };
    return { store, seen };
  };
  const registryFor = (s: ReturnType<typeof scriptedFetch>, clock = fakeClock(), seen?: SeenStore) =>
    createSignedTrustListRegistry({ url: TRUST_URL, fetch: s.fetch, verifier: webCryptoVerifier, chainValidator: validator, clock, ...(seen ? { seen } : {}) });

  test('E1: a forged list with ttl 2^52 and exp +10 y is refused', async () => {
    const forged = await rawJws(h(old), { iat: NOW_S + 59, exp: NOW_S + 10 * 365 * 86_400, ttl: 2 ** 52, ...clone() }, old);
    const r = await verifyTrustListToken(forged, { chainValidator: validator, verifier: webCryptoVerifier, now: NOW });
    assert.equal(r.ok ? 'ok' : `${r.reason}: ${r.detail}`, 'claims: exp - iat is more than 24 hours');
    await assert.rejects(createTrustListToken({ ...clone(), signer: old, now: NOW, lifetimeSeconds: 86_401 }), TypeError);
  });
  test('E2: with ttl 2^52 inside 24 h the list is refetched after 3600 s and a removal arrives', async () => {
    const big = await rawJws(h(old), { iat: NOW_S, exp: NOW_S + 86_400, ttl: 2 ** 52, ...clone() }, old);
    const s = scriptedFetch({ [TRUST_URL]: ok(big) });
    const clock = fakeClock();
    const registry = registryFor(s, clock);
    assert.ok(await registry.lookup(FP.vc));
    clock.advance(3600);
    s.routes[TRUST_URL] = ok(await trustToken({ ...clone(), issuers: clone().issuers.slice(1) }, clock.now()));
    assert.equal(await registry.lookup(FP.vc), null);
    assert.equal(s.calls.length, 2);
  });
  test('signer_not_before: after it was seen, a list of the replaced signer is refused even with a newer iat', async () => {
    const withoutVerifier = { ...clone(), verifiers: [] };
    const s = scriptedFetch({ [TRUST_URL]: ok(await trustToken(withoutVerifier, NOW, { signer: later, signerNotBefore: LATER_SIGNER_NOT_BEFORE })) });
    const clock = fakeClock();
    const { store, seen } = memory();
    const registry = registryFor(s, clock, seen);
    assert.equal(await registry.lookup(FP.request), null);
    assert.deepEqual(Object.fromEntries(store), { [`iat:${TRUST_URL}`]: NOW_S, [`signer-not-before:${TRUST_URL}`]: LATER_SIGNER_NOT_BEFORE });
    clock.advance(10);
    s.routes[TRUST_URL] = ok(await trustToken(clone(), clock.now(), { signer: old }));
    assert.equal(await registry.refresh(), true);
    assert.equal(await registry.lookup(FP.request), null, 'still the list of the new signer');
    // The same refusal directly, and after a restart with the persisted state.
    const r = await verifyTrustListToken(await trustToken(clone(), clock.now(), { signer: old }), { chainValidator: validator, verifier: webCryptoVerifier, now: clock.now(), minSignerNotBefore: LATER_SIGNER_NOT_BEFORE });
    assert.equal(r.ok ? 'ok' : r.reason, 'not_trusted');
    const restarted = registryFor(scriptedFetch({ [TRUST_URL]: ok(await trustToken(clone(), clock.now(), { signer: old })) }), clock, seen);
    await assert.rejects(restarted.lookup(FP.vc), TrustListUnavailableError);
    // The new signer keeps working.
    const fresh = registryFor(scriptedFetch({ [TRUST_URL]: ok(await trustToken(clone(), clock.now(), { signer: later })) }), clock, seen);
    assert.ok(await fresh.lookup(FP.request));
  });
  test('a list whose signer_not_before is later than its own signer notBefore is invalid', async () => {
    const t = await rawJws(h(old), { iat: NOW_S, exp: NOW_S + 86_400, ttl: 3600, signer_not_before: LATER_SIGNER_NOT_BEFORE, ...clone() }, old);
    const r = await verifyTrustListToken(t, { chainValidator: validator, verifier: webCryptoVerifier, now: NOW });
    assert.match(r.ok ? 'ok' : `${r.reason}: ${r.detail}`, /^claims: signer_not_before is later/);
    await assert.rejects(trustToken(clone(), NOW, { signer: old, signerNotBefore: LATER_SIGNER_NOT_BEFORE }), /signerNotBefore must be/);
  });
  test('seen: an older iat is refused after a restart', async () => {
    const { seen } = memory();
    await registryFor(scriptedFetch({ [TRUST_URL]: ok(await trustToken(clone(), new Date(NOW.getTime() + 30_000))) }), fakeClock(), seen).lookup(FP.vc);
    const restarted = registryFor(scriptedFetch({ [TRUST_URL]: ok(await trustToken(clone(), NOW)) }), fakeClock(), seen);
    await assert.rejects(restarted.lookup(FP.vc), TrustListUnavailableError);
  });
});


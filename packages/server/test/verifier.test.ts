// The OpenID4VP verifier called directly, as a controller would (no HTTP, no wallet): construction
// rules, the request object, which responses may finalise a session (only a proven holder), the
// flood cap, exactly once under concurrency, storage failure while finalising, what is left in the
// store afterwards, and the hourly trust-list re-check.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, test } from 'node:test';
import { CompactEncrypt, importJWK, type JWK } from 'jose';
import {
  base64Decode, base64Encode, base64UrlDecode, base64UrlEncode, createCertificateChainValidator, createPresentation, issueDiploma, utf8Decode, utf8Encode, VCT,
  type Signer, type TrustEntry,
} from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair, webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { createMemoryStateStore, createPresentationVerifier, MAX_RESPONSE_ATTEMPTS, type ProtocolStateStore } from '@identra/sdk-server';
import { fakeClock } from './helpers.js';

const ISS = 'https://api-identra.awncorp.vn/issuers/truong-mau';
const NOW = new Date('2026-06-01T00:00:00Z');
const PKI = new URL('../../../.pki/test/', import.meta.url);
const pem = (p: string) => readFileSync(new URL(p, PKI), 'utf8');
const der = (p: string) => base64Decode(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END/.exec(pem(p))![1]!.replace(/\s+/g, ''));
const signerOf = (leaf: string) => createWebCryptoSigner({ privateKey: pem(`leaf/${leaf}.key.pem`), x5c: [base64Encode(der(`leaf/${leaf}.cert.pem`)), base64Encode(der('ca/issuing/ca.cert.pem'))] });
const fingerprint = async (leaf: string) => base64UrlEncode(await webCryptoHasher.sha256(der(`leaf/${leaf}.cert.pem`)));
const chainValidator = createCertificateChainValidator({ trustedRoots: [der('ca/root/ca.cert.pem')], verifier: webCryptoVerifier, hasher: webCryptoHasher });
const SCENARIO = { vct: VCT.diploma, claimSets: [['ho_ten', 'nganh', 'hang_tot_nghiep', 'nam_tot_nghiep'], ['ho_ten', 'nganh']], purpose: { vi: 'Ứng tuyển', en: 'Job application' } };
const DIPLOMA = { ho_ten: 'Nguyễn Văn A', ngay_sinh: '2001-02-03', ma_sinh_vien: 'SV1', nganh: 'CNTT', hang_tot_nghiep: 'Giỏi', nam_tot_nghiep: '2024', so_hieu_bang: 'B-1' };
type RequestPayload = {
  nonce: string; state: string; client_id: string; response_type: string; response_mode: string; aud: string; iat: number; exp: number;
  client_metadata: { jwks: { keys: { kty: string; crv: string; x: string; y: string; kid: string }[] } };
};
const form = (body: string, contentType = 'application/x-www-form-urlencoded') => ({ headers: { 'content-type': contentType }, body });

async function world(o: { store?: (s: ProtocolStateStore) => ProtocolStateStore; requestEntry?: Partial<TrustEntry> | null; signer?: string; claimSets?: string[][] } = {}) {
  const clock = fakeClock(NOW);
  const entries = new Map<string, TrustEntry | null>([
    [await fingerprint('vc'), { maToChuc: 'VATVN-0100000001', ten: 'Trường Mẫu', mucDich: 'vc', vct: [VCT.diploma] }],
    [await fingerprint('request'), o.requestEntry === null ? null : { maToChuc: 'VATVN-0100000005', ten: 'Nhà Tuyển Dụng Mẫu', mucDich: 'request', ...o.requestEntry }],
  ]);
  const trustRegistry = { lookup: async (fp: string) => entries.get(fp) ?? null };
  const memory = createMemoryStateStore(clock);
  const puts: string[] = [];
  const recording: ProtocolStateStore = { ...memory, put: (k, v, t) => (puts.push(k), memory.put(k, v, t)) };
  const store = (o.store ?? ((s) => s))(recording);
  const verifier = await createPresentationVerifier({
    apiOrigin: 'https://api-identra.awncorp.vn', signer: await signerOf(o.signer ?? 'request'),
    verification: { verifier: webCryptoVerifier, hasher: webCryptoHasher, chainValidator, trustRegistry, statusChecker: { check: async () => 'valid' }, supportedVcts: [VCT.diploma] },
    random: webCryptoRandom, clock, store, scenarios: { 'ung-tuyen': o.claimSets ? { ...SCENARIO, claimSets: o.claimSets } : SCENARIO },
  });
  const holder = await createWebCryptoSigner(await generateWebCryptoKeyPair());
  const credential = await issueDiploma({
    signer: await signerOf('vc'), hasher: webCryptoHasher, random: webCryptoRandom, clock, iss: ISS, cnfJwk: holder.publicJwk, status: { idx: 7, uri: `${ISS}/status/1` }, claims: DIPLOMA,
  });
  const session = async () => {
    const r = await verifier.createSession({ scenario: 'ung-tuyen' });
    assert.ok(r.ok);
    const jwt = (await verifier.requestObject(r.session.requestId))!.body;
    return { ...r.session, jwt, payload: JSON.parse(utf8Decode(base64UrlDecode(jwt.split('.')[1]!))) as RequestPayload };
  };
  const present = (p: RequestPayload, o2: { signer?: Signer; nonce?: string; disclose?: string[] } = {}) =>
    createPresentation({ compact: credential, disclose: o2.disclose ?? SCENARIO.claimSets[1]!, holderSigner: o2.signer ?? holder, audience: verifier.clientId, nonce: o2.nonce ?? p['nonce'], now: clock.now(), hasher: webCryptoHasher });
  const encrypt = async (p: RequestPayload, body: unknown, header: Record<string, unknown> = {}) => {
    const { kty, crv, x, y, kid } = p['client_metadata'].jwks.keys[0]!;
    return new CompactEncrypt(utf8Encode(JSON.stringify(body))).setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid, ...header }).encrypt(await importJWK({ kty, crv, x, y } as JWK, 'ECDH-ES'));
  };
  /** The HTTP response, with the outcome alongside; an unknown request (null) reads as 400. */
  const answer = async (s: Awaited<ReturnType<typeof session>>, vpToken: unknown, header?: Record<string, unknown>) => {
    const handled = await verifier.handleResponse(s.requestId, form(`response=${await encrypt(s.payload, { vp_token: vpToken, state: s.payload['state'] }, header)}`));
    return { status: handled?.response.status ?? 400, outcome: handled?.outcome ?? null };
  };
  return { clock, verifier, entries, memory, puts, holder, session, present, encrypt, answer };
}

describe('construction and the request object', () => {
  test('the request certificate must be listed with purpose request and its own organisation', async () => {
    await assert.rejects(world({ signer: 'vc' }), /purpose request/, 'an issuer certificate (purpose vc)');
    await assert.rejects(world({ requestEntry: null }), /purpose request/, 'not listed');
    await assert.rejects(world({ requestEntry: { mucDich: 'vc' } }), /purpose request/, 'listed for another purpose');
    await assert.rejects(world({ requestEntry: { maToChuc: 'VATVN-0100000009' } }), /purpose request/, 'another organisation');
  });

  test('a scenario whose claim sets do not shrink strictly (ADR-0008 section 5) is refused at construction', async () => {
    for (const claimSets of [[['ho_ten'], ['ho_ten', 'nganh']], [['ho_ten', 'nganh'], ['ho_ten', 'nganh']], [['ho_ten', 'nganh'], ['nam_tot_nghiep']], [['ho_ten', 'ho_ten']], [],
      [['ho_ten', 'nganh', 'hang_tot_nghiep', 'nam_tot_nghiep', 'so_hieu_bang'], ['ho_ten', 'nganh', 'hang_tot_nghiep', 'nam_tot_nghiep'], ['ho_ten', 'nganh', 'hang_tot_nghiep'], ['ho_ten', 'nganh'], ['ho_ten']]]) {
      await assert.rejects(world({ claimSets }), /proper subset/, JSON.stringify(claimSets));
    }
    await world({ claimSets: [['ho_ten', 'nganh', 'hang_tot_nghiep', 'nam_tot_nghiep'], ['ho_ten', 'nganh', 'hang_tot_nghiep'], ['ho_ten', 'nganh'], ['ho_ten']] });
  });

  test('the request object: header, 256-bit nonce and state, exactly one encryption key, the fixed members', async () => {
    const w = await world();
    const s = await w.session();
    const header = JSON.parse(utf8Decode(base64UrlDecode(s.jwt.split('.')[0]!)));
    assert.deepEqual([header.typ, header.alg, header.x5c.length], ['oauth-authz-req+jwt', 'ES256', 2]);
    assert.equal(s.payload['nonce'].length, 43);
    assert.equal(s.payload['state'].length, 43);
    assert.equal(s.payload['client_metadata'].jwks.keys.length, 1);
    assert.deepEqual([s.payload['response_type'], s.payload['response_mode'], s.payload['aud'], s.payload['exp'] - s.payload['iat']], ['vp_token', 'direct_post.jwt', 'https://self-issued.me/v2', 300]);
    assert.equal(s.payload['client_id'], `x509_hash:${await fingerprint('request')}`);
    assert.deepEqual(await w.verifier.createSession({ scenario: 'other' }), { ok: false, reason: 'unknown_scenario' });
  });
});

describe('which responses finalise a session', () => {
  test('a garbage vp_token or any other shape leaves the session open (V2, V6); the holder then verifies', async () => {
    const w = await world();
    const s = await w.session();
    const vp = await w.present(s.payload);
    const shapes: [string, unknown][] = [
      ['garbage', { credential: ['garbage'] }],
      ['two in the array', { credential: [vp, vp] }],
      ['an extra id', { credential: [vp], other: [vp] }],
      ['another id only', { other: [vp] }],
      ['an object entry', { credential: [{ a: 1 }] }],
      ['a bare string', { credential: vp }],
      ['a JSON string token', JSON.stringify({ credential: [vp] })],
      ['an empty array', { credential: [] }],
      ['an array token', [vp]],
    ];
    for (const [name, token] of shapes) {
      assert.equal((await w.answer(s, token)).status, 400, name);
      assert.equal((await w.verifier.session(s.id))?.status, 'request_retrieved', name);
    }
    assert.equal((await w.answer(s, { credential: [vp] })).status, 200);
    const done = await w.verifier.session(s.id);
    assert.equal(done?.status, 'verified');
    assert.deepEqual(done?.result?.claims, { ho_ten: DIPLOMA.ho_ten, nganh: DIPLOMA.nganh });
  });

  test('a compressed JWE, the wrong content type and a KB-JWT for another nonce are refused too', async () => {
    const w = await world();
    const s = await w.session();
    const vp = await w.present(s.payload);
    assert.equal((await w.answer(s, { credential: [vp] }, { zip: 'DEF' })).status, 400, 'a compressed JWE');
    const plain = await w.verifier.handleResponse(s.requestId, form(`response=${await w.encrypt(s.payload, { vp_token: { credential: [vp] }, state: s.payload['state'] })}`, 'text/plain'));
    assert.deepEqual([plain?.response.status, plain?.outcome], [400, { sessionId: s.id, final: false, code: 'MALFORMED' }], 'the content type');
    assert.equal((await w.answer(s, { credential: [await w.present(s.payload, { nonce: 'n'.repeat(43) })] })).status, 400, 'wrong nonce');
    assert.equal((await w.verifier.session(s.id))?.status, 'request_retrieved');
    assert.equal((await w.answer(s, { credential: [vp] })).status, 200);
    const done = await w.verifier.session(s.id);
    assert.equal(done?.status, 'verified');
    assert.deepEqual(done?.result?.claims, { ho_ten: DIPLOMA.ho_ten, nganh: DIPLOMA.nganh });
  });

  test('a proven holder whose credential fails later checks finalises the session as failed', async () => {
    const w = await world();
    const s = await w.session();
    assert.equal((await w.answer(s, { credential: [await w.present(s.payload, { disclose: ['ho_ten'] })] })).status, 200);
    const done = await w.verifier.session(s.id);
    assert.equal(done?.status, 'failed');
    assert.equal(done?.result?.checks.at(-1)?.code, 'QUERY_NOT_SATISFIED');
  });

  test(`after ${MAX_RESPONSE_ATTEMPTS} refused responses the session ends as failed with TOO_MANY_ATTEMPTS`, async () => {
    const w = await world();
    const s = await w.session();
    for (let i = 0; i < MAX_RESPONSE_ATTEMPTS; i++) assert.equal((await w.answer(s, { credential: ['garbage'] })).status, 400);
    const done = await w.verifier.session(s.id);
    assert.equal(done?.status, 'failed');
    assert.deepEqual(done?.result?.checks, [{ id: 'holder_binding', ok: false, code: 'TOO_MANY_ATTEMPTS' }]);
    assert.equal((await w.answer(s, { credential: [await w.present(s.payload)] })).status, 400, 'too late for the holder');
  });

  test('20 concurrent valid responses: one result, written once', async () => {
    const w = await world();
    const s = await w.session();
    const vps = await Promise.all(Array.from({ length: 20 }, () => w.present(s.payload)));
    const statuses = await Promise.all(vps.map((vp) => w.answer(s, { credential: [vp] }).then((r) => r.status)));
    assert.deepEqual([statuses.filter((x) => x === 200).length, statuses.filter((x) => x === 400).length], [1, 19]);
    assert.equal(w.puts.filter((k) => k.includes(':result:')).length, 1);
    assert.equal((await w.verifier.session(s.id))?.status, 'verified');
  });

  test('when the result cannot be written, the session stays open and a retry completes it', async () => {
    let failFirst = true;
    const w = await world({
      store: (inner) => ({
        ...inner,
        put: async (k, v, t) => {
          if (failFirst && k.includes(':result:')) {
            failFirst = false;
            throw new Error('redis down');
          }
          return inner.put(k, v, t);
        },
      }),
    });
    const s = await w.session();
    const vp = await w.present(s.payload);
    await assert.rejects(w.answer(s, { credential: [vp] }), /redis down/);
    assert.equal((await w.verifier.session(s.id))?.status, 'request_retrieved');
    assert.equal((await w.answer(s, { credential: [vp] })).status, 200);
    assert.equal((await w.verifier.session(s.id))?.status, 'verified');
  });

  test('a final session keeps no session key and no request record', async () => {
    const w = await world();
    const s = await w.session();
    assert.equal((await w.answer(s, { credential: [await w.present(s.payload)] })).status, 200);
    const prefix = `vp:${w.verifier.clientId}`;
    for (const kind of ['key', 'request', 'open']) assert.equal(await w.memory.get(`${prefix}:${kind}:${s.requestId}`), null, kind);
    assert.equal(await w.verifier.requestObject(s.requestId), null);
  });
});

describe('the hourly trust-list re-check', () => {
  test('a verifier removed from the trust list stops creating sessions within the hour; its name follows the list', async () => {
    const w = await world();
    const requestFp = await fingerprint('request');
    w.entries.set(requestFp, { maToChuc: 'VATVN-0100000005', ten: 'Tên mới', mucDich: 'request' });
    assert.equal((await w.verifier.createSession({ scenario: 'ung-tuyen' })).ok, true, 'not re-checked yet');
    assert.equal(w.verifier.name, 'Nhà Tuyển Dụng Mẫu');
    w.clock.advance(3600);
    assert.equal((await w.verifier.createSession({ scenario: 'ung-tuyen' })).ok, true);
    assert.equal(w.verifier.name, 'Tên mới');
    w.entries.set(requestFp, null);
    w.clock.advance(3600);
    assert.deepEqual(await w.verifier.createSession({ scenario: 'ung-tuyen' }), { ok: false, reason: 'verifier_not_listed' });
  });
});

describe('outcome for the server log, and "not mine"', () => {
  test('outcomes: refused with the reason, finalising with ok and the first failing code, the race loser, the flood; null for requests it does not hold', async () => {
    const w = await world();
    const s = await w.session();
    assert.deepEqual((await w.answer(s, { credential: ['garbage'] })).outcome, { sessionId: s.id, final: false, code: 'MALFORMED' });
    assert.deepEqual((await w.answer(s, { credential: [await w.present(s.payload, { nonce: 'n'.repeat(43) })] })).outcome, { sessionId: s.id, final: false, code: 'NONCE_MISMATCH' });
    const vp = await w.present(s.payload);
    assert.deepEqual((await w.answer(s, { credential: [vp] })).outcome, { sessionId: s.id, final: true, ok: true });
    assert.equal(await w.verifier.handleResponse(s.requestId, form('response=x')), null, 'final: the request is gone');
    const f = await w.session();
    assert.deepEqual((await w.answer(f, { credential: [await w.present(f.payload, { disclose: ['ho_ten'] })] })).outcome, { sessionId: f.id, final: true, ok: false, code: 'QUERY_NOT_SATISFIED' });
    const race = await w.session();
    const both = await Promise.all([w.answer(race, { credential: [await w.present(race.payload)] }), w.answer(race, { credential: [await w.present(race.payload)] })]);
    assert.deepEqual(both.map((b) => b.outcome?.final).sort(), [false, true]);
    assert.deepEqual(both.find((b) => !b.outcome?.final)?.outcome, { sessionId: race.id, final: false });
    const flood = await w.session();
    for (let i = 0; i < MAX_RESPONSE_ATTEMPTS - 1; i++) await w.answer(flood, { credential: ['garbage'] });
    assert.deepEqual((await w.answer(flood, { credential: ['garbage'] })).outcome, { sessionId: flood.id, final: true, ok: false, code: 'TOO_MANY_ATTEMPTS' });
    for (const unknown of ['AAAAAAAAAAAAAAAAAAAAAA', 'not an id']) {
      assert.equal(await w.verifier.requestObject(unknown), null);
      assert.equal(await w.verifier.handleResponse(unknown, form('response=x')), null);
    }
    const other = await world();
    const mine = await other.session();
    assert.equal(await w.verifier.requestObject(mine.requestId), null, 'another verifier\'s request (separate stores here; one shared Redis keys by client_id)');
  });
});

// Session results of the DID trust path (ADR-0020): `trustPath`, `issuerDid` without a name, the
// check id `did_resolution` and the code DID_RESOLUTION_UNAVAILABLE; every malformed variant rejected.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createVerifierClient, DID_PRESENTATION_CHECK_IDS, PRESENTATION_CHECK_IDS, VerifierClientError } from '@identra/sdk-client';

const BASE = 'https://api.example';
const ID = 'sess_0123456789abcdef';
const DID = 'did:certnet:testnet:truongdid0001';
const session = (status: string, result: object) => ({
  id: ID, status, verifier: { name: 'Nhà tuyển dụng mẫu (DEMO)' }, expiresAt: '2026-11-19T10:05:00.000Z', serverTime: '2026-11-19T10:00:00.000Z', result,
});
const didChecks = DID_PRESENTATION_CHECK_IDS.map((id) => ({ id, ok: true, code: null }));
const x509Checks = PRESENTATION_CHECK_IDS.map((id) => ({ id, ok: true, code: null }));
const claims = { ho_ten: 'Nguyễn Văn A', nganh: 'CNTT' };
const didResult = { ok: true, checks: didChecks, claims, trustPath: 'did', issuerDid: DID, verifiedAt: '2026-11-19T10:01:00.000Z' };
const x509Result = { ok: true, checks: x509Checks, claims, trustPath: 'x509', issuer: { maToChuc: 'VATVN-0100000001', ten: 'Trường Mẫu' }, verifiedAt: '2026-11-19T10:01:00.000Z' };
const get = (body: unknown) =>
  createVerifierClient({ baseUrl: BASE, fetch: (async () => new Response(JSON.stringify(body), { status: 200 })) as typeof fetch }).getSession(ID);

test('the DID path checks list did_resolution where the X.509 path lists certificate_chain', () => {
  assert.deepEqual(DID_PRESENTATION_CHECK_IDS.map((id) => (id === 'did_resolution' ? 'certificate_chain' : id)), [...PRESENTATION_CHECK_IDS]);
});

test('results of both paths parse: did with issuerDid and no name, x509 with the trust-list issuer; a result without trustPath reads as x509', async () => {
  assert.deepEqual((await get(session('verified', didResult))).result, { ok: true, checks: didChecks, claims, trustPath: 'did', issuerDid: DID, verifiedAt: didResult.verifiedAt });
  assert.deepEqual((await get(session('verified', x509Result))).result, x509Result);
  const { trustPath, ...legacy } = x509Result;
  void trustPath;
  assert.deepEqual((await get(session('verified', legacy))).result, x509Result);
  // A failure at did_resolution because the gateway did not answer: "not checked yet", never valid.
  const unavailable = {
    ok: false,
    checks: [
      { id: 'structure', ok: true, code: null }, { id: 'algorithm', ok: true, code: null },
      { id: 'did_resolution', ok: false, code: 'DID_RESOLUTION_UNAVAILABLE' },
      ...['signature', 'validity_time', 'credential_type', 'issuer_trust', 'status', 'holder_binding'].map((id) => ({ id, ok: false, code: 'SKIPPED', skipped: true })),
    ],
    verifiedAt: didResult.verifiedAt,
  };
  const s = await get(session('failed', unavailable));
  assert.equal(s.status, 'failed');
  assert.deepEqual(s.result?.checks.find((c) => c.id === 'did_resolution'), { id: 'did_resolution', ok: false, code: 'DID_RESOLUTION_UNAVAILABLE' });
});

test('malformed DID-path results are rejected, naming only the field', async () => {
  const LEAK = 'LEAK-Truong';
  const withDid = (patch: object) => session('verified', { ...didResult, ...patch });
  const without = (key: string, r: Record<string, unknown> = didResult) => session('verified', Object.fromEntries(Object.entries(r).filter(([k]) => k !== key)));
  const failed = { ok: false, checks: didChecks.map((c) => (c.id === 'status' ? { id: 'status', ok: false, code: 'REVOKED' } : c)), verifiedAt: didResult.verifiedAt };
  const cases: [unknown, string][] = [
    [withDid({ issuer: { maToChuc: 'VATVN-0100000001', ten: LEAK } }), 'result.issuer'],
    [withDid({ issuer: null }), 'result.issuer'],
    [without('issuerDid'), 'result.issuerDid'],
    [withDid({ issuerDid: 'did:web:truong.example.vn' }), 'result.issuerDid'],
    [withDid({ issuerDid: 'did:certnet:other:abc' }), 'result.issuerDid'],
    [withDid({ issuerDid: `${DID}#key-1` }), 'result.issuerDid'],
    [withDid({ issuerDid: `${DID}\n` }), 'result.issuerDid'],
    [withDid({ issuerDid: 42 }), 'result.issuerDid'],
    [withDid({ trustPath: 'dpki' }), 'result.trustPath'],
    [withDid({ trustPath: null }), 'result.trustPath'],
    // Each path lists its own step 3, and only that one.
    [withDid({ checks: x509Checks }), 'result.checks'],
    [withDid({ checks: [...didChecks, { id: 'certificate_chain', ok: true, code: null }] }), 'result.checks'],
    [withDid({ checks: didChecks.filter((c) => c.id !== 'did_resolution') }), 'result.checks'],
    [session('verified', { ...x509Result, checks: didChecks }), 'result.checks'],
    [session('verified', { ...x509Result, checks: [...x509Checks, { id: 'did_resolution', ok: true, code: null }] }), 'result.checks'],
    // An X.509 result still needs its trust-list issuer and carries no DID.
    [without('issuer', x509Result), 'result.issuer'],
    [session('verified', { ...x509Result, issuerDid: DID }), 'result.issuerDid'],
    // A failure names no path and no issuer.
    [session('failed', { ...failed, trustPath: 'did' }), 'result.trustPath'],
    [session('failed', { ...failed, issuerDid: DID }), 'result.issuerDid'],
  ];
  for (const [body, path] of cases) {
    const err = await get(body).then(() => assert.fail(`accepted a result with a bad ${path}: ${JSON.stringify(body)}`), (e: unknown) => e);
    assert.ok(err instanceof VerifierClientError, path);
    assert.equal(err.message, `malformed session response: ${path}`, JSON.stringify(body));
    assert.ok(!err.message.includes(LEAK));
  }
});

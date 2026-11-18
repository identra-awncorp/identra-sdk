// GĐ6 end to end over REAL HTTP (127.0.0.1:47642): a diploma issued through OpenID4VCI in the same
// test, then presented over OpenID4VP 1.0 (direct_post.jwt) to the sdk-server verifier mounted at the
// paths of vc-api.md section 6, with the server's own trust and status lists.
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { CompactEncrypt, importJWK, type JWK } from 'jose';
import { base64UrlDecode, base64UrlEncode, createMappedFetch, createPresentation, utf8Decode, utf8Encode, VCT } from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair, webCryptoHasher } from '@identra/sdk-core/webcrypto';
import { createWorld, DIPLOMA, newSession, nodeHttpFetch, ORIGIN, startListener, UNG_TUYEN, type Listener, type World } from './helpers/world.js';

let listener: Listener;
before(async () => (listener = await startListener(47642)));
after(() => listener.close());

/** Issue a diploma into a fresh wallet, create a session, resolve its QR. */
async function setup(o: { world?: World } = {}) {
  const world = o.world ?? (await createWorld(listener));
  const verifier = await world.newVerifier();
  const w = world.newWallet();
  const credentialId = await world.issueTo(w);
  const session = (await newSession(verifier));
  return { world, verifier, w, credentialId, session };
}
const resolveOk = async (w: ReturnType<World['newWallet']>, qr: string) => {
  const r = await w.wallet.presentations.resolve(qr);
  assert.equal(r.ok, true, JSON.stringify(r));
  return (r as Extract<typeof r, { ok: true }>).request;
};
const codeAt = (checks: { id: string; code: string | null }[] | undefined, id: string) => checks?.find((c) => c.id === id)?.code;

describe('presentation over HTTP', () => {
  test('issue -> present claim set 1, then claim set 2 (ho_ten + nganh only); the verifier never sees ngay_sinh', async () => {
    const { world, verifier, w, credentialId, session } = await setup();
    assert.match(session.qr, /^openid4vp:\/\/\?client_id=x509_hash%3A[A-Za-z0-9_-]{43}&request_uri=https%3A%2F%2Fapi-identra\.awncorp\.vn%2Foid4vp%2Frequest%2F/);
    assert.notEqual(session.id, session.requestId);
    assert.equal(session.qr.includes(session.id), false, 'the QR never reveals the session id');
    assert.equal((await verifier.session(session.id))?.status, 'pending');

    const request = await resolveOk(w, session.qr);
    assert.deepEqual(request.verifier, { trusted: true, ten: world.verifierEntry.ten, maToChuc: world.verifierEntry.ma_to_chuc });
    assert.equal(request.warning, undefined);
    assert.deepEqual(request.purpose, UNG_TUYEN.purpose);
    assert.equal(request.clientId, verifier.clientId);
    assert.deepEqual(request.matches.map((m) => [m.credentialId, m.vct, m.issuerName, m.claimSets]), [
      [credentialId, VCT.diploma, 'Trường Mẫu (TEST)', [{ index: 0, claims: UNG_TUYEN.claimSets[0] }, { index: 1, claims: UNG_TUYEN.claimSets[1] }]],
    ]);
    const s = await verifier.session(session.id);
    assert.deepEqual([s?.status, 'result' in s!], ['request_retrieved', false]);
    assert.equal(s?.verifier.name, world.verifierEntry.ten);

    assert.deepEqual(await w.wallet.presentations.submit(request, { credentialId, claimSetIndex: 0 }), { ok: true });
    const done = (await verifier.session(session.id))!;
    assert.equal(done.status, 'verified', JSON.stringify(done.result));
    assert.deepEqual(done.result?.claims, { ho_ten: DIPLOMA.ho_ten, nganh: DIPLOMA.nganh, hang_tot_nghiep: DIPLOMA.hang_tot_nghiep, nam_tot_nghiep: DIPLOMA.nam_tot_nghiep });
    assert.deepEqual(done.result?.issuer, { maToChuc: 'VATVN-0100000001', ten: 'Trường Mẫu (TEST)' });
    assert.equal(done.result?.checks.every((c) => c.ok), true);
    assert.equal(done.result?.checks.at(-1)?.id, 'query');

    // Claim set 2 in a new session.
    listener.log.length = 0;
    const second = (await newSession(verifier));
    const request2 = await resolveOk(w, second.qr);
    assert.deepEqual(await w.wallet.presentations.submit(request2, { credentialId, claimSetIndex: 1 }), { ok: true });
    const done2 = (await verifier.session(second.id))!;
    assert.equal(done2.status, 'verified');
    assert.deepEqual(done2.result?.claims, { ho_ten: DIPLOMA.ho_ten, nganh: DIPLOMA.nganh });
    const verifierSide = JSON.stringify([done, done2, listener.log.map((l) => l.body)]);
    assert.equal(verifierSide.includes(DIPLOMA.ngay_sinh), false, 'ngay_sinh never reaches the verifier side');
    const posted = listener.log.find((l) => l.path.startsWith('/oid4vp/response/'))!;
    assert.equal(posted.contentType, 'application/x-www-form-urlencoded');
    assert.match(posted.body, /^response=[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    assert.equal(posted.body.includes(DIPLOMA.ho_ten), false);
    void world;
  });
});

// ---- a hand-made wallet for responses the real wallet would never send ----
const http = () => createMappedFetch(nodeHttpFetch, { [ORIGIN]: listener.localOrigin });
type Payload = { nonce: string; state: string; client_id: string; response_uri: string; client_metadata: { jwks: { keys: (Record<string, string> & { kid: string })[] } } };
async function requestPayloadOf(requestId: string): Promise<Payload> {
  const r = await http()(`${ORIGIN}/oid4vp/request/${requestId}`);
  assert.equal(r.status, 200);
  return JSON.parse(utf8Decode(base64UrlDecode((await r.text()).split('.')[1]!))) as Payload;
}
async function encryptFor(p: Payload, body: unknown) {
  const { kty, crv, x, y, kid } = p.client_metadata.jwks.keys[0]!;
  return new CompactEncrypt(utf8Encode(JSON.stringify(body))).setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid }).encrypt(await importJWK({ kty, crv, x, y } as JWK, 'ECDH-ES'));
}
const post = async (requestId: string, form: string) => {
  const r = await http()(`${ORIGIN}/oid4vp/response/${requestId}`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form });
  return r.status;
};
/** A presentation made with the credential's own wallet key, to `audience` / `nonce` of our choosing. */
async function presentationOf(w: ReturnType<World['newWallet']>, credentialId: string, audience: string, nonce: string, now: Date, disclose = UNG_TUYEN.claimSets[1]!) {
  const row = (await w.vault.getMeta(credentialId))!;
  return createPresentation({ compact: await w.vault.open(credentialId), disclose, holderSigner: await w.keyStore.signer(row.key_id), audience, nonce, now, hasher: webCryptoHasher });
}
const answer = async (requestId: string, presentation: string, p?: Payload) => {
  const payload = p ?? (await requestPayloadOf(requestId));
  return post(requestId, `response=${await encryptFor(payload, { vp_token: { credential: [presentation] }, state: payload.state })}`);
};

describe('what the verifier concludes', () => {
  for (const [name, change, check, code] of [
    ['revoked through the status service', (w: World, idx: number) => w.statusService.setStatus('truong-mau', 1, idx, 'revoked'), 'status', 'REVOKED'],
    ['suspended', (w: World, idx: number) => w.statusService.setStatus('truong-mau', 1, idx, 'suspended'), 'status', 'SUSPENDED'],
    ['issuer removed from the trust list', async (w: World) => void (w.trust.content = { ...w.trust.content, issuers: [] }), 'issuer_trust', 'ISSUER_NOT_TRUSTED'],
  ] as const) {
    test(`${name}: the next session fails with ${code} at ${check}`, async () => {
      const { world, verifier, w, credentialId, session } = await setup();
      await change(world, world.issued[0]!.statusIdx);
      world.clock.advance(1);
      assert.deepEqual(await w.wallet.presentations.submit(await resolveOk(w, session.qr), { credentialId, claimSetIndex: 1 }), { ok: true });
      const done = (await verifier.session(session.id))!;
      assert.equal(done.status, 'failed');
      assert.equal(done.result?.ok, false);
      assert.equal(codeAt(done.result?.checks, check), code);
      assert.deepEqual(['claims' in done.result!, 'issuer' in done.result!], [false, false]);
    });
  }

  test('a wallet clock 3 minutes ahead: the KB-JWT iat is refused (400, session open); with the clock fixed the same session verifies', async () => {
    const world = await createWorld(listener);
    const verifier = await world.newVerifier();
    let skew = 0;
    const ahead = { now: () => new Date(world.clock.now().getTime() + skew) };
    const w = world.newWallet('noble', undefined, ahead);
    const credentialId = await world.issueTo(w);
    skew = 180_000;
    const session = await newSession(verifier);
    assert.deepEqual(await w.wallet.presentations.submit(await resolveOk(w, session.qr), { credentialId, claimSetIndex: 1 }), { ok: false, code: 'VERIFIER_ERROR' });
    assert.equal((await verifier.session(session.id))?.status, 'request_retrieved');
    skew = 0;
    assert.deepEqual(await w.wallet.presentations.submit(await resolveOk(w, session.qr), { credentialId, claimSetIndex: 1 }), { ok: true });
    assert.equal((await verifier.session(session.id))?.status, 'verified');
  });

  test('holder binding failures do not finalise: KB-JWT for another session (nonce), another verifier (aud), another key; then the genuine response verifies', async () => {
    const { world, verifier, w, credentialId, session } = await setup();
    const first = await requestPayloadOf(session.requestId);
    const replayed = await presentationOf(w, credentialId, verifier.clientId, first.nonce, world.clock.now());
    const second = await newSession(verifier);
    const p2 = await requestPayloadOf(second.requestId);
    const good = await presentationOf(w, credentialId, verifier.clientId, p2.nonce, world.clock.now());
    const other = await createWebCryptoSigner(await generateWebCryptoKeyPair());
    const kb = good.split('~').pop()!;
    const input = kb.split('.').slice(0, 2).join('.');
    const forged = `${good.slice(0, good.length - kb.length)}${input}.${base64UrlEncode(await other.sign(utf8Encode(input)))}`;
    const wrongAud = await presentationOf(w, credentialId, 'x509_hash:another-verifier', p2.nonce, world.clock.now());
    for (const [name, vp] of [['nonce of another session', replayed], ['audience of another verifier', wrongAud], ['KB-JWT by another key', forged]] as const) {
      assert.equal(await answer(second.requestId, vp, p2), 400, name);
      assert.equal((await verifier.session(second.id))?.status, 'request_retrieved', name);
    }
    assert.equal(await answer(second.requestId, good, p2), 200);
    assert.equal((await verifier.session(second.id))?.status, 'verified');
  });

  test('a presentation disclosing more than the satisfied claim set: the extra claims are dropped', async () => {
    const { world, verifier, w, credentialId, session } = await setup();
    const p = await requestPayloadOf(session.requestId);
    assert.equal(await answer(session.requestId, await presentationOf(w, credentialId, verifier.clientId, p.nonce, world.clock.now(), ['ho_ten', 'nganh', 'ngay_sinh']), p), 200);
    const done = (await verifier.session(session.id))!;
    assert.equal(done.status, 'verified');
    assert.deepEqual(done.result?.claims, { ho_ten: DIPLOMA.ho_ten, nganh: DIPLOMA.nganh });
    assert.equal(JSON.stringify(done).includes(DIPLOMA.ngay_sinh), false);
  });

  test('a presentation satisfying no claim set fails at query (QUERY_NOT_SATISFIED)', async () => {
    const { world, verifier, w, credentialId, session } = await setup();
    const p = await requestPayloadOf(session.requestId);
    assert.equal(await answer(session.requestId, await presentationOf(w, credentialId, verifier.clientId, p.nonce, world.clock.now(), ['ho_ten']), p), 200);
    const done = (await verifier.session(session.id))!;
    assert.equal(done.status, 'failed');
    assert.equal(codeAt(done.result?.checks, 'query'), 'QUERY_NOT_SATISFIED');
  });
});

describe('responses the verifier refuses (400, nothing stored)', () => {
  test('sent twice, then 10 concurrent: exactly one is processed and its result is not overwritten', async () => {
    const { world, verifier, w, credentialId, session } = await setup();
    const p = await requestPayloadOf(session.requestId);
    const vp = await presentationOf(w, credentialId, verifier.clientId, p.nonce, world.clock.now());
    const form = `response=${await encryptFor(p, { vp_token: { credential: [vp] }, state: p.state })}`;
    assert.equal(await post(session.requestId, form), 200);
    const result = (await verifier.session(session.id))!.result;
    assert.equal(await post(session.requestId, form), 400);
    const other = (await newSession(verifier));
    const po = await requestPayloadOf(other.requestId);
    const vpo = await presentationOf(w, credentialId, verifier.clientId, po.nonce, world.clock.now());
    const forms = await Promise.all(Array.from({ length: 10 }, async () => `response=${await encryptFor(po, { vp_token: { credential: [vpo] }, state: po.state })}`));
    const statuses = await Promise.all(forms.map((f) => post(other.requestId, f)));
    assert.deepEqual([statuses.filter((x) => x === 200).length, statuses.filter((x) => x === 400).length], [1, 9]);
    assert.deepEqual((await verifier.session(session.id))!.result, result);
    assert.equal((await verifier.requestObject(session.requestId)).status, 404, 'no request object once final');
  });

  test('plain direct_post, signed-only, another session key, tampered, wrong state, unknown request, after expiry; the session stays open', async () => {
    const { world, verifier, w, credentialId, session } = await setup();
    const p = await requestPayloadOf(session.requestId);
    const vp = await presentationOf(w, credentialId, verifier.clientId, p.nonce, world.clock.now());
    const other = (await newSession(verifier));
    const po = await requestPayloadOf(other.requestId);
    const good = await encryptFor(p, { vp_token: { credential: [vp] }, state: p.state });
    const [h, k, iv, ct, tag] = good.split('.') as [string, string, string, string, string];
    const flipped = ct.slice(0, -2) + (ct.endsWith('AA') ? 'AB' : 'AA');
    const refused: [string, string, string?][] = [
      ['plain direct_post', `vp_token=${encodeURIComponent(JSON.stringify({ credential: [vp] }))}&state=${p.state}`],
      ['plain next to the JWE', `response=${good}&vp_token=x`],
      ['signed only (a JWS)', `response=${vp.split('~')[0]}`],
      ['encrypted to another session key', `response=${await encryptFor({ ...p, client_metadata: po.client_metadata }, { vp_token: { credential: [vp] }, state: p.state })}`],
      ['tampered ciphertext', `response=${[h, k, iv, flipped, tag].join('.')}`],
      ['wrong state', `response=${await encryptFor(p, { vp_token: { credential: [vp] }, state: po.state })}`],
      ['unknown request', `response=${good}`, 'AAAAAAAAAAAAAAAAAAAAAA'],
    ];
    for (const [name, form, requestId] of refused) assert.equal(await post(requestId ?? session.requestId, form), 400, name);
    assert.equal((await verifier.session(session.id))?.status, 'request_retrieved');
    assert.equal(await post(session.requestId, `response=${good}`), 200, 'the session was still open');
    const late = (await newSession(verifier));
    world.clock.advance(250);
    const pl = await requestPayloadOf(late.requestId);
    assert.equal(await answer(late.requestId, await presentationOf(w, credentialId, verifier.clientId, pl.nonce, world.clock.now()), pl), 200);
    world.clock.advance(50);
    assert.equal(await answer(other.requestId, await presentationOf(w, credentialId, verifier.clientId, po.nonce, world.clock.now()), po), 400, 'after expiry');
    assert.equal((await verifier.session(other.id))?.status, 'expired');
    assert.equal('result' in (await verifier.session(other.id))!, false);
    world.clock.advance(1500);
    assert.equal(await verifier.session(other.id), null, 'deleted 30 minutes after creation');
    assert.equal((await verifier.session(late.id))?.status, 'verified', 'kept 30 minutes after verification');
    assert.deepEqual(await verifier.createSession({ scenario: 'other' }), { ok: false, reason: 'unknown_scenario' });
  });
});

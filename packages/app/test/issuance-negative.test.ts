// The wallet against a misbehaving world over real HTTP (127.0.0.1:47641): every failure ends with
// its exact wallet code, and after any failure there is NO stored row and NO leftover wallet key.
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { CompactEncrypt, compactDecrypt, importJWK } from 'jose';
import { base64UrlDecode, createMappedFetch, issueCredential, issueDiploma, utf8Decode, utf8Encode, VCT, type EcPublicJwk, type Signer } from '@identra/sdk-core';
import { generateWebCryptoKeyPair, webCryptoHasher, webCryptoRandom } from '@identra/sdk-core/webcrypto';
import type { ProtocolStateStore } from '@identra/sdk-server';
import { createWorld, DIPLOMA, ISS, leafSigner, nodeHttpFetch, ORIGIN, startListener, type Handler, type Listener, type World } from './helpers/world.js';

let listener: Listener;
before(async () => (listener = await startListener(47641)));
after(() => listener.close());

type TestWallet = ReturnType<World['newWallet']>;
const nothingLeft = (w: TestWallet) => {
  assert.equal(w.rows.size, 0, 'no stored row');
  assert.equal(w.secrets.size, 0, 'no leftover key');
};
async function resolvedOffer(world: World, w: TestWallet) {
  const created = await world.offer();
  const r = await w.wallet.offers.resolve(created.offerUri);
  assert.equal(r.ok, true, JSON.stringify(r));
  return { ...created, offer: (r as Extract<typeof r, { ok: true }>).offer };
}
const otherPin = (pin: string) => (pin === '000000' ? '000001' : '000000');

/** A credential endpoint that answers `credentials` (built from the proof's key) encrypted to the wallet, like a real issuer would. */
function maliciousCredential(world: World, make: (proofJwk: EcPublicJwk) => Promise<unknown>, o: { encrypt?: boolean } = {}): Handler {
  return async (req) => {
    const { plaintext } = await compactDecrypt(req.body, world.keys.requestEncryption.privateKey);
    const request = JSON.parse(utf8Decode(plaintext)) as { proofs: { jwt: string[] }; credential_response_encryption: { jwk: EcPublicJwk } };
    const header = JSON.parse(utf8Decode(base64UrlDecode(request.proofs.jwt[0]!.split('.')[0]!))) as { jwk: EcPublicJwk };
    const response = JSON.stringify({ credentials: await make(header.jwk) });
    if (o.encrypt === false) return { status: 200, headers: { 'Content-Type': 'application/json' }, body: response };
    const { kty, crv, x, y } = request.credential_response_encryption.jwk;
    const jwe = await new CompactEncrypt(utf8Encode(response)).setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' }).encrypt(await importJWK({ kty, crv, x, y }, 'ECDH-ES'));
    return { status: 200, headers: { 'Content-Type': 'application/jwt' }, body: jwe };
  };
}
const diplomaFor = async (world: World, cnfJwk: EcPublicJwk, signer?: Signer, revoked = false) => {
  const status = await world.statusService.allocate('truong-mau');
  if (revoked) await world.statusService.setStatus('truong-mau', 1, status.idx, 'revoked');
  return issueDiploma({ signer: signer ?? (await leafSigner('vc')), hasher: webCryptoHasher, random: webCryptoRandom, clock: world.clock, iss: ISS, cnfJwk, status, claims: DIPLOMA });
};
/** Rewrites the JSON a route answers. */
function rewrite(key: string, edit: (json: Record<string, unknown>) => void) {
  const inner = listener.routes.get(key)!;
  listener.routes.set(key, async (req) => {
    const r = await inner(req);
    const json = JSON.parse(r.body) as Record<string, unknown>;
    edit(json);
    return { ...r, body: JSON.stringify(json) };
  });
}
const CREDENTIAL = 'POST /issuers/truong-mau/credential';
const METADATA = 'GET /.well-known/openid-credential-issuer/issuers/truong-mau';

describe('PIN and offer lifetime', () => {
  test('a wrong PIN is TX_CODE_WRONG and retryable on the same resolved offer; no key is created before the token', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    const { offer, txCode } = await resolvedOffer(world, w);
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode: otherPin(txCode) }), { ok: false, code: 'TX_CODE_WRONG' });
    nothingLeft(w);
    assert.equal((await w.wallet.offers.accept(offer, { txCode })).ok, true);
  });

  test('5 wrong PINs destroy the offer: the fifth and every later attempt are OFFER_EXPIRED', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    const { offer, txCode } = await resolvedOffer(world, w);
    const codes = [];
    for (let i = 0; i < 5; i++) codes.push(((await w.wallet.offers.accept(offer, { txCode: otherPin(txCode) })) as { code: string }).code);
    assert.deepEqual(codes, ['TX_CODE_WRONG', 'TX_CODE_WRONG', 'TX_CODE_WRONG', 'TX_CODE_WRONG', 'OFFER_EXPIRED']);
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'OFFER_EXPIRED' });
    nothingLeft(w);
  });

  test('an expired offer, and an offer another wallet already collected, are OFFER_EXPIRED', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    const first = await resolvedOffer(world, w);
    world.clock.advance(601);
    assert.deepEqual(await w.wallet.offers.accept(first.offer, { txCode: first.txCode }), { ok: false, code: 'OFFER_EXPIRED' });
    assert.deepEqual(await w.wallet.offers.resolve(first.offerUri), { ok: false, code: 'OFFER_EXPIRED' });
    const other = world.newWallet();
    const second = await resolvedOffer(world, w);
    const again = await other.wallet.offers.resolve(second.offerUri);
    assert.equal((await w.wallet.offers.accept(second.offer, { txCode: second.txCode })).ok, true);
    assert.ok(again.ok);
    assert.deepEqual(await other.wallet.offers.accept(again.offer, { txCode: second.txCode }), { ok: false, code: 'OFFER_EXPIRED' });
    nothingLeft(other);
  });
});

describe('what the wallet refuses to contact or to accept as an offer', () => {
  test('QR texts: not an offer, by value, http, extra parameters; no request is made', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    listener.requests.length = 0;
    const qr = (uri: string) => `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(uri)}`;
    for (const [text, code] of [
      ['https://api-identra.awncorp.vn/issuers/truong-mau/offers/x', 'OFFER_INVALID'],
      ['openid-credential-offer://?credential_offer=%7B%7D', 'OFFER_INVALID'],
      [qr('http://api-identra.awncorp.vn/issuers/truong-mau/offers/x'), 'URL_NOT_ALLOWED'],
      [qr('https://user@api-identra.awncorp.vn/issuers/truong-mau/offers/x'), 'URL_NOT_ALLOWED'],
      [`${qr(`${ISS}/offers/x`)}&credential_offer=%7B%7D`, 'OFFER_INVALID'],
    ]) {
      assert.deepEqual(await w.wallet.offers.resolve(text!), { ok: false, code }, text);
    }
    assert.deepEqual(listener.requests, []);
  });

  test('metadata or offer pointing at another origin: URL_NOT_ALLOWED; http in metadata is refused by the schema; nothing else is contacted', async () => {
    const cases: [string, (j: Record<string, unknown>) => void, string][] = [
      [METADATA, (m) => (m['credential_endpoint'] = 'https://evil.example/issuers/truong-mau/credential'), 'URL_NOT_ALLOWED'],
      ['GET /.well-known/oauth-authorization-server/issuers/truong-mau', (m) => (m['token_endpoint'] = 'https://evil.example/token'), 'URL_NOT_ALLOWED'],
      ['GET /issuers/truong-mau/offers/*', (o) => (o['credential_issuer'] = 'https://evil.example/issuers/truong-mau'), 'URL_NOT_ALLOWED'],
      // The library's metadata schema accepts https URLs only, so this ends before our own origin check.
      [METADATA, (m) => (m['nonce_endpoint'] = 'http://api-identra.awncorp.vn/issuers/truong-mau/nonce'), 'ISSUER_ERROR'],
    ];
    for (const [route, edit, code] of cases) {
      const world = await createWorld(listener);
      rewrite(route, edit);
      const contacted: string[] = [];
      const recording = createMappedFetch((url, init) => (contacted.push(url), nodeHttpFetch(url, init)), { [ORIGIN]: listener.localOrigin });
      const w = world.newWallet('noble', recording);
      assert.deepEqual(await w.wallet.offers.resolve((await world.offer()).offerUri), { ok: false, code }, `${route} ${edit}`);
      assert.deepEqual(contacted.filter((u) => !u.startsWith(`${listener.localOrigin}/`)), []);
    }
  });

  test('unsupported offers: unknown vct, no pre-authorized grant, no response encryption: OFFER_INVALID', async () => {
    const edits: [string, (j: Record<string, unknown>) => void][] = [
      [METADATA, (m) => (((m['credential_configurations_supported'] as Record<string, Record<string, unknown>>)['bang-tot-nghiep-v1']!)['vct'] = 'https://identra.awncorp.vn/vct/other/v1')],
      ['GET /issuers/truong-mau/offers/*', (o) => (o['grants'] = { authorization_code: { issuer_state: 'x' } })],
      [METADATA, (m) => delete m['credential_response_encryption']],
    ];
    for (const [route, edit] of edits) {
      const world = await createWorld(listener);
      rewrite(route, edit);
      assert.deepEqual(await world.newWallet().wallet.offers.resolve((await world.offer()).offerUri), { ok: false, code: 'OFFER_INVALID' });
    }
  });

  test('an unreachable issuer is NETWORK_ERROR', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet('noble', createMappedFetch(nodeHttpFetch, { [ORIGIN]: 'http://127.0.0.1:47659' }));
    assert.deepEqual(await w.wallet.offers.resolve((await world.offer()).offerUri), { ok: false, code: 'NETWORK_ERROR' });
  });
});

describe('a malicious or failing issuer after the wallet key exists: exact code, no row, no key', () => {
  const cases: [string, (world: World) => Handler | Promise<Handler>, string, [string, string]?][] = [
    ['a credential bound to another key', (world) => maliciousCredential(world, async () => [{ credential: await diplomaFor(world, (await generateWebCryptoKeyPair()).publicJwk) }]), 'CNF_MISMATCH'],
    ['a credential signed by an untrusted chain', (world) => maliciousCredential(world, async (jwk) => [{ credential: await diplomaFor(world, jwk, await leafSigner('evil-vc', 'evil-issuing')) }]), 'CREDENTIAL_INVALID', ['certificate_chain', 'CERT_CHAIN_UNTRUSTED']],
    ['a revoked credential', (world) => maliciousCredential(world, async (jwk) => [{ credential: await diplomaFor(world, jwk, undefined, true) }]), 'CREDENTIAL_INVALID', ['status', 'REVOKED']],
    ['two credentials', (world) => maliciousCredential(world, async (jwk) => [{ credential: await diplomaFor(world, jwk) }, { credential: await diplomaFor(world, jwk) }]), 'ISSUER_ERROR'],
    ['a string that is not an SD-JWT', (world) => maliciousCredential(world, async () => [{ credential: 'not-an-sd-jwt' }]), 'CREDENTIAL_INVALID', ['structure', 'MALFORMED']],
    ['a credential missing a claim', (world) => maliciousCredential(world, async (jwk) => {
      const six: Record<string, string> = { ...DIPLOMA };
      delete six['so_hieu_bang'];
      const credential = await issueCredential({
        signer: await leafSigner('vc'), hasher: webCryptoHasher, random: webCryptoRandom, clock: world.clock, iss: ISS, vct: VCT.diploma,
        cnfJwk: jwk, status: await world.statusService.allocate('truong-mau'), claims: six, disclosable: Object.keys(six), sdDigests: 10,
      });
      return [{ credential }];
    }), 'CLAIMS_INCOMPLETE'],
    ['an unencrypted response', (world) => maliciousCredential(world, async (jwk) => [{ credential: await diplomaFor(world, jwk) }], { encrypt: false }), 'ISSUER_ERROR'],
    ['an oversized response', () => async () => ({ status: 200, headers: { 'Content-Type': 'application/jwt' }, body: 'a'.repeat(70_000) }), 'ISSUER_ERROR'],
    ['a redirect', () => async () => ({ status: 302, headers: { Location: 'https://evil.example/credential' }, body: '' }), 'ISSUER_ERROR'],
  ];
  for (const [name, handler, code, check] of cases) {
    test(name, async () => {
      const world = await createWorld(listener);
      listener.routes.set(CREDENTIAL, await handler(world));
      const w = world.newWallet();
      const { offer, txCode } = await resolvedOffer(world, w);
      const r = await w.wallet.offers.accept(offer, { txCode });
      assert.equal(r.ok, false);
      assert.equal((r as { code: string }).code, code, JSON.stringify(r));
      if (check) assert.equal((r as { checks: { id: string; code: string }[] }).checks.find((c) => c.id === check[0])?.code, check[1]);
      assert.equal(listener.requests.filter((p) => p === CREDENTIAL).length, 1, 'the key existed: the credential request was sent');
      nothingLeft(w);
    });
  }

  test('a credential from another issuer than the offer: ISSUER_MISMATCH', async () => {
    const world = await createWorld(listener, { issuerName: 'truong-khac' });
    listener.routes.set('POST /issuers/truong-khac/credential', maliciousCredential(world, async (jwk) => [{ credential: await diplomaFor(world, jwk) }]));
    const w = world.newWallet();
    const { offer, txCode } = await resolvedOffer(world, w);
    assert.equal(offer.issuerUri, 'https://api-identra.awncorp.vn/issuers/truong-khac');
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'ISSUER_MISMATCH' });
    nothingLeft(w);
  });

  test('onIssued throws on the server: ISSUER_ERROR', async () => {
    const world = await createWorld(listener, { handlers: { onIssued: async () => { throw new Error('database down'); } } });
    const w = world.newWallet();
    const { offer, txCode, offerId } = await resolvedOffer(world, w);
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'ISSUER_ERROR' });
    nothingLeft(w);
    assert.equal((await world.issuer.offerStatus(offerId))?.status, 'pending');
  });

  test('the state store fails mid-flow on the server: ISSUER_ERROR, nothing recorded', async () => {
    let failing = false;
    const store = (s: ProtocolStateStore): ProtocolStateStore => ({ ...s, take: async (k) => (failing && k.includes(':nonce:') ? Promise.reject(new Error('redis down')) : s.take(k)) });
    const world = await createWorld(listener, { store });
    const w = world.newWallet();
    const { offer, txCode } = await resolvedOffer(world, w);
    failing = true;
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'ISSUER_ERROR' });
    nothingLeft(w);
    assert.equal(world.issued.length, 0);
  });
});

describe('status vocabulary at the wallet boundary', () => {
  test('a status that cannot be checked is `unknown` in the wallet API and `unavailable` in the vault row', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    const { offer, txCode } = await resolvedOffer(world, w);
    const accepted = await w.wallet.offers.accept(offer, { txCode });
    assert.ok(accepted.ok);
    listener.routes.delete('GET /issuers/truong-mau/status/*');
    world.clock.advance(86_461); // past the held status list's exp
    const refreshed = await w.wallet.credentials.refreshStatus(accepted.credentialId);
    assert.deepEqual([refreshed.ok, refreshed.ok && refreshed.status], [true, 'unknown']);
    assert.equal((await w.wallet.credentials.list())[0]!.status, 'unknown');
    assert.equal([...w.rows.values()][0]!.status_cache, 'unavailable');
  });
});

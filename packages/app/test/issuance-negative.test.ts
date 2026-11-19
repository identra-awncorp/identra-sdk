// The wallet against a misbehaving world over real HTTP (127.0.0.1:47641): every failure ends with
// its exact wallet code, and after any failure there is NO stored row and NO leftover wallet key.
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { CompactEncrypt, compactDecrypt, importJWK } from 'jose';
import {
  base64UrlDecode, base64UrlEncode, createMappedFetch, issueCredential, issueDiploma, signJws, utf8Decode, utf8Encode, VCT, type EcPublicJwk, type Signer,
} from '@identra/sdk-core';
import { generateWebCryptoKeyPair, webCryptoHasher, webCryptoRandom } from '@identra/sdk-core/webcrypto';
import type { ProtocolStateStore } from '@identra/sdk-server';
import { WalletKeyError } from '@identra/sdk-app';
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
/** A diploma with all seven claims, only `disclosable` of them selectively disclosable, the rest plain. */
const plainDiploma = async (world: World, cnfJwk: EcPublicJwk, disclosable: string[]) =>
  issueCredential({
    signer: await leafSigner('vc'), hasher: webCryptoHasher, random: webCryptoRandom, clock: world.clock, iss: ISS, vct: VCT.diploma,
    cnfJwk, status: await world.statusService.allocate('truong-mau'), claims: { ...DIPLOMA }, disclosable, ...(disclosable.length > 0 ? { sdDigests: 10 } : {}),
  });

/** A diploma signed by the real issuer key whose `status` claim is `status` (none when undefined): what issueCredential refuses to build. */
async function diplomaWithStatus(world: World, cnfJwk: EcPublicJwk, status: unknown): Promise<string> {
  const json = (v: unknown) => base64UrlEncode(utf8Encode(JSON.stringify(v)));
  const disclosures = Object.entries(DIPLOMA).map(([k, v]) => json([base64UrlEncode(webCryptoRandom.bytes(16)), k, v]));
  const sd = (await Promise.all(disclosures.map(async (d) => base64UrlEncode(await webCryptoHasher.sha256(utf8Encode(d)))))).sort();
  const payload = { iss: ISS, vct: VCT.diploma, iat: Math.floor(world.clock.now().getTime() / 1000), cnf: { jwk: cnfJwk }, _sd: sd, _sd_alg: 'sha-256', ...(status === undefined ? {} : { status }) };
  return `${await signJws({ typ: 'dc+sd-jwt' }, utf8Encode(JSON.stringify(payload)), await leafSigner('vc'))}~${disclosures.join('~')}~`;
}
const BAD_STATUS: [string, unknown][] = [
  ['no status claim', undefined],
  ['status on another host', { status_list: { uri: 'https://elsewhere.example/status/1', idx: 5 } }],
  ['status uri with a dot segment', { status_list: { uri: `${ISS}/status/../1`, idx: 5 } }],
  ['idx -1', { status_list: { uri: `${ISS}/status/1`, idx: -1 } }],
  ['idx past the list', { status_list: { uri: `${ISS}/status/1`, idx: 131_072 } }],
];

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
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode: otherPin(txCode) }), { ok: false, code: 'TX_CODE_WRONG', retryable: true, codeRedeemed: false });
    assert.equal(offer.codeRedeemed, false);
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
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'OFFER_EXPIRED', retryable: false, codeRedeemed: false });
    nothingLeft(w);
  });

  test('an expired offer, and an offer another wallet already collected, are OFFER_EXPIRED', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    const first = await resolvedOffer(world, w);
    world.clock.advance(601);
    assert.deepEqual(await w.wallet.offers.accept(first.offer, { txCode: first.txCode }), { ok: false, code: 'OFFER_EXPIRED', retryable: false, codeRedeemed: false });
    assert.deepEqual(await w.wallet.offers.resolve(first.offerUri), { ok: false, code: 'OFFER_EXPIRED' });
    const other = world.newWallet();
    const second = await resolvedOffer(world, w);
    const again = await other.wallet.offers.resolve(second.offerUri);
    assert.equal((await w.wallet.offers.accept(second.offer, { txCode: second.txCode })).ok, true);
    assert.ok(again.ok);
    assert.deepEqual(await other.wallet.offers.accept(again.offer, { txCode: second.txCode }), { ok: false, code: 'OFFER_EXPIRED', retryable: false, codeRedeemed: false });
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
    ['a diploma whose claims are all plain payload claims', (world) => maliciousCredential(world, async (jwk) => [{ credential: await plainDiploma(world, jwk, []) }]), 'CLAIMS_INCOMPLETE'],
    ['a diploma with only one claim disclosable', (world) => maliciousCredential(world, async (jwk) => [{ credential: await plainDiploma(world, jwk, ['ho_ten']) }]), 'CLAIMS_INCOMPLETE'],
    ['a response encrypted to a key the wallet did not send', (world) => async (req) => {
      const r = await maliciousCredential(world, async (jwk) => [{ credential: await diplomaFor(world, jwk) }], { encrypt: false })(req);
      const { publicJwk } = await generateWebCryptoKeyPair();
      const jwe = await new CompactEncrypt(utf8Encode(r.body)).setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' }).encrypt(await importJWK(publicJwk, 'ECDH-ES'));
      return { status: 200, headers: { 'Content-Type': 'application/jwt' }, body: jwe };
    }, 'ISSUER_ERROR'],
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
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'ISSUER_MISMATCH', retryable: false, codeRedeemed: true });
    nothingLeft(w);
  });

  test('onIssued throws on the server: ISSUER_ERROR', async () => {
    const world = await createWorld(listener, { handlers: { onIssued: async () => { throw new Error('database down'); } } });
    const w = world.newWallet();
    const { offer, txCode, offerId } = await resolvedOffer(world, w);
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'ISSUER_ERROR', retryable: false, codeRedeemed: true });
    nothingLeft(w);
    assert.equal((await world.issuer.offerStatus(offerId))?.status, 'pending');
  });

  test('the state store fails on the server before anything is spent (503): ISSUER_ERROR, retryable, the same offer then completes', async () => {
    for (const [op, part, codeRedeemed] of [['take', ':nonce:', true], ['take', ':token:', true], ['get', ':code:', false], ['increment', ':attempts:', false]] as const) {
      let failing = false;
      const store = (s: ProtocolStateStore): ProtocolStateStore => ({
        ...s,
        [op]: async (k: string, t?: number) => (failing && k.includes(part) ? Promise.reject(new Error('redis down')) : op === 'increment' ? s.increment(k, t!) : s[op](k)),
      });
      const world = await createWorld(listener, { store });
      const w = world.newWallet();
      const { offer, txCode } = await resolvedOffer(world, w);
      failing = true;
      assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'ISSUER_ERROR', retryable: true, codeRedeemed }, `${op} ${part}`);
      nothingLeft(w);
      assert.equal(world.issued.length, 0);
      failing = false;
      assert.equal((await w.wallet.offers.accept(offer, { txCode })).ok, true, `${op} ${part}: retry`);
    }
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

describe('GĐ5 review fixes', () => {
  test('F4: trust list or status list unreachable at receipt: stored as unknown, settled by refreshStatus; an untrusted issuer is still refused', async () => {
    const world = await createWorld(listener);
    const trustRoute = listener.routes.get('GET /trust-list')!;
    const statusRoute = listener.routes.get('GET /issuers/truong-mau/status/*')!;
    listener.routes.delete('GET /trust-list');
    const a = world.newWallet();
    const r1 = await resolvedOffer(world, a);
    const noTrust = await a.wallet.offers.accept(r1.offer, { txCode: r1.txCode });
    assert.deepEqual({ ...noTrust, credentialId: 'x' }, { ok: true, credentialId: 'x', vct: VCT.diploma, issuerName: null, status: 'unknown' });
    assert.deepEqual([a.rows.size, a.secrets.size, [...a.rows.values()][0]!.status_cache], [1, 1, 'unavailable']);
    listener.routes.set('GET /trust-list', trustRoute);
    listener.routes.delete('GET /issuers/truong-mau/status/*');
    const b = world.newWallet();
    const r2 = await resolvedOffer(world, b);
    const noStatus = await b.wallet.offers.accept(r2.offer, { txCode: r2.txCode });
    assert.deepEqual({ ...noStatus, credentialId: 'x' }, { ok: true, credentialId: 'x', vct: VCT.diploma, issuerName: 'Trường Mẫu (TEST)', status: 'unknown' });
    listener.routes.set('GET /issuers/truong-mau/status/*', statusRoute);
    for (const [w, r] of [[a, noTrust], [b, noStatus]] as const) {
      const settled = await w.wallet.credentials.refreshStatus((r as { credentialId: string }).credentialId);
      assert.equal(settled.ok && settled.status, 'valid');
    }
    world.trust.content = { ...world.trust.content, issuers: [] };
    world.clock.advance(3601); // the wallets' held trust lists are stale; a fresh wallet reads the new one anyway
    const c = world.newWallet();
    const r3 = await resolvedOffer(world, c);
    const untrusted = await c.wallet.offers.accept(r3.offer, { txCode: r3.txCode });
    assert.equal((untrusted as { code: string }).code, 'CREDENTIAL_INVALID');
    assert.equal((untrusted as { checks: { id: string; code: string }[] }).checks.find((x) => x.id === 'issuer_trust')?.code, 'ISSUER_NOT_TRUSTED');
    nothingLeft(c);
  });

  test('F3-1: a missing or malformed status reference is CREDENTIAL_INVALID at receipt (lists reachable or not) and invalid on refresh', async () => {
    for (const trustDown of [false, true]) {
      for (const [name, status] of BAD_STATUS) {
        const world = await createWorld(listener);
        if (trustDown) listener.routes.delete('GET /trust-list');
        listener.routes.set(CREDENTIAL, maliciousCredential(world, async (jwk) => [{ credential: await diplomaWithStatus(world, jwk, status) }]));
        const w = world.newWallet();
        const { offer, txCode } = await resolvedOffer(world, w);
        const r = await w.wallet.offers.accept(offer, { txCode });
        assert.equal(r.ok ? 'stored' : r.code, 'CREDENTIAL_INVALID', `${name}, trust list down: ${trustDown}`);
        nothingLeft(w);
      }
    }
    const world = await createWorld(listener);
    const w = world.newWallet();
    const { publicJwk } = await generateWebCryptoKeyPair();
    for (const [name, status] of BAD_STATUS) {
      const id = await w.vault.save({ compact: await diplomaWithStatus(world, publicJwk, status), vct: VCT.diploma, issuer: ISS, keyId: 'k' });
      const refreshed = await w.wallet.credentials.refreshStatus(id);
      assert.equal(refreshed.ok && refreshed.status, 'invalid', name);
    }
    const good = await w.vault.save({ compact: await diplomaWithStatus(world, publicJwk, { status_list: { uri: `${ISS}/status/1`, idx: 5 } }), vct: VCT.diploma, issuer: ISS, keyId: 'k' });
    listener.routes.delete('GET /issuers/truong-mau/status/*');
    const down = await w.wallet.credentials.refreshStatus(good);
    assert.equal(down.ok && down.status, 'unknown', 'a well-formed reference whose list is unreachable stays unknown');
  });

  test('F1-2 / F3-2: the issuer name comes only from a passing issuer_trust check (purpose, organisation, vct)', async () => {
    const world = await createWorld(listener);
    const trustRoute = listener.routes.get('GET /trust-list')!;
    listener.routes.delete('GET /trust-list');
    const w = world.newWallet();
    const { offer, txCode } = await resolvedOffer(world, w);
    const a = await w.wallet.offers.accept(offer, { txCode });
    assert.ok(a.ok);
    assert.deepEqual([a.status, a.issuerName], ['unknown', null]);
    const name = async () => { const d = await w.wallet.credentials.get(a.credentialId); assert.ok(d.ok); return d.credential.issuerName; };
    assert.equal(await name(), null, 'trust list still unreachable');
    listener.routes.set('GET /trust-list', trustRoute);
    const seen = listener.requests.length;
    assert.equal(await name(), 'Trường Mẫu (TEST)');
    assert.ok(listener.requests.slice(seen).every((p) => !p.includes('/status/')), 'get() never requests a status list');
    // Still listed with purpose vc and the organisation, but no longer for this vct: no name.
    world.trust.content = { ...world.trust.content, issuers: world.trust.content.issuers.map((e) => ({ ...e, vct: [VCT.productEvent] })) };
    world.clock.advance(3601);
    assert.equal(await name(), null);
  });

  test('F7: remove deletes the key first and a retry completes after either step failed', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    const id = (await (async () => { const r = await resolvedOffer(world, w); return w.wallet.offers.accept(r.offer, { txCode: r.txCode }); })()) as { credentialId: string };
    const del = w.keyStore.delete;
    w.keyStore.delete = async () => Promise.reject(new Error('keychain busy'));
    assert.deepEqual(await w.wallet.credentials.remove(id.credentialId), { ok: false, code: 'STORAGE_ERROR' });
    assert.deepEqual([w.rows.size, w.secrets.size], [1, 1], 'nothing removed: no key without a row');
    w.keyStore.delete = del;
    const removeRow = w.vault.remove;
    const repoDelete = w.rows.delete.bind(w.rows);
    w.rows.delete = () => { throw new Error('db busy'); };
    assert.deepEqual(await w.wallet.credentials.remove(id.credentialId), { ok: false, code: 'STORAGE_ERROR' });
    assert.deepEqual([w.rows.size, w.secrets.size], [1, 0], 'the row is left, detectably keyless');
    w.rows.delete = repoDelete;
    void removeRow;
    assert.deepEqual(await w.wallet.credentials.remove(id.credentialId), { ok: true });
    assert.deepEqual([w.rows.size, w.secrets.size], [0, 0]);
  });

  test('F7: a late failure in accept never leaves a row without its key', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    w.vault.setStatus = async () => Promise.reject(new Error('db'));
    w.vault.remove = async () => Promise.reject(new Error('db'));
    const r = await resolvedOffer(world, w);
    assert.deepEqual(await w.wallet.offers.accept(r.offer, { txCode: r.txCode }), { ok: false, code: 'STORAGE_ERROR', retryable: false, codeRedeemed: true });
    const row = [...w.rows.values()][0]!;
    assert.equal(w.secrets.has(`identra.key.${row.key_id}`), true, 'the row that could not be removed keeps its key');
    // The row was removed: the received credential and its key wait in the offer for the next accept,
    // and discard deletes the key when the user gives up.
    const v = world.newWallet();
    const setStatus = v.vault.setStatus;
    v.vault.setStatus = async () => Promise.reject(new Error('db'));
    const r2 = await resolvedOffer(world, v);
    assert.deepEqual(await v.wallet.offers.accept(r2.offer, { txCode: r2.txCode }), { ok: false, code: 'STORAGE_ERROR', retryable: true, codeRedeemed: true });
    assert.deepEqual([v.rows.size, v.secrets.size], [0, 1]);
    await v.wallet.offers.discard(r2.offer);
    nothingLeft(v);
    v.vault.setStatus = setStatus;
  });

  test('F8: an authorization server on another origin is never contacted', async () => {
    const world = await createWorld(listener);
    rewrite(METADATA, (m) => (m['authorization_servers'] = ['https://evil.example/as']));
    const contacted: string[] = [];
    const w = world.newWallet('noble', createMappedFetch((url, init) => (contacted.push(url), nodeHttpFetch(url, init)), { [ORIGIN]: listener.localOrigin }));
    const r = await w.wallet.offers.resolve((await world.offer()).offerUri);
    assert.equal(r.ok, false);
    assert.deepEqual(contacted.filter((u) => !u.startsWith(listener.localOrigin)), []);
  });

  test('F8: refreshStatus writes unknown, never valid, when the trust list is unavailable', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    const r = await resolvedOffer(world, w);
    const a = (await w.wallet.offers.accept(r.offer, { txCode: r.txCode })) as { credentialId: string };
    listener.routes.delete('GET /trust-list');
    world.clock.advance(86_461);
    const refreshed = await w.wallet.credentials.refreshStatus(a.credentialId);
    assert.equal(refreshed.ok && refreshed.status, 'unknown');
    assert.equal([...w.rows.values()][0]!.status_cache, 'unavailable');
  });

  test('F8: the response key is fresh for every credential and is never the credential key', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    const seen: string[] = [];
    const real = listener.routes.get(CREDENTIAL)!;
    listener.routes.set(CREDENTIAL, async (req) => {
      const { plaintext } = await compactDecrypt(req.body, world.keys.requestEncryption.privateKey);
      seen.push(JSON.stringify((JSON.parse(utf8Decode(plaintext)) as { credential_response_encryption: { jwk: { x: string } } }).credential_response_encryption.jwk.x));
      return real(req);
    });
    for (let i = 0; i < 2; i++) {
      const r = await resolvedOffer(world, w);
      assert.equal((await w.wallet.offers.accept(r.offer, { txCode: r.txCode })).ok, true);
    }
    const cnfXs = await Promise.all([...w.rows.values()].map(async (row) => JSON.stringify((await w.keyStore.signer(row.key_id)).publicJwk.x)));
    assert.equal(new Set([...seen, ...cnfXs]).size, 4);
  });
});

describe('resumable accept (app review A)', () => {
  const TOKEN = 'POST /issuers/truong-mau/token';
  const CREDENTIAL_POST = 'POST /issuers/truong-mau/credential';
  const count = (key: string) => listener.requests.filter((r) => r === key).length;
  /** A wallet whose fetch fails once, with no answer, for the first request to a path ending in `suffix`. */
  const failingOnce = (world: World, suffix: string) => {
    let failed = false;
    return world.newWallet('noble', createMappedFetch(async (url, init) => {
      if (!failed && url.endsWith(suffix)) {
        failed = true;
        throw new TypeError('fetch failed');
      }
      return nodeHttpFetch(url, init);
    }, { [ORIGIN]: listener.localOrigin }));
  };

  test('a cancelled prompt at key creation or at signing: retryable, then the same offer completes with one token request and no orphan key', async () => {
    for (const where of ['create', 'signer'] as const) {
      const world = await createWorld(listener);
      const w = world.newWallet();
      const { offer, txCode } = await resolvedOffer(world, w);
      const real = w.keyStore[where];
      (w.keyStore as unknown as Record<string, unknown>)[where] = async () => Promise.reject(new WalletKeyError('CANCELLED'));
      assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'USER_CANCELLED', retryable: true, codeRedeemed: true }, where);
      assert.equal(w.secrets.size, 0, `${where}: no key left behind`);
      assert.equal(offer.codeRedeemed, true, where);
      (w.keyStore as unknown as Record<string, unknown>)[where] = real;
      // The PIN is not needed, and ignored, on a resume after the token step.
      const second = await w.wallet.offers.accept(offer, where === 'create' ? {} : { txCode: otherPin(txCode) });
      assert.equal(second.ok, true, `${where}: ${JSON.stringify(second)}`);
      assert.deepEqual([count(TOKEN), w.rows.size, w.secrets.size], [1, 1, 1], where);
    }
  });

  test('no answer to the nonce or to the credential request: retryable, and the same token completes it', async () => {
    for (const suffix of ['/nonce', '/credential']) {
      const world = await createWorld(listener);
      const w = failingOnce(world, suffix);
      const { offer, txCode } = await resolvedOffer(world, w);
      assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'NETWORK_ERROR', retryable: true, codeRedeemed: true }, suffix);
      assert.equal(w.secrets.size, 0);
      assert.equal((await w.wallet.offers.accept(offer, { txCode })).ok, true, suffix);
      assert.deepEqual([count(TOKEN), count(CREDENTIAL_POST)], [1, 1], suffix);
    }
  });

  test('no answer to the token request: codeRedeemed false; without the PIN TX_CODE_REQUIRED and nothing sent; with it one credential', async () => {
    const world = await createWorld(listener);
    const sent: string[] = [];
    let failed = false;
    const w = world.newWallet('noble', createMappedFetch(async (url, init) => {
      sent.push(url);
      if (!failed && url.endsWith('/token')) {
        failed = true;
        throw new DOMException('The operation timed out.', 'TimeoutError'); // what the app's fetch throws at timeoutMs
      }
      return nodeHttpFetch(url, init);
    }, { [ORIGIN]: listener.localOrigin }));
    const { offer, txCode } = await resolvedOffer(world, w);
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'NETWORK_ERROR', retryable: true, codeRedeemed: false });
    assert.equal(offer.codeRedeemed, false);
    sent.length = 0;
    listener.requests.length = 0;
    for (const input of [undefined, {}, { txCode: '' }]) {
      assert.deepEqual(await w.wallet.offers.accept(offer, input), { ok: false, code: 'TX_CODE_REQUIRED', retryable: true, codeRedeemed: false }, JSON.stringify(input));
    }
    assert.deepEqual([sent, listener.requests], [[], []], 'no request at all, so no PIN attempt is spent');
    assert.equal((await w.wallet.offers.accept(offer, { txCode })).ok, true);
    assert.equal(offer.codeRedeemed, true);
    assert.deepEqual([count(TOKEN), count(CREDENTIAL_POST), world.issued.length, w.rows.size, w.secrets.size], [1, 1, 1, 1, 1]);
  });

  test('a token answer lost on the way back: the code was spent, so the retry with the PIN is OFFER_EXPIRED', async () => {
    const world = await createWorld(listener);
    let lost = false;
    const w = world.newWallet('noble', createMappedFetch(async (url, init) => {
      const r = await nodeHttpFetch(url, init);
      if (!lost && url.endsWith('/token')) {
        lost = true;
        throw new TypeError('fetch failed');
      }
      return r;
    }, { [ORIGIN]: listener.localOrigin }));
    const { offer, txCode } = await resolvedOffer(world, w);
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'NETWORK_ERROR', retryable: true, codeRedeemed: false });
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'OFFER_EXPIRED', retryable: false, codeRedeemed: false });
    assert.equal(world.issued.length, 0);
    nothingLeft(w);
  });

  test('a failing vault write: the received credential is stored on the next accept, without a second credential request', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    const { offer, txCode } = await resolvedOffer(world, w);
    const save = w.vault.save;
    w.vault.save = async () => Promise.reject(new Error('disk full'));
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'STORAGE_ERROR', retryable: true, codeRedeemed: true });
    w.vault.save = save;
    const second = await w.wallet.offers.accept(offer, { txCode });
    assert.equal(second.ok, true);
    assert.deepEqual([count(TOKEN), count(CREDENTIAL_POST), world.issued.length, w.rows.size, w.secrets.size], [1, 1, 1, 1, 1]);
  });

  test('after the token expired the offer is over (no request sent); a definitive issuer answer is not retried with the same token', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    const { offer, txCode } = await resolvedOffer(world, w);
    const create = w.keyStore.create;
    w.keyStore.create = async () => Promise.reject(new WalletKeyError('CANCELLED'));
    assert.equal((await w.wallet.offers.accept(offer, { txCode })).ok, false);
    w.keyStore.create = create;
    world.clock.advance(301);
    listener.requests.length = 0;
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'OFFER_EXPIRED', retryable: false, codeRedeemed: true });
    assert.deepEqual(listener.requests, []);

    const world2 = await createWorld(listener);
    const v = world2.newWallet();
    const second = await resolvedOffer(world2, v);
    const real = listener.routes.get(CREDENTIAL)!;
    listener.routes.set(CREDENTIAL, async () => ({ status: 400, headers: { 'Content-Type': 'application/json' }, body: '{"error":"invalid_proof"}' }));
    assert.deepEqual(await v.wallet.offers.accept(second.offer, { txCode: second.txCode }), { ok: false, code: 'ISSUER_ERROR', retryable: false, codeRedeemed: true });
    listener.routes.set(CREDENTIAL, real);
    listener.requests.length = 0;
    assert.deepEqual(await v.wallet.offers.accept(second.offer, { txCode: second.txCode }), { ok: false, code: 'OFFER_EXPIRED', retryable: false, codeRedeemed: true });
    assert.deepEqual(listener.requests, [], 'neither the code nor the token is sent again');
    nothingLeft(v);
  });

  test('both credential_offer and credential_offer_uri in one QR text are refused, in either order', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    const uri = encodeURIComponent(`${ISS}/offers/AAAAAAAAAAAAAAAAAAAAAA`);
    for (const qr of [`openid-credential-offer://?credential_offer_uri=${uri}&credential_offer=%7B%7D`, `openid-credential-offer://?credential_offer=%7B%7D&credential_offer_uri=${uri}`]) {
      assert.deepEqual(await w.wallet.offers.resolve(qr), { ok: false, code: 'OFFER_INVALID' }, qr);
    }
  });
});

describe('refreshStatus tells why (app review C)', () => {
  test('invalid when the issuer left the trust list or a certificate expired, unknown only when a list is unreachable; checks and times come back', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    const { offer, txCode } = await resolvedOffer(world, w);
    const a = (await w.wallet.offers.accept(offer, { txCode })) as { credentialId: string };
    const receivedAt = world.clock.now().toISOString();
    world.trust.content = { ...world.trust.content, issuers: [] };
    world.clock.advance(3601);
    const gone = await w.wallet.credentials.refreshStatus(a.credentialId);
    assert.ok(gone.ok);
    assert.deepEqual([gone.status, gone.checks.find((c) => c.id === 'issuer_trust')?.code, gone.lastValidAt], ['invalid', 'ISSUER_NOT_TRUSTED', receivedAt]);
    assert.equal(gone.checkedAt, world.clock.now().toISOString());
    assert.equal([...w.rows.values()][0]!.status_cache, 'invalid');
    assert.equal((await w.wallet.credentials.list())[0]!.status, 'invalid');
    const again = await w.wallet.credentials.refreshStatus(a.credentialId);
    assert.equal(again.ok && again.lastValidAt, null, 'one stored check time only: the last valid time is not kept past an invalid check');

    const world2 = await createWorld(listener);
    const v = world2.newWallet();
    const second = await resolvedOffer(world2, v);
    const b = (await v.wallet.offers.accept(second.offer, { txCode: second.txCode })) as { credentialId: string };
    world2.clock.advance(Date.UTC(2029, 1, 1) / 1000 - world2.clock.now().getTime() / 1000);
    const expired = await v.wallet.credentials.refreshStatus(b.credentialId);
    assert.ok(expired.ok);
    assert.deepEqual([expired.status, expired.checks.find((c) => c.id === 'certificate_chain')?.code], ['invalid', 'CERT_EXPIRED']);
  });
});

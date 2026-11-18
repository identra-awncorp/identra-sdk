// The wallet against presentation requests it must refuse or flag, over real HTTP (127.0.0.1:47643),
// key-store failures at submit, and the two pinned behaviours of @openid4vc/openid4vp 0.10.0.
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { Openid4vpClient } from '@openid4vc/openid4vp';
import { base64Decode, base64UrlDecode, base64UrlEncode, parseCertificate, signJws, utf8Decode, utf8Encode, type Signer } from '@identra/sdk-core';
import { webCryptoHasher } from '@identra/sdk-core/webcrypto';
import { SecretStorageError, WalletKeyError } from '@identra/sdk-app';
import { createWorld, leafSigner, newSession, ORIGIN, startListener, UNG_TUYEN, type Listener, type World } from './helpers/world.js';

let listener: Listener;
before(async () => (listener = await startListener(47643)));
after(() => listener.close());

const fingerprintOf = async (signer: Signer) => base64UrlEncode(await webCryptoHasher.sha256(base64Decode(signer.x5c![0]!)));
type Query = { credentials: (Record<string, unknown> & { claims: Record<string, unknown>[] })[]; credential_sets?: unknown };
const query = (p: Record<string, unknown>) => p['dcql_query'] as Query;
const qrFor = (clientId: string, requestUri: string, extra = '') => `openid4vp://?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(requestUri)}${extra}`;

async function setup(o: { untrustedVerifier?: boolean; credentials?: number } = {}) {
  const world = await createWorld(listener, o.untrustedVerifier ? { untrustedVerifier: true } : {});
  // The server trusts itself in every case: only the wallet's trust list changes.
  const serverTrust = { lookup: async () => ({ maToChuc: world.verifierEntry.ma_to_chuc, ten: world.verifierEntry.ten, mucDich: 'request' as const }) };
  const verifier = await world.newVerifier(o.untrustedVerifier ? { trustRegistry: { lookup: async (fp: string, at?: Date) => (fp === world.verifierEntry.chung_thu[0]!.sha256 ? serverTrust.lookup() : world.serverRegistry.lookup(fp, at)) } } : {});
  const w = world.newWallet();
  const ids: string[] = [];
  for (let i = 0; i < (o.credentials ?? 1); i++) ids.push(await world.issueTo(w));
  return { world, verifier, w, ids };
}

/** Signs `edit(payload of a real session)` with `signer` and serves it at /oid4vp/request/crafted. */
async function crafted(world: World, verifier: Awaited<ReturnType<World['newVerifier']>>, edit: (p: Record<string, unknown>) => void, o: { signer?: Signer; header?: Record<string, unknown>; tamper?: boolean; clientIdFromSigner?: boolean } = {}) {
  const session = await newSession(verifier);
  const jwt = (await verifier.requestObject(session.requestId))!.body;
  const payload = JSON.parse(utf8Decode(base64UrlDecode(jwt.split('.')[1]!))) as Record<string, unknown>;
  edit(payload);
  if (o.clientIdFromSigner) payload['client_id'] = `x509_hash:${await fingerprintOf(o.signer!)}`;
  let signed = await signJws({ typ: 'oauth-authz-req+jwt', ...o.header }, utf8Encode(JSON.stringify(payload)), o.signer ?? (await leafSigner('request')));
  if (o.tamper) signed = `${signed.split('.')[0]}.${base64UrlEncode(utf8Encode(JSON.stringify({ ...payload, nonce: 'changed-after-signing-xxxx' })))}.${signed.split('.')[2]}`;
  listener.routes.set('GET /oid4vp/request/crafted', async () => ({ status: 200, headers: { 'Content-Type': 'application/oauth-authz-req+jwt' }, body: signed }));
  void world;
  return `${ORIGIN}/oid4vp/request/crafted`;
}

describe('who is asking', () => {
  test('a verifier missing from the trust list: resolve flags it, submit refuses without allowUntrusted', async () => {
    const { verifier, w, ids } = await setup({ untrustedVerifier: true });
    const session = (await newSession(verifier));
    const r = await w.wallet.presentations.resolve(session.qr);
    assert.ok(r.ok);
    assert.deepEqual([r.request.verifier, r.request.warning], [{ trusted: false }, 'VERIFIER_NOT_TRUSTED']);
    assert.equal(r.request.matches.length, 1, 'the matches are still shown, under the warning');
    assert.deepEqual(await w.wallet.presentations.submit(r.request, { credentialId: ids[0]!, claimSetIndex: 1 }), { ok: false, code: 'VERIFIER_NOT_TRUSTED' });
    assert.equal((await verifier.session(session.id))?.status, 'request_retrieved', 'nothing was sent');
    assert.deepEqual(await w.wallet.presentations.submit(r.request, { credentialId: ids[0]!, claimSetIndex: 1, allowUntrusted: true }), { ok: true });
    assert.equal((await verifier.session(session.id))?.status, 'verified');
  });

  test('no trust list at all: TRUST_LIST_UNAVAILABLE (fail closed)', async () => {
    const { world, verifier } = await setup({ credentials: 0 });
    const session = (await newSession(verifier));
    listener.routes.delete('GET /trust-list');
    assert.deepEqual(await world.newWallet().wallet.presentations.resolve(session.qr), { ok: false, code: 'TRUST_LIST_UNAVAILABLE' });
  });

  test('no matching credential: ok with no matches; two diplomas: both offered', async () => {
    const { world, verifier, w, ids } = await setup({ credentials: 2 });
    const empty = await world.newWallet().wallet.presentations.resolve((await newSession(verifier)).qr);
    assert.ok(empty.ok);
    assert.deepEqual(empty.request.matches, []);
    const two = await w.wallet.presentations.resolve((await newSession(verifier)).qr);
    assert.ok(two.ok);
    assert.deepEqual(two.request.matches.map((m) => m.credentialId).sort(), [...ids].sort());
  });
});

describe('request objects the wallet refuses before anything is shown', () => {
  test('each rule, with its code', async () => {
    const { world, verifier, w } = await setup({ credentials: 0 });
    const request = await leafSigner('request');
    const evil = await leafSigner('evil-vc', 'evil-issuing');
    const clientId = `x509_hash:${await fingerprintOf(request)}`;
    const cases: [string, () => Promise<string>, string][] = [
      ['a chain from another PKI', async () => qrFor(`x509_hash:${await fingerprintOf(evil)}`, await crafted(world, verifier, (p) => (p['client_id'] = `x509_hash:${'A'.repeat(43)}`), { signer: evil })), 'CERT_CHAIN_UNTRUSTED'],
      ['client_id of the QR is not the hash', async () => qrFor(`x509_hash:${'A'.repeat(43)}`, await crafted(world, verifier, (p) => (p['client_id'] = `x509_hash:${'A'.repeat(43)}`))), 'CLIENT_ID_MISMATCH'],
      ['client_id of the JWT is not the QR one', async () => qrFor(clientId, await crafted(world, verifier, (p) => (p['client_id'] = `x509_hash:${'B'.repeat(43)}`))), 'CLIENT_ID_MISMATCH'],
      ['response_uri on another origin', async () => qrFor(clientId, await crafted(world, verifier, (p) => (p['response_uri'] = 'https://evil.example/oid4vp/response/x'))), 'URL_NOT_ALLOWED'],
      ['response_uri over http', async () => qrFor(clientId, await crafted(world, verifier, (p) => (p['response_uri'] = 'http://api-identra.awncorp.vn/oid4vp/response/x'))), 'URL_NOT_ALLOWED'],
      ['response_mode direct_post', async () => qrFor(clientId, await crafted(world, verifier, (p) => (p['response_mode'] = 'direct_post'))), 'REQUEST_INVALID'],
      ['no nonce', async () => qrFor(clientId, await crafted(world, verifier, (p) => delete p['nonce'])), 'REQUEST_INVALID'],
      ['expired', async () => qrFor(clientId, await crafted(world, verifier, (p) => (p['exp'] = (p['iat'] as number) - 120))), 'REQUEST_EXPIRED'],
      ['typ JWT', async () => qrFor(clientId, await crafted(world, verifier, () => {}, { header: { typ: 'JWT' } })), 'REQUEST_INVALID'],
      ['an off-curve encryption key', async () => qrFor(clientId, await crafted(world, verifier, (p) => {
        const key = (p['client_metadata'] as { jwks: { keys: Record<string, string>[] } }).jwks.keys[0]!;
        const y = base64UrlDecode(key['y']!);
        y[31]! ^= 1;
        key['y'] = base64UrlEncode(y);
      })), 'REQUEST_INVALID'],
      ['a payload changed after signing', async () => qrFor(clientId, await crafted(world, verifier, () => {}, { tamper: true })), 'SIGNATURE_INVALID'],
      ['no exp', async () => qrFor(clientId, await crafted(world, verifier, (p) => delete p['exp'])), 'REQUEST_INVALID'],
      ['an exp ten years away', async () => qrFor(clientId, await crafted(world, verifier, (p) => (p['exp'] = (p['iat'] as number) + 315_360_000))), 'REQUEST_INVALID'],
      ['an exp 601 s after iat', async () => qrFor(clientId, await crafted(world, verifier, (p) => (p['exp'] = (p['iat'] as number) + 601))), 'REQUEST_INVALID'],
      ['another aud', async () => qrFor(clientId, await crafted(world, verifier, (p) => (p['aud'] = 'https://wallet.example'))), 'REQUEST_INVALID'],
      ['response_type id_token', async () => qrFor(clientId, await crafted(world, verifier, (p) => (p['response_type'] = 'vp_token id_token'))), 'REQUEST_INVALID'],
      ['two encryption keys', async () => qrFor(clientId, await crafted(world, verifier, (p) => {
        const jwks = (p['client_metadata'] as { jwks: { keys: Record<string, string>[] } }).jwks;
        jwks.keys.push({ ...jwks.keys[0]!, kid: 'second' });
      })), 'REQUEST_INVALID'],
      ['DCQL value matching', async () => qrFor(clientId, await crafted(world, verifier, (p) => (query(p).credentials[0]!.claims[0]!['values'] = ['Nguyễn Văn A']))), 'REQUEST_INVALID'],
      ['DCQL credential_sets with two options', async () => qrFor(clientId, await crafted(world, verifier, (p) => (query(p).credential_sets = [{ options: [['credential'], ['credential']] }]))), 'REQUEST_INVALID'],
      ['two credential queries', async () => qrFor(clientId, await crafted(world, verifier, (p) => query(p).credentials.push({ ...query(p).credentials[0]!, id: 'second' }))), 'REQUEST_INVALID'],
      ['multiple: true', async () => qrFor(clientId, await crafted(world, verifier, (p) => (query(p).credentials[0]!['multiple'] = true))), 'REQUEST_INVALID'],
    ];
    // Built one at a time: each serves its request object at the same path.
    for (const [name, qr, code] of cases) {
      const text = await qr();
      listener.requests.length = 0;
      assert.deepEqual(await w.wallet.presentations.resolve(text), { ok: false, code }, name);
    }
  });

  test('QR texts: only openid4vp://?client_id=x509_hash:…&request_uri=https://…', async () => {
    const { verifier, w } = await setup({ credentials: 0 });
    const session = (await newSession(verifier));
    const requestUri = `${ORIGIN}/oid4vp/request/${session.requestId}`;
    listener.requests.length = 0;
    for (const [qr, code] of [
      [`${session.qr}&request_uri_method=post`, 'REQUEST_INVALID'],
      [`openid4vp://?client_id=${encodeURIComponent(verifier.clientId)}&request=eyJhbGciOiJFUzI1NiJ9.e30.c2ln`, 'REQUEST_INVALID'],
      [qrFor('redirect_uri:https://evil.example/cb', requestUri), 'REQUEST_INVALID'],
      [qrFor('x509_san_dns:api-identra.awncorp.vn', requestUri), 'REQUEST_INVALID'],
      [`${session.qr}&state=x`, 'REQUEST_INVALID'],
      [`openid4vp://?request_uri=${encodeURIComponent(requestUri)}`, 'REQUEST_INVALID'],
      [qrFor(verifier.clientId, requestUri.replace('https:', 'http:')), 'URL_NOT_ALLOWED'],
      [session.qr.replace('openid4vp://', 'haip-vp://'), 'REQUEST_INVALID'],
    ]) {
      assert.deepEqual(await w.wallet.presentations.resolve(qr!), { ok: false, code }, qr);
    }
    assert.deepEqual(listener.requests, [], 'nothing was fetched');
  });
});

describe('submit', () => {
  test('key-store refusals map to wallet codes; an expired request is not answered; decline is local', async () => {
    const { world, verifier, w, ids } = await setup();
    const fresh = async () => {
      const r = await w.wallet.presentations.resolve((await newSession(verifier)).qr);
      assert.ok(r.ok);
      return r.request;
    };
    const original = w.keyStore.signer;
    for (const [rejection, code] of [
      [new WalletKeyError('CANCELLED'), 'USER_CANCELLED'],
      [new WalletKeyError('KEY_INVALIDATED'), 'KEY_INVALIDATED'],
      [new WalletKeyError('LOCKED'), 'DEVICE_LOCKED'],
      [new WalletKeyError('KEY_NOT_FOUND'), 'KEY_NOT_FOUND'],
      [new Error('keychain exploded'), 'STORAGE_ERROR'],
    ] as const) {
      w.keyStore.signer = async () => Promise.reject(rejection);
      assert.deepEqual(await w.wallet.presentations.submit(await fresh(), { credentialId: ids[0]!, claimSetIndex: 1 }), { ok: false, code }, code);
    }
    // A hardware key prompts when it signs: its rejection is reported the same way.
    w.keyStore.signer = async (keyId) => ({ ...(await original(keyId)), sign: () => Promise.reject(new SecretStorageError('CANCELLED')) });
    assert.deepEqual(await w.wallet.presentations.submit(await fresh(), { credentialId: ids[0]!, claimSetIndex: 1 }), { ok: false, code: 'USER_CANCELLED' });
    w.keyStore.signer = original;

    const late = await fresh();
    world.clock.advance(300);
    assert.deepEqual(await w.wallet.presentations.submit(late, { credentialId: ids[0]!, claimSetIndex: 1 }), { ok: false, code: 'REQUEST_EXPIRED' });
    const declined = await fresh();
    await assert.rejects(w.wallet.presentations.submit(declined, { credentialId: ids[0]!, claimSetIndex: 2 }), TypeError);
    assert.deepEqual(w.wallet.presentations.decline(declined), { ok: true });
    assert.deepEqual(await w.wallet.presentations.submit(declined, { credentialId: ids[0]!, claimSetIndex: 1 }), { ok: false, code: 'REQUEST_INVALID' });
    assert.deepEqual(w.wallet.presentations.decline(declined), { ok: false, code: 'REQUEST_INVALID' });
    // Single use: a second submit, even with another claim set, sends nothing.
    const once = await fresh();
    listener.requests.length = 0;
    const [a, b] = await Promise.all([
      w.wallet.presentations.submit(once, { credentialId: ids[0]!, claimSetIndex: 1 }),
      w.wallet.presentations.submit(once, { credentialId: ids[0]!, claimSetIndex: 0 }),
    ]);
    assert.deepEqual([a, b].map((r) => r.ok).sort(), [false, true]);
    assert.deepEqual([a, b].find((r) => !r.ok), { ok: false, code: 'REQUEST_INVALID' });
    assert.deepEqual(await w.wallet.presentations.submit(once, { credentialId: ids[0]!, claimSetIndex: 1 }), { ok: false, code: 'REQUEST_INVALID' });
    assert.equal(listener.requests.filter((r) => r.startsWith('POST /oid4vp/response/')).length, 1);
  });
});

describe('pinned behaviours of @openid4vc/openid4vp 0.10.0 (an upgrade that changes them fails here)', () => {
  const libraryFetch = (seen: { method?: string; body?: unknown }[]) => (url: string, init: RequestInit) => {
    seen.push({ method: init.method as string, body: init.body });
    return fetch(url.replace(ORIGIN, listener.localOrigin), init);
  };
  const callbacks = (seen: { method?: string; body?: unknown }[], withMetadata: boolean) => ({
    fetch: libraryFetch(seen),
    hash: (d: string | ArrayBuffer) => webCryptoHasher.sha256(typeof d === 'string' ? utf8Encode(d) : new Uint8Array(d)),
    verifyJws: async (signer: { x5c?: string[] }) => ({ verified: true, signerJwk: parseCertificate(base64Decode(signer.x5c![0]!)).publicJwk! }),
    ...(withMetadata ? { getX509CertificateMetadata: () => ({ sanDnsNames: [], sanUriNames: [] }) } : {}),
  });

  test('x509_hash needs a getX509CertificateMetadata callback, which it never reads for that prefix', async () => {
    const { world, verifier } = await setup({ credentials: 0 });
    for (const withMetadata of [false, true]) {
      const session = (await newSession(verifier));
      const client = new Openid4vpClient({ callbacks: callbacks([], withMetadata) as never });
      const parsed = client.parseOpenid4vpAuthorizationRequest({ authorizationRequest: session.qr });
      const resolving = client.resolveOpenid4vpAuthorizationRequest({ authorizationRequestPayload: parsed.params as never, responseMode: { type: 'direct_post' } as never, now: world.clock.now() });
      if (withMetadata) assert.equal((await resolving).client.prefix, 'x509_hash');
      else await assert.rejects(resolving);
    }
  });

  test('request_uri_method=post sends the flattened wallet metadata, without wallet_nonce (so the wallet uses GET only)', async () => {
    const { world, verifier } = await setup({ credentials: 0 });
    const session = (await newSession(verifier));
    const seen: { method?: string; body?: unknown }[] = [];
    const client = new Openid4vpClient({ callbacks: callbacks(seen, true) as never });
    const parsed = client.parseOpenid4vpAuthorizationRequest({ authorizationRequest: `${session.qr}&request_uri_method=post` });
    await client
      .resolveOpenid4vpAuthorizationRequest({
        authorizationRequestPayload: parsed.params as never, responseMode: { type: 'direct_post' } as never, now: world.clock.now(),
        wallet: { nonce: 'wallet-nonce-1', metadata: { vp_formats_supported: { 'dc+sd-jwt': {} } } } as never,
      })
      .catch(() => {});
    assert.equal(seen[0]?.method, 'post');
    const body = String(seen[0]?.body);
    assert.equal(body.includes('wallet_nonce'), false, 'OpenID4VP 1.0 section 5.10 wants wallet_nonce in the body');
    assert.equal(body.includes('wallet_metadata'), false, 'and wallet_metadata as one JSON parameter');
    void UNG_TUYEN;
  });
});

describe('GĐ6 review: who the wallet says is asking, what it shows, storage failures', () => {
  test('an issuer\'s vc certificate signing a request is never shown as a trusted verifier (purpose check)', async () => {
    const { world, verifier, w } = await setup();
    const vc = await leafSigner('vc');
    const r = await w.wallet.presentations.resolve(qrFor(`x509_hash:${await fingerprintOf(vc)}`, await crafted(world, verifier, (p) => (p['client_id'] = 'x'), { signer: vc, clientIdFromSigner: true })));
    assert.ok(r.ok, JSON.stringify(r));
    assert.deepEqual([r.request.verifier, r.request.warning, 'purpose' in r.request], [{ trusted: false }, 'VERIFIER_NOT_TRUSTED', false]);
  });

  test('purpose: a safe string or { vi, en } of at most 300 characters; anything else is dropped; never for an untrusted verifier', async () => {
    const { world, verifier, w } = await setup();
    const clientId = verifier.clientId;
    const withPurpose = async (purpose: unknown) => {
      const r = await w.wallet.presentations.resolve(qrFor(clientId, await crafted(world, verifier, (p) => (query(p).credential_sets = [{ options: [['credential']], purpose }]))));
      assert.ok(r.ok, JSON.stringify(r));
      return r.request.purpose;
    };
    assert.equal(await withPurpose('Ứng tuyển'), 'Ứng tuyển');
    assert.deepEqual(await withPurpose({ vi: 'Ứng tuyển' }), { vi: 'Ứng tuyển' });
    for (const bad of ['x'.repeat(301), 'Ứng tuyển\u202egnàh', 'line\nbreak', '', { vi: 'a', fr: 'b' }, { vi: 'a', en: 'x'.repeat(301) }, { vi: 1 }, {}, 42]) {
      assert.equal(await withPurpose(bad), undefined, JSON.stringify(bad));
    }
    // A purpose DCQL itself does not allow (string, number or object) makes the query invalid.
    const r0 = await w.wallet.presentations.resolve(qrFor(clientId, await crafted(world, verifier, (p) => (query(p).credential_sets = [{ options: [['credential']], purpose: ['a'] }]))));
    assert.deepEqual(r0, { ok: false, code: 'REQUEST_INVALID' });
    const untrusted = await setup({ untrustedVerifier: true });
    const r = await untrusted.w.wallet.presentations.resolve((await newSession(untrusted.verifier)).qr);
    assert.ok(r.ok);
    assert.equal('purpose' in r.request, false);
  });

  test('storage failures: key-store codes propagate, others are STORAGE_ERROR, in resolve and in submit', async () => {
    const { verifier, w, ids } = await setup();
    const open = w.vault.open;
    const list = w.vault.list;
    for (const [failure, code] of [[new SecretStorageError('CANCELLED'), 'USER_CANCELLED'], [new SecretStorageError('LOCKED'), 'DEVICE_LOCKED'], [new SecretStorageError('KEY_INVALIDATED'), 'KEY_INVALIDATED'], [new Error('sqlite busy'), 'STORAGE_ERROR']] as const) {
      w.vault.open = async () => Promise.reject(failure);
      assert.deepEqual(await w.wallet.presentations.resolve((await newSession(verifier)).qr), { ok: false, code }, `resolve ${code}`);
      w.vault.open = open;
      const r = await w.wallet.presentations.resolve((await newSession(verifier)).qr);
      assert.ok(r.ok);
      w.vault.open = async () => Promise.reject(failure);
      assert.deepEqual(await w.wallet.presentations.submit(r.request, { credentialId: ids[0]!, claimSetIndex: 1 }), { ok: false, code }, `submit ${code}`);
      w.vault.open = open;
    }
    w.vault.list = async () => Promise.reject(new Error('sqlite busy'));
    assert.deepEqual(await w.wallet.presentations.resolve((await newSession(verifier)).qr), { ok: false, code: 'STORAGE_ERROR' });
    w.vault.list = list;
  });
});

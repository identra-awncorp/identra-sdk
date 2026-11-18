// The OpenID4VCI issuer called directly, as a controller would: every protocol error with its exact
// OAuth code, single use under concurrency, the order of effects when a dependency fails.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, test } from 'node:test';
import { CompactEncrypt, compactDecrypt, importJWK } from 'jose';
import {
  base64Decode, base64Encode, base64UrlDecode, base64UrlEncode, decodeCredentialUnverified, normalizeEcPublicJwk, utf8Decode, utf8Encode,
  type RandomSource, type Signer,
} from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair, webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import {
  createCredentialIssuer, createMemoryStateStore, createMemoryStatusListStorage, createStatusListService, generateIssuerKeys,
  type CredentialHandlers, type HttpResponse, type IssuedEvent, type ProtocolStateStore,
} from '@identra/sdk-server';
import { fakeClock } from './helpers.js';

const ISS = 'https://api-identra.awncorp.vn/issuers/truong-mau';
const CONFIG = 'bang-tot-nghiep-v1';
const NOW = new Date('2026-06-01T00:00:00Z');
const DIPLOMA = { ho_ten: 'Nguyễn Văn A', ngay_sinh: '2001-02-03', ma_sinh_vien: 'SV1', nganh: 'CNTT', hang_tot_nghiep: 'Giỏi', nam_tot_nghiep: '2024', so_hieu_bang: 'B-1' };
const PKI = new URL('../../../.pki/test/', import.meta.url);
const pem = (p: string) => readFileSync(new URL(p, PKI), 'utf8');
const der = (p: string) => base64Decode(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END/.exec(pem(p))![1]!.replace(/\s+/g, ''));
const vcSigner = createWebCryptoSigner({ privateKey: pem('leaf/vc.key.pem'), x5c: [base64Encode(der('leaf/vc.cert.pem')), base64Encode(der('ca/issuing/ca.cert.pem'))] });
const b64json = (v: unknown) => base64UrlEncode(utf8Encode(JSON.stringify(v)));
const body = (r: HttpResponse) => JSON.parse(r.body) as Record<string, unknown>;
const form = (fields: Record<string, string>) => ({ headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() });

async function world(o: { handlers?: Partial<CredentialHandlers>; store?: (s: ProtocolStateStore) => ProtocolStateStore; random?: RandomSource } = {}) {
  const clock = fakeClock(NOW);
  const statusStorage = createMemoryStatusListStorage();
  const keyStore = { signer: async () => { throw new Error('unused'); }, trustListSigner: async () => { throw new Error('unused'); }, trustedRoots: () => [] };
  const statusService = createStatusListService({ issuerUri: (n) => `https://api-identra.awncorp.vn/issuers/${n}`, keyStore, storage: statusStorage, random: webCryptoRandom, clock });
  const issued: IssuedEvent[] = [];
  const allocations: { uri: string; idx: number }[] = [];
  const puts: string[] = [];
  const memory = createMemoryStateStore(clock);
  const recording: ProtocolStateStore = { ...memory, put: (k, v, t) => (puts.push(v), memory.put(k, v, t)) };
  const keys = await generateIssuerKeys(webCryptoRandom);
  const issuer = createCredentialIssuer({
    issuerUri: ISS, display: { vi: 'Trường Mẫu', en: 'Sample University' }, signer: await vcSigner,
    allocateStatus: async () => {
      const a = await statusService.allocate('truong-mau');
      allocations.push(a);
      return a;
    },
    hasher: webCryptoHasher, verifier: webCryptoVerifier, random: o.random ?? webCryptoRandom, clock, store: (o.store ?? ((s) => s))(recording), keys,
    credentials: {
      [CONFIG]: {
        resolveClaims: o.handlers?.resolveClaims ?? (async () => ({ ...DIPLOMA })),
        onIssued: o.handlers?.onIssued ?? (async (e) => (issued.push(e), { credentialId: `cred-${issued.length}` })),
      },
    },
  });
  const holder = await createWebCryptoSigner(await generateWebCryptoKeyPair());
  const now = () => Math.floor(clock.now().getTime() / 1000);

  const newOffer = async () => {
    const created = await issuer.createOffer({ subjectRef: 'sv001', configurationId: CONFIG });
    const offer = body(await issuer.offer(created.offerId)) as { grants: Record<string, { 'pre-authorized_code': string }> };
    const code = offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']!['pre-authorized_code'];
    return { ...created, code };
  };
  const token = (code: string, txCode: string) => issuer.token(form({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code, tx_code: txCode }));
  const accessToken = async () => {
    const o = await newOffer();
    return body(await token(o.code, o.txCode))['access_token'] as string;
  };
  const cNonce = async () => body(await issuer.nonce())['c_nonce'] as string;
  /** A proof JWT; header/payload members set to undefined are left out. Signed by `signer` exactly as given. */
  const proof = async (p: { header?: Record<string, unknown>; payload?: Record<string, unknown>; signer?: Signer; nonce?: string } = {}) => {
    const signer = p.signer ?? holder;
    const input = `${b64json({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: holder.publicJwk, ...p.header })}.${b64json({ aud: ISS, iat: now(), nonce: p.nonce ?? (await cNonce()), ...p.payload })}`;
    return `${input}.${base64UrlEncode(await signer.sign(utf8Encode(input)))}`;
  };
  const credential = (at: string, request: unknown, contentType = 'application/json') =>
    issuer.credential({ headers: { authorization: `Bearer ${at}`, 'content-type': contentType }, body: typeof request === 'string' ? request : JSON.stringify(request) });
  const requestWith = async (proofs: unknown) => ({ credential_configuration_id: CONFIG, proofs });
  return { clock, issuer, keys, issued, allocations, statusStorage, holder, puts, newOffer, token, accessToken, cNonce, proof, credential, requestWith };
}

const error = (r: HttpResponse) => [r.status, body(r)['error']];

describe('metadata and offers', () => {
  test('credential issuer, authorization server metadata and jwks', async () => {
    const w = await world();
    const m = body(w.issuer.metadata());
    assert.equal(m['credential_issuer'], ISS);
    assert.equal(m['credential_endpoint'], `${ISS}/credential`);
    assert.equal(m['nonce_endpoint'], `${ISS}/nonce`);
    assert.deepEqual(m['display'], [{ name: 'Trường Mẫu', locale: 'vi' }, { name: 'Sample University', locale: 'en' }]);
    assert.deepEqual((m['credential_response_encryption'] as Record<string, unknown>)['alg_values_supported'], ['ECDH-ES']);
    const reqEnc = m['credential_request_encryption'] as { jwks: { keys: Record<string, unknown>[] }; enc_values_supported: string[] };
    assert.deepEqual(reqEnc.enc_values_supported, ['A256GCM', 'A128GCM']);
    assert.equal(reqEnc.jwks.keys[0]!['alg'], 'ECDH-ES');
    assert.equal('d' in reqEnc.jwks.keys[0]!, false);
    const c = (m['credential_configurations_supported'] as Record<string, Record<string, unknown>>)[CONFIG]!;
    assert.equal(c['format'], 'dc+sd-jwt');
    assert.equal(c['vct'], 'https://identra.awncorp.vn/vct/bang-tot-nghiep/v1');
    const claims = (c['credential_metadata'] as { claims: { path: string[]; display: unknown[] }[] }).claims;
    assert.deepEqual(claims.map((x) => x.path[0]), ['ho_ten', 'ngay_sinh', 'ma_sinh_vien', 'nganh', 'hang_tot_nghiep', 'nam_tot_nghiep', 'so_hieu_bang']);
    assert.equal(claims.every((x) => x.display.length === 2), true);
    const as = body(w.issuer.authorizationServerMetadata());
    assert.equal(as['issuer'], ISS);
    assert.equal(as['token_endpoint'], `${ISS}/token`);
    assert.equal(as['pre-authorized_grant_anonymous_access_supported'], true);
    const jwks = body(w.issuer.jwks()) as { keys: Record<string, unknown>[] };
    assert.deepEqual(Object.keys(jwks.keys[0]!).sort(), ['alg', 'crv', 'kid', 'kty', 'use', 'x', 'y']);
  });

  test('createOffer: offer by reference, 6-digit PIN returned once and stored only as a keyed hash', async () => {
    const w = await world();
    const o = await w.newOffer();
    assert.equal(o.offerUri, `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(`${ISS}/offers/${o.offerId}`)}`);
    assert.match(o.txCode, /^[0-9]{6}$/);
    assert.match(o.offerId, /^[A-Za-z0-9_-]{22}$/);
    assert.equal(new Date(o.expiresAt).getTime(), NOW.getTime() + 600_000);
    const offer = body(await w.issuer.offer(o.offerId));
    assert.deepEqual((offer['grants'] as Record<string, Record<string, unknown>>)['urn:ietf:params:oauth:grant-type:pre-authorized_code']!['tx_code'], {
      input_mode: 'numeric', length: 6, description: 'Nhập mã PIN 6 chữ số được cấp cùng mã QR',
    });
    assert.equal(w.puts.some((v) => v.includes(`"${o.txCode}"`) || v === o.txCode), false);
    assert.deepEqual(await w.issuer.offerStatus(o.offerId), { status: 'pending', subjectRef: 'sv001' });
    assert.equal((await w.issuer.offer('unknown')).status, 404);
  });

  test('the PIN is drawn without modulo bias: a draw at or above the largest multiple of 10^6 is drawn again', async () => {
    const pins = [Uint8Array.of(0xff, 0xff, 0xff, 0xff), Uint8Array.of(0xff, 0xf1, 0x3d, 0x80), Uint8Array.of(0, 0, 0, 42)]; // 4294967295, 4294000000 (= limit), 42
    const random: RandomSource = { bytes: (n) => (n === 4 ? pins.shift()! : webCryptoRandom.bytes(n)) };
    const w = await world({ random });
    assert.equal((await w.newOffer()).txCode, '000042');
  });
});

describe('token endpoint', () => {
  test('wrong PIN, then the right PIN on the same offer; the code is single use; the offer is gone once used', async () => {
    const w = await world();
    const o = await w.newOffer();
    const wrong = o.txCode === '000000' ? '000001' : '000000';
    assert.deepEqual(error(await w.token(o.code, wrong)), [400, 'invalid_grant']);
    assert.equal((await w.issuer.offer(o.offerId)).status, 200);
    assert.equal((await w.issuer.offer(o.offerId)).status, 200, 'fetching the offer twice is not a use');
    const ok = await w.token(o.code, o.txCode);
    assert.equal(ok.status, 200);
    assert.equal(ok.headers['Cache-Control'], 'no-store');
    assert.deepEqual({ ...body(ok), access_token: 'x' }, { access_token: 'x', token_type: 'Bearer', expires_in: 300 });
    assert.deepEqual(error(await w.token(o.code, o.txCode)), [400, 'invalid_grant']);
    assert.equal((await w.issuer.offer(o.offerId)).status, 404);
  });

  test('5 wrong PINs destroy the offer', async () => {
    const w = await world();
    const o = await w.newOffer();
    const wrong = o.txCode === '999999' ? '999998' : '999999';
    for (let i = 0; i < 5; i++) assert.deepEqual(error(await w.token(o.code, wrong)), [400, 'invalid_grant']);
    assert.equal((await w.issuer.offer(o.offerId)).status, 404);
    assert.equal((await w.issuer.offerStatus(o.offerId))?.status, 'expired');
    assert.deepEqual(error(await w.token(o.code, o.txCode)), [400, 'invalid_grant']);
  });

  test('an expired offer: invalid_grant, offer 404, status expired, then unknown after 30 minutes', async () => {
    const w = await world();
    const o = await w.newOffer();
    w.clock.advance(600);
    assert.deepEqual(error(await w.token(o.code, o.txCode)), [400, 'invalid_grant']);
    assert.equal((await w.issuer.offer(o.offerId)).status, 404);
    assert.equal((await w.issuer.offerStatus(o.offerId))?.status, 'expired');
    w.clock.advance(1200);
    assert.equal(await w.issuer.offerStatus(o.offerId), null);
  });

  test('20 concurrent token requests with the right PIN: exactly one succeeds', async () => {
    const w = await world();
    const o = await w.newOffer();
    const results = await Promise.all(Array.from({ length: 20 }, () => w.token(o.code, o.txCode)));
    assert.equal(results.filter((r) => r.status === 200).length, 1);
    assert.equal(results.filter((r) => r.status === 400 && body(r)['error'] === 'invalid_grant').length, 19);
  });

  test('malformed requests', async () => {
    const w = await world();
    assert.deepEqual(error(await w.issuer.token({ headers: { 'content-type': 'application/json' }, body: '{}' })), [400, 'invalid_request']);
    assert.deepEqual(error(await w.issuer.token(form({ grant_type: 'authorization_code', code: 'x' }))), [400, 'unsupported_grant_type']);
    assert.deepEqual(error(await w.issuer.token(form({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': 'x' }))), [400, 'invalid_request']);
    const repeated = { headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=a&grant_type=b' };
    assert.deepEqual(error(await w.issuer.token(repeated)), [400, 'invalid_request']);
    assert.deepEqual(error(await w.token('unknown-code', '123456')), [400, 'invalid_grant']);
  });
});

describe('credential endpoint', () => {
  test('one credential per access token, bound to the proof key, recorded through onIssued', async () => {
    const w = await world();
    const o = await w.newOffer();
    const at = body(await w.token(o.code, o.txCode))['access_token'] as string;
    const nonce = await w.issuer.nonce();
    assert.equal(nonce.headers['Cache-Control'], 'no-store');
    assert.equal(body(nonce)['c_nonce_expires_in'], 300);
    const r = await w.credential(at, await w.requestWith({ jwt: [await w.proof({ nonce: body(nonce)['c_nonce'] as string })] }));
    assert.equal(r.status, 200, r.body);
    const compact = ((body(r)['credentials'] as { credential: string }[])[0]!).credential;
    const decoded = decodeCredentialUnverified(compact);
    assert.equal(decoded.payload['iss'], ISS);
    assert.deepEqual((decoded.payload['cnf'] as { jwk: unknown }).jwk, w.holder.publicJwk);
    assert.deepEqual(decoded.payload['status'], { status_list: w.allocations[0] });
    assert.equal(w.issued.length, 1);
    assert.deepEqual({ ...w.issued[0], cnfThumbprint: typeof w.issued[0]!.cnfThumbprint }, {
      offerId: o.offerId, subjectRef: 'sv001', statusUri: w.allocations[0]!.uri, statusIdx: w.allocations[0]!.idx, cnfThumbprint: 'string', issuedAt: NOW,
    });
    assert.deepEqual(await w.issuer.offerStatus(o.offerId), { status: 'issued', subjectRef: 'sv001', credentialId: 'cred-1' });
    // The same access token again: one credential only.
    assert.deepEqual(error(await w.credential(at, await w.requestWith({ jwt: [await w.proof()] }))), [401, 'invalid_token']);
  });

  test('access token missing, expired, forged or of another key: 401 invalid_token with WWW-Authenticate', async () => {
    const w = await world();
    const at = await w.accessToken();
    const req = await w.requestWith({ jwt: [await w.proof()] });
    const missing = await w.issuer.credential({ headers: { 'content-type': 'application/json' }, body: JSON.stringify(req) });
    assert.deepEqual(error(missing), [401, 'invalid_token']);
    assert.equal(missing.headers['WWW-Authenticate'], 'Bearer error="invalid_token"');
    const [h, p] = at.split('.') as [string, string];
    const payload = JSON.parse(utf8Decode(base64UrlDecode(p)));
    const other = await createWebCryptoSigner(await generateWebCryptoKeyPair());
    const signed = async (header: string, body: string, signer: Signer) => `${header}.${body}.${base64UrlEncode(await signer.sign(utf8Encode(`${header}.${body}`)))}`;
    const forged = [
      await signed(h, p, other), // same header and kid, another key
      `${b64json({ alg: 'none', typ: 'at+jwt', kid: w.keys.accessToken.publicJwk.kid })}.${p}.`,
      await signed(h, b64json({ ...payload, aud: 'https://evil.example' }), w.keys.accessToken.signer),
      await signed(b64json({ alg: 'ES256', typ: 'JWT', kid: w.keys.accessToken.publicJwk.kid }), p, w.keys.accessToken.signer),
      `${h}.${b64json({ ...payload, exp: payload.exp + 3600 })}.${at.split('.')[2]}`,
    ];
    for (const t of forged) assert.deepEqual(error(await w.credential(t, req)), [401, 'invalid_token'], t);
    w.clock.advance(300);
    assert.deepEqual(error(await w.credential(at, await w.requestWith({ jwt: [await w.proof()] }))), [401, 'invalid_token'], 'expired');
  });

  test('c_nonce missing, unknown, reused or expired', async () => {
    const w = await world();
    const at = await w.accessToken();
    assert.deepEqual(error(await w.credential(at, await w.requestWith({ jwt: [await w.proof({ payload: { nonce: undefined } })] }))), [400, 'invalid_proof']);
    assert.deepEqual(error(await w.credential(at, await w.requestWith({ jwt: [await w.proof({ nonce: 'never-issued' })] }))), [400, 'invalid_nonce']);
    const nonce = await w.cNonce();
    assert.equal((await w.credential(at, await w.requestWith({ jwt: [await w.proof({ nonce })] }))).status, 200);
    const at2 = await w.accessToken();
    assert.deepEqual(error(await w.credential(at2, await w.requestWith({ jwt: [await w.proof({ nonce })] }))), [400, 'invalid_nonce'], 'reused');
    const stale = await w.cNonce();
    w.clock.advance(290);
    const at3 = await w.accessToken();
    w.clock.advance(11);
    assert.deepEqual(error(await w.credential(at3, await w.requestWith({ jwt: [await w.proof({ nonce: stale })] }))), [400, 'invalid_nonce'], 'expired');
    assert.equal((await w.credential(at3, await w.requestWith({ jwt: [await w.proof()] }))).status, 200, 'the failures above did not spend the token');
  });

  test('every proof rule: invalid_proof, and the access token is not spent', async () => {
    const w = await world();
    const at = await w.accessToken();
    const other = await createWebCryptoSigner(await generateWebCryptoKeyPair());
    const { x, y } = w.holder.publicJwk;
    const yBytes = base64UrlDecode(y);
    yBytes[31]! ^= 1;
    const offCurve = { kty: 'EC', crv: 'P-256', x, y: base64UrlEncode(yBytes) };
    const hmacProof = async () => {
      const input = `${b64json({ typ: 'openid4vci-proof+jwt', alg: 'HS256', jwk: w.holder.publicJwk })}.${b64json({ aud: ISS, iat: Math.floor(NOW.getTime() / 1000), nonce: await w.cNonce() })}`;
      const key = await crypto.subtle.importKey('raw', new Uint8Array(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      return `${input}.${base64UrlEncode(new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8Encode(input))))}`;
    };
    const cases: [string, unknown][] = [
      ['wrong aud', { jwt: [await w.proof({ payload: { aud: 'https://evil.example/issuers/truong-mau' } })] }],
      ['aud as an array', { jwt: [await w.proof({ payload: { aud: [ISS] } })] }],
      ['wrong typ', { jwt: [await w.proof({ header: { typ: 'JWT' } })] }],
      ['alg none', { jwt: [`${b64json({ typ: 'openid4vci-proof+jwt', alg: 'none', jwk: w.holder.publicJwk })}.${b64json({ aud: ISS, iat: 1, nonce: 'n' })}.`] }],
      ['HS256', { jwt: [await hmacProof()] }],
      ['key with d', { jwt: [await w.proof({ header: { jwk: { ...w.holder.publicJwk, d: base64UrlEncode(new Uint8Array(32)) } } })] }],
      ['off-curve key', { jwt: [await w.proof({ header: { jwk: offCurve } })] }],
      ['kid next to jwk', { jwt: [await w.proof({ header: { kid: 'k1' } })] }],
      ['stale iat', { jwt: [await w.proof({ payload: { iat: Math.floor(NOW.getTime() / 1000) - 361 } })] }],
      ['future iat', { jwt: [await w.proof({ payload: { iat: Math.floor(NOW.getTime() / 1000) + 61 } })] }],
      ['two proofs', { jwt: [await w.proof(), await w.proof()] }],
      ['no proof', { jwt: [] }],
      ['signed by another key than its header jwk', { jwt: [await w.proof({ signer: other })] }],
    ];
    for (const [name, proofs] of cases) {
      const r = await w.credential(at, await w.requestWith(proofs));
      assert.equal(r.status, 400, name);
      assert.ok(['invalid_proof', 'invalid_credential_request'].includes(body(r)['error'] as string), `${name}: ${r.body}`);
      // The library's request schema already refuses an unsigned JWT and a wrong number of proofs.
      if (!['two proofs', 'no proof', 'alg none'].includes(name)) assert.equal(body(r)['error'], 'invalid_proof', name);
    }
    assert.equal((await w.credential(at, await w.requestWith({ jwt: [await w.proof()] }))).status, 200);
  });

  test('response encryption: a plain request asking for it is refused; an encrypted one gets an encrypted response', async () => {
    const w = await world();
    const at = await w.accessToken();
    const { privateKey, publicKey } = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const walletJwk = { ...normalizeEcPublicJwk(await crypto.subtle.exportKey('jwk', publicKey))!, alg: 'ECDH-ES' };
    const asking = { ...(await w.requestWith({ jwt: [await w.proof()] })), credential_response_encryption: { jwk: walletJwk, enc: 'A256GCM' } };
    assert.deepEqual(error(await w.credential(at, asking)), [400, 'invalid_encryption_parameters']);
    const encrypt = async (request: unknown) =>
      new CompactEncrypt(utf8Encode(JSON.stringify(request)))
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM', kid: w.keys.requestEncryption.publicJwk.kid })
        .encrypt(await importJWK(w.keys.requestEncryption.publicJwk, 'ECDH-ES'));
    const withPrivate = { ...asking, credential_response_encryption: { jwk: { ...walletJwk, d: base64UrlEncode(new Uint8Array(32)) }, enc: 'A256GCM' } };
    assert.deepEqual(error(await w.credential(at, await encrypt(withPrivate), 'application/jwt')), [400, 'invalid_encryption_parameters']);
    assert.deepEqual(error(await w.credential(at, 'not.a.jwe.at.all', 'application/jwt')), [400, 'invalid_encryption_parameters']);
    const fresh = { ...asking, proofs: { jwt: [await w.proof()] } };
    const r = await w.credential(at, await encrypt(fresh), 'application/jwt');
    assert.equal(r.status, 200, r.body);
    assert.equal(r.headers['Content-Type'], 'application/jwt');
    const { plaintext } = await compactDecrypt(r.body, privateKey);
    assert.equal((JSON.parse(utf8Decode(plaintext)) as { credentials: unknown[] }).credentials.length, 1);
  });

  test('a configuration the access token does not cover', async () => {
    const w = await world();
    const at = await w.accessToken();
    const r = await w.credential(at, { credential_configuration_id: 'other-v1', proofs: { jwt: [await w.proof()] } });
    assert.deepEqual(error(r), [400, 'unknown_credential_configuration']);
    assert.deepEqual(error(await w.credential(at, '{not json')), [400, 'invalid_credential_request']);
  });
});

describe('order of effects', () => {
  test('onIssued throws: no credential is sent, the offer is not marked issued, the index stays reserved and is never reused', async () => {
    let fail = true;
    const w = await world({
      handlers: {
        onIssued: async () => {
          if (fail) throw new Error('database down');
          return { credentialId: 'cred-ok' };
        },
      },
    });
    const o = await w.newOffer();
    const at = body(await w.token(o.code, o.txCode))['access_token'] as string;
    await assert.rejects(w.credential(at, await w.requestWith({ jwt: [await w.proof()] })), /database down/);
    assert.deepEqual(await w.issuer.offerStatus(o.offerId), { status: 'pending', subjectRef: 'sv001' });
    assert.equal(w.statusStorage.reservedCount('truong-mau', 1), 1);
    assert.deepEqual(error(await w.credential(at, await w.requestWith({ jwt: [await w.proof()] }))), [401, 'invalid_token'], 'the token is spent');
    fail = false;
    const at2 = await w.accessToken();
    assert.equal((await w.credential(at2, await w.requestWith({ jwt: [await w.proof()] }))).status, 200);
    assert.equal(w.statusStorage.reservedCount('truong-mau', 1), 2);
    assert.notEqual(w.allocations[0]!.idx, w.allocations[1]!.idx);
  });

  test('resolveClaims returns null: credential_request_denied before any status is allocated', async () => {
    const w = await world({ handlers: { resolveClaims: async () => null } });
    const at = await w.accessToken();
    assert.deepEqual(error(await w.credential(at, await w.requestWith({ jwt: [await w.proof()] }))), [400, 'credential_request_denied']);
    assert.equal(w.allocations.length, 0);
  });

  test('state store failure mid-flow: the call rejects and nothing is allocated or recorded', async () => {
    let failTake = false;
    const w = await world({
      store: (s) => ({
        ...s,
        take: async (k) => {
          if (failTake && k.includes(':token:')) throw new Error('redis down');
          return s.take(k);
        },
      }),
    });
    const at = await w.accessToken();
    failTake = true;
    await assert.rejects(w.credential(at, await w.requestWith({ jwt: [await w.proof()] })), /redis down/);
    assert.equal(w.allocations.length, 0);
    assert.equal(w.issued.length, 0);
    failTake = false;
  });
});

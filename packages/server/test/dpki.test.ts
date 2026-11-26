// The DID trust path (ADR-0020) on the server: DID files in the key store, a DID issuer over the
// OpenID4VCI flow, its DID-signed status lists, and the verifier with and without `dpki`, against
// a FAKE CertNet gateway (helpers.ts fakeGateway; no gateway exists on this machine). Keys are
// generated at run time.
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, test } from 'node:test';
import { CompactEncrypt, importJWK, type JWK } from 'jose';
import {
  base64Decode, base64Encode, base64UrlDecode, base64UrlEncode, createCertificateChainValidator, createPresentation, createStatusListChecker, decodeCredentialUnverified,
  decodeJws, issueDiploma, signJws, utf8Decode, utf8Encode, VCT, verifyDidStatusListToken, verifyJws, type Signer, type TrustEntry,
} from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair, webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import {
  createCredentialIssuer, createFileKeyStore, createMemoryStateStore, createMemoryStatusListStorage, createPresentationVerifier, createStatusListService, generateIssuerKeys,
  type HttpResponse, type IssuerKeyStore,
} from '@identra/sdk-server';
import { DID, fakeClock, fakeGateway, newDidSigner } from './helpers.js';

const ISSUERS = 'https://api-identra.awncorp.vn/issuers';
const ISS_URL = `${ISSUERS}/truong-did`;
const NOW = new Date('2026-06-01T00:00:00Z');
const CONFIG = 'bang-tot-nghiep-v1';
const DIPLOMA = { ho_ten: 'Nguyễn Văn A', ngay_sinh: '2001-02-03', ma_sinh_vien: 'SV1', nganh: 'CNTT', hang_tot_nghiep: 'Giỏi', nam_tot_nghiep: '2024', so_hieu_bang: 'B-1' };
const body = (r: HttpResponse) => JSON.parse(r.body) as Record<string, unknown>;
const b64json = (v: unknown) => base64UrlEncode(utf8Encode(JSON.stringify(v)));
const header = (jws: string) => JSON.parse(utf8Decode(base64UrlDecode(jws.split('.')[0]!))) as Record<string, unknown>;

/** A PKCS#8 PEM private key generated now (P-256 unless `namedCurve` says otherwise). */
async function pkcs8Pem(namedCurve = 'P-256') {
  const pair = await globalThis.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, ['sign', 'verify']) as CryptoKeyPair;
  const der = Buffer.from(await globalThis.crypto.subtle.exportKey('pkcs8', pair.privateKey)).toString('base64');
  return `-----BEGIN PRIVATE KEY-----\n${der.match(/.{1,64}/g)!.join('\n')}\n-----END PRIVATE KEY-----\n`;
}

/** A key directory with `orgs/<org>/` holding `files` (strings written as is, objects as JSON), keys mode 600. */
function keyDir(files: Record<string, string | object>, org = 'truong-did') {
  const dir = mkdtempSync(join(tmpdir(), 'identra-did-keys-'));
  mkdirSync(join(dir, 'orgs', org), { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, 'orgs', org, name), typeof content === 'string' ? content : JSON.stringify(content), { mode: 0o600 });
  }
  return dir;
}
const didJson = { did: DID, kid: `${DID}#key-1` };

describe('key store: DID files', () => {
  test('did.json + did.key.pem load as a DID signer: ES256, kid, no x5c, the public key of the private key', async () => {
    const store = createFileKeyStore(keyDir({ 'did.json': didJson, 'did.key.pem': await pkcs8Pem() }));
    const signer = (await store.didSigner!('truong-did'))!;
    assert.deepEqual(Object.keys(signer).sort(), ['alg', 'kid', 'publicJwk', 'sign']);
    assert.equal(signer.alg, 'ES256');
    assert.equal(signer.kid, `${DID}#key-1`);
    assert.ok(Object.isFrozen(signer));
    assert.doesNotMatch(JSON.stringify(signer), /"d"|PRIVATE/);
    assert.equal(await store.didSigner!('truong-did'), signer, 'cached');
    const jws = await signJws({ typ: 'test' }, utf8Encode('{}'), signer);
    assert.deepEqual([header(jws)['kid'], 'x5c' in header(jws)], [signer.kid, false]);
    const decoded = decodeJws(jws, 16_384);
    assert.ok(decoded.ok);
    assert.equal(await verifyJws(decoded.jws, signer.publicJwk, webCryptoVerifier), null);
  });

  test('an organisation without DID files has no DID signer', async () => {
    const store = createFileKeyStore(keyDir({ 'vc.key.pem': 'x' }));
    assert.equal(await store.didSigner!('truong-did'), null);
    assert.equal(await store.didSigner!('khong-co'), null);
    await assert.rejects(store.didSigner!('../truong-did'), TypeError);
  });

  test('load errors name the file and the reason, never key material', async () => {
    const key = await pkcs8Pem();
    const secret = key.split('\n')[1]!;
    const cases: [Record<string, string | object>, RegExp][] = [
      [{ 'did.json': didJson }, /needs both did\.json and did\.key\.pem/],
      [{ 'did.key.pem': key }, /needs both did\.json and did\.key\.pem/],
      [{ 'did.json': '{"did": ', 'did.key.pem': key }, /did\.json is not readable JSON/],
      [{ 'did.json': '[]', 'did.key.pem': key }, /did\.json: did is not a did:certnet DID/],
      [{ 'did.json': { ...didJson, did: 'did:web:truong.example.vn' }, 'did.key.pem': key }, /did is not a did:certnet DID/],
      [{ 'did.json': { ...didJson, kid: 'did:certnet:local:other0001#key-1' }, 'did.key.pem': key }, /kid is not <did>#<fragment> of its did/],
      [{ 'did.json': { ...didJson, kid: DID }, 'did.key.pem': key }, /kid is not <did>#<fragment>/],
      [{ 'did.json': { ...didJson, kid: `${DID}#a#b` }, 'did.key.pem': key }, /kid is not <did>#<fragment>/],
      [{ 'did.json': didJson, 'did.key.pem': await pkcs8Pem('P-384') }, /did\.key\.pem is not an EC P-256 private key/],
      [{ 'did.json': didJson, 'did.key.pem': 'not a key' }, /did\.key\.pem is not a single PKCS#8 PRIVATE KEY block/],
      [{ 'did.json': didJson, 'did.key.pem': key, 'vc.key.pem': 'x' }, /both DID files and X\.509 issuing keys/],
      [{ 'did.json': didJson, 'did.key.pem': key, 'status.key.pem': 'x' }, /both DID files and X\.509 issuing keys/],
    ];
    for (const [files, expected] of cases) {
      const e = await createFileKeyStore(keyDir(files)).didSigner!('truong-did').then(() => null, (err: Error) => err);
      assert.ok(e, `${Object.keys(files).join(',')} must be refused`);
      assert.match(e.message, expected);
      assert.doesNotMatch(e.message, new RegExp(secret.slice(0, 20).replace(/[+/]/g, '.')));
    }
    // The private key file must not be readable by others, as every other key file.
    const dir = keyDir({ 'did.json': didJson, 'did.key.pem': key });
    chmodSync(join(dir, 'orgs/truong-did/did.key.pem'), 0o644);
    await assert.rejects(createFileKeyStore(dir).didSigner!('truong-did'), /accessible by group or others/);
  });

  test('an organisation with DID files gets no X.509 issuing signer (one path per issuer), but may still hold a request key', async () => {
    const store = createFileKeyStore(keyDir({ 'did.json': didJson, 'did.key.pem': await pkcs8Pem(), 'vc.key.pem': 'x' }));
    await assert.rejects(store.signer('truong-did', 'vc'), /both DID files and X\.509 issuing keys/);
    await assert.rejects(store.signer('truong-did', 'status'), /both DID files and X\.509 issuing keys/);
    await assert.rejects(store.signer('truong-did', 'request'), (e: Error) => !/both DID files/.test(e.message));
  });
});

/** A DID issuer over the file key store (DID files generated now), its status lists and a fake gateway that knows its DID. */
async function didIssuerWorld() {
  const clock = fakeClock(NOW);
  const keyStore = createFileKeyStore(keyDir({ 'did.json': didJson, 'did.key.pem': await pkcs8Pem() }));
  const signer = (await keyStore.didSigner!('truong-did'))!;
  const gateway = fakeGateway();
  gateway.register(signer);
  const statusService = createStatusListService({ issuerUri: (n) => `${ISSUERS}/${n}`, keyStore, storage: createMemoryStatusListStorage(), random: webCryptoRandom, clock });
  const issuer = createCredentialIssuer({
    issuerUri: ISS_URL, display: { vi: 'Trường DID', en: 'DID University' }, signer, allocateStatus: () => statusService.allocate('truong-did'),
    hasher: webCryptoHasher, verifier: webCryptoVerifier, random: webCryptoRandom, clock, store: createMemoryStateStore(clock), keys: await generateIssuerKeys(webCryptoRandom),
    credentials: { [CONFIG]: { resolveClaims: async () => ({ ...DIPLOMA }), onIssued: async () => ({ credentialId: 'cred-1' }) } },
  });
  return { clock, keyStore, signer, gateway, statusService, issuer };
}

/** Offer -> token (PIN) -> c_nonce -> proof -> credential, called as a controller would. */
async function issueOverOpenId4Vci(issuer: Awaited<ReturnType<typeof didIssuerWorld>>['issuer'], clock: { now(): Date }, issuerUri = ISS_URL) {
  const holder = await createWebCryptoSigner(await generateWebCryptoKeyPair());
  const created = await issuer.createOffer({ subjectRef: 'sv001', configurationId: CONFIG });
  const offer = body(await issuer.offer(created.offerId)) as { credential_issuer: string; grants: Record<string, { 'pre-authorized_code': string }> };
  assert.equal(offer.credential_issuer, issuerUri);
  const code = offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']!['pre-authorized_code'];
  const token = await issuer.token({ headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code, tx_code: created.txCode }).toString() });
  const accessToken = body(token)['access_token'] as string;
  const nonce = body(await issuer.nonce())['c_nonce'] as string;
  const input = `${b64json({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: holder.publicJwk })}.${b64json({ aud: issuerUri, iat: Math.floor(clock.now().getTime() / 1000), nonce })}`;
  const proof = `${input}.${base64UrlEncode(await holder.sign(utf8Encode(input)))}`;
  const r = await issuer.credential({ headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ credential_configuration_id: CONFIG, proofs: { jwt: [proof] } }) });
  assert.equal(r.status, 200, r.body);
  return { compact: ((body(r)['credentials'] as { credential: string }[])[0]!).credential, holder };
}

describe('DID issuer (OpenID4VCI) and its status lists', () => {
  test('the credential has iss = the DID and a kid header without x5c; the issuer identifier stays the https URL; the metadata names the DID', async () => {
    const w = await didIssuerWorld();
    const m = body(w.issuer.metadata());
    assert.equal(m['credential_issuer'], ISS_URL);
    assert.equal(m['identra_issuer_did'], DID);
    assert.equal(body(w.issuer.authorizationServerMetadata())['issuer'], ISS_URL);
    const { compact, holder } = await issueOverOpenId4Vci(w.issuer, w.clock);
    const d = decodeCredentialUnverified(compact);
    assert.equal(d.payload['iss'], DID);
    assert.deepEqual([header(compact)['kid'], 'x5c' in header(compact)], [`${DID}#key-1`, false]);
    assert.deepEqual((d.payload['cnf'] as { jwk: unknown }).jwk, holder.publicJwk);
    const ref = (d.payload['status'] as { status_list: { uri: string; idx: number } }).status_list;
    assert.equal(ref.uri, `${ISS_URL}/status/1`);

    // The list is signed by the DID key (kid, no x5c) and verifies on the DID path.
    const token = (await w.statusService.token('truong-did', 1))!;
    assert.deepEqual([header(token)['kid'], 'x5c' in header(token)], [`${DID}#key-1`, false]);
    const { resolver } = w.gateway.dpki(w.clock);
    const verified = await verifyDidStatusListToken(token, { uri: ref.uri, did: DID, didResolver: resolver, verifier: webCryptoVerifier, now: w.clock.now() });
    assert.equal(verified.ok, true, JSON.stringify(verified));
    assert.deepEqual(w.statusService.current('truong-did', 1), { iat: Math.floor(NOW.getTime() / 1000), exp: Math.floor(NOW.getTime() / 1000) + 86_400, signerNotAfter: null });
    // The checker a verifier uses, over the same gateway and the issuer's served list.
    const listFetch = async (url: string) => (url === ref.uri ? { status: 200, headers: { get: () => null }, text: async () => token } : w.gateway.fetch(url));
    const checker = createStatusListChecker({
      fetch: listFetch, verifier: webCryptoVerifier, chainValidator: { validate: async () => ({ ok: false, code: 'CERT_CHAIN_UNTRUSTED', checks: [] }) },
      trustRegistry: { lookup: async () => null }, clock: w.clock, didResolver: resolver,
    });
    assert.equal(await checker.check(ref, { did: DID }), 'valid');
  });

  test('an X.509 issuer publishes no identra_issuer_did', async () => {
    const pem = (p: string) => readFileSync(new URL(p, new URL('../../../.pki/test/', import.meta.url)), 'utf8');
    const der = (p: string) => base64Encode(base64Decode(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END/.exec(pem(p))![1]!.replace(/\s+/g, '')));
    const clock = fakeClock(NOW);
    const issuer = createCredentialIssuer({
      issuerUri: `${ISSUERS}/truong-mau`, display: { vi: 'Trường Mẫu', en: 'Sample University' },
      signer: await createWebCryptoSigner({ privateKey: pem('leaf/vc.key.pem'), x5c: [der('leaf/vc.cert.pem'), der('ca/issuing/ca.cert.pem')] }),
      allocateStatus: async () => ({ uri: `${ISSUERS}/truong-mau/status/1`, idx: 1 }),
      hasher: webCryptoHasher, verifier: webCryptoVerifier, random: webCryptoRandom, clock, store: createMemoryStateStore(clock), keys: await generateIssuerKeys(webCryptoRandom),
      credentials: { [CONFIG]: { resolveClaims: async () => ({ ...DIPLOMA }), onIssued: async () => ({ credentialId: 'c' }) } },
    });
    assert.equal('identra_issuer_did' in body(issuer.metadata()), false);
  });

  test('a signer with a DID kid must be a did:certnet DID URL without x5c', async () => {
    const base = await didIssuerWorld();
    const keys = await generateIssuerKeys(webCryptoRandom);
    const create = (signer: Signer) => createCredentialIssuer({
      issuerUri: ISS_URL, display: { vi: 'x', en: 'x' }, signer, allocateStatus: async () => ({ uri: `${ISS_URL}/status/1`, idx: 1 }),
      hasher: webCryptoHasher, verifier: webCryptoVerifier, random: webCryptoRandom, clock: base.clock, store: createMemoryStateStore(base.clock), keys, credentials: {},
    });
    assert.doesNotThrow(() => create(base.signer));
    for (const kid of ['did:web:example.com#k', DID, 'did:certnet:local:x#a#b', 'did:certnet:elsewhere:x#k']) {
      assert.throws(() => create({ ...base.signer, kid }), /a DID signer needs/, kid);
    }
    assert.throws(() => create({ ...base.signer, x5c: ['AA=='] }), /a DID signer needs/, 'kid and x5c');
  });

  test('a DID key store org signs no X.509 status list, and an X.509 key store without didSigner is unchanged', async () => {
    const clock = fakeClock(NOW);
    const signer = await newDidSigner();
    const calls: string[] = [];
    const keyStore: IssuerKeyStore = {
      signer: async (org, purpose) => (calls.push(`${org}/${purpose}`), Promise.reject(new Error('no X.509 key'))),
      didSigner: async (org) => (org === 'truong-did' ? signer : null),
      trustListSigner: async () => { throw new Error('unused'); }, trustedRoots: () => [],
    };
    const service = createStatusListService({ issuerUri: (n) => `${ISSUERS}/${n}`, keyStore, storage: createMemoryStatusListStorage(), random: webCryptoRandom, clock });
    await service.allocate('truong-did');
    assert.equal(header((await service.token('truong-did', 1))!)['kid'], signer.kid);
    assert.deepEqual(calls, []);
    await service.allocate('truong-mau');
    await assert.rejects(service.token('truong-mau', 1), /no X\.509 key/);
    assert.deepEqual(calls, ['truong-mau/status']);
  });
});

describe('verifier with the DID path', () => {
  /** A verifier (request certificate of the test PKI) over a fake gateway; `dpki` false leaves the DID path off. */
  async function verifierWorld(o: { dpki?: boolean } = {}) {
    const clock = fakeClock(NOW);
    const PKI = new URL('../../../.pki/test/', import.meta.url);
    const pem = (p: string) => readFileSync(new URL(p, PKI), 'utf8');
    const der = (p: string) => base64Decode(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END/.exec(pem(p))![1]!.replace(/\s+/g, ''));
    const requestSigner = await createWebCryptoSigner({ privateKey: pem('leaf/request.key.pem'), x5c: [base64Encode(der('leaf/request.cert.pem')), base64Encode(der('ca/issuing/ca.cert.pem'))] });
    const requestFp = base64UrlEncode(await webCryptoHasher.sha256(der('leaf/request.cert.pem')));
    const entries = new Map<string, TrustEntry>([[requestFp, { maToChuc: 'VATVN-0100000005', ten: 'Nhà Tuyển Dụng Mẫu', mucDich: 'request' }]]);
    const trustRegistry = { lookup: async (fp: string) => entries.get(fp) ?? null };
    const chainValidator = createCertificateChainValidator({ trustedRoots: [der('ca/root/ca.cert.pem')], verifier: webCryptoVerifier, hasher: webCryptoHasher });
    const gateway = fakeGateway();
    const issuerSigner = await newDidSigner();
    gateway.register(issuerSigner);
    const dpki = gateway.dpki(clock);
    const statusUri = `${ISS_URL}/status/1`;
    const statusService = createStatusListService({
      issuerUri: (n) => `${ISSUERS}/${n}`, storage: createMemoryStatusListStorage(), random: webCryptoRandom, clock,
      keyStore: { signer: async () => { throw new Error('unused'); }, didSigner: async () => issuerSigner, trustListSigner: async () => { throw new Error('unused'); }, trustedRoots: () => [] },
    });
    const status = await statusService.allocate('truong-did');
    const fetch = async (url: string) => (url === statusUri ? { status: 200, headers: { get: () => null }, text: async () => (await statusService.token('truong-did', 1))! } : gateway.fetch(url));
    const statusChecker = createStatusListChecker({ fetch, verifier: webCryptoVerifier, chainValidator, trustRegistry, clock, maxAgeSeconds: 0, didResolver: dpki.resolver });
    const verifier = await createPresentationVerifier({
      apiOrigin: 'https://api-identra.awncorp.vn', signer: requestSigner,
      verification: { verifier: webCryptoVerifier, hasher: webCryptoHasher, chainValidator, trustRegistry, statusChecker, supportedVcts: [VCT.diploma], ...(o.dpki === false ? {} : { dpki }) },
      random: webCryptoRandom, clock, store: createMemoryStateStore(clock), scenarios: { 'ung-tuyen': { vct: VCT.diploma, claimSets: [['ho_ten', 'nganh']], purpose: { vi: 'Ứng tuyển', en: 'Job application' } } },
    });
    const holder = await createWebCryptoSigner(await generateWebCryptoKeyPair());
    const credential = await issueDiploma({ signer: issuerSigner, hasher: webCryptoHasher, random: webCryptoRandom, clock, iss: DID, cnfJwk: holder.publicJwk, status: { uri: status.uri, idx: status.idx }, claims: DIPLOMA });
    /** A session answered with the credential presented by its holder; the outcome and the session after it. */
    const presentOnce = async () => {
      const r = await verifier.createSession({ scenario: 'ung-tuyen' });
      assert.ok(r.ok);
      const jwt = (await verifier.requestObject(r.session.requestId))!.body;
      const p = JSON.parse(utf8Decode(base64UrlDecode(jwt.split('.')[1]!))) as { nonce: string; state: string; client_metadata: { jwks: { keys: JWK[] } } };
      const presentation = await createPresentation({ compact: credential, disclose: ['ho_ten', 'nganh'], holderSigner: holder, audience: verifier.clientId, nonce: p.nonce, now: clock.now(), hasher: webCryptoHasher });
      const { kty, crv, x, y, kid } = p.client_metadata.jwks.keys[0]!;
      const jwe = await new CompactEncrypt(utf8Encode(JSON.stringify({ vp_token: { credential: [presentation] }, state: p.state })))
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', ...(kid ? { kid } : {}) }).encrypt(await importJWK({ kty, crv, x, y } as JWK, 'ECDH-ES'));
      const handled = await verifier.handleResponse(r.session.requestId, { headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `response=${jwe}` });
      return { outcome: handled!.outcome, session: await verifier.session(r.session.id) };
    };
    return { gateway, verifier, presentOnce, statusService, status };
  }

  test('accepts a DID-issued presentation and reports trustPath did, the issuer DID and no name', async () => {
    const w = await verifierWorld();
    assert.match(w.verifier.clientId, /^x509_hash:/, 'the verifier itself is still identified by X.509');
    const { outcome, session } = await w.presentOnce();
    assert.deepEqual(outcome, { sessionId: session!.id, final: true, ok: true });
    const result = session!.result!;
    assert.equal(session!.status, 'verified');
    assert.deepEqual([result.trustPath, result.issuerDid, 'issuer' in result], ['did', DID, false]);
    assert.deepEqual(result.claims, { ho_ten: DIPLOMA.ho_ten, nganh: DIPLOMA.nganh });
    assert.deepEqual(result.checks.map((c) => c.id), ['structure', 'algorithm', 'did_resolution', 'signature', 'validity_time', 'credential_type', 'issuer_trust', 'status', 'holder_binding', 'query']);
    // Revoked by its issuer: the DID-signed list says so.
    await w.statusService.setStatus('truong-did', 1, w.status.idx, 'revoked');
    const revoked = (await w.presentOnce()).session!.result!;
    assert.deepEqual([revoked.ok, revoked.checks.find((c) => c.id === 'status')?.code, 'issuerDid' in revoked], [false, 'REVOKED', false]);
  });

  test('without dpki a DID-issued presentation is refused (DID_RESOLUTION_FAILED) and never finalises the session', async () => {
    const w = await verifierWorld({ dpki: false });
    const { outcome, session } = await w.presentOnce();
    assert.deepEqual([outcome.final, outcome.code, session!.status], [false, 'DID_RESOLUTION_FAILED', 'request_retrieved']);
    assert.deepEqual(w.gateway.state.calls, [], 'no gateway request');
  });

  test('issuer rejected by the trust registry fails at issuer_trust', async () => {
    const w = await verifierWorld();
    w.gateway.state.recognition = 'rejected';
    const { outcome, session } = await w.presentOnce();
    assert.deepEqual([outcome.final, outcome.ok, outcome.code], [true, false, 'ISSUER_NOT_TRUSTED']);
    const r = session!.result!;
    assert.deepEqual([r.ok, r.checks.find((c) => c.id === 'issuer_trust')?.code, 'trustPath' in r, 'issuerDid' in r, 'claims' in r], [false, 'ISSUER_NOT_TRUSTED', false, false, false]);
    w.gateway.state.recognition = 'recognized';
    w.gateway.state.vcTypes = ['https://identra.awncorp.vn/vct/other/v1'];
    assert.equal((await w.presentOnce()).outcome.code, 'ISSUER_NOT_TRUSTED', 'recognised for another type only');
  });

  test('gateway down: did_resolution DID_RESOLUTION_UNAVAILABLE, never accepted; registry down: TRUST_LIST_UNAVAILABLE, failed', async () => {
    const w = await verifierWorld();
    w.gateway.state.down = true;
    const { outcome, session } = await w.presentOnce();
    assert.deepEqual([outcome.final, outcome.code, session!.status, 'result' in session!], [false, 'DID_RESOLUTION_UNAVAILABLE', 'request_retrieved', false]);
    w.gateway.state.down = false;
    w.gateway.state.tirDown = true;
    const down = await w.presentOnce();
    assert.deepEqual([down.outcome.final, down.outcome.ok, down.outcome.code], [true, false, 'TRUST_LIST_UNAVAILABLE']);
  });
});

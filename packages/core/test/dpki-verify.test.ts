// The DID trust path in the verification policy (ADR-0020 sections 2-6): step 3 `did_resolution`
// with the order and codes of the table of section 4, step 7 on the CertNet trust registry, the
// status of a DID issuer, issuance with a DID signer, and the separation of the two paths.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  base64UrlEncode, createPresentation, createStatusList, createStatusListChecker, createStatusListToken, decodeJws, didJwkResolver, ErrorCodes, issueDiploma,
  issueProductEvent, signJws, utf8Encode, VCT, verifyDidStatusListToken, verifyPresentation, verifyStoredCredential, type CredentialVerificationResult,
} from '@identra/sdk-core';
import { webCryptoHasher, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { NOW, x5c } from './helpers/pki.js';
import { ok, scriptedFetch } from './helpers/lists.js';
import {
  AUD, check, codes, craft, DIPLOMA, fakeStatus, fakeTrust, holderKey, ISS, issuerContext, NONCE, rawJws, STATUS, validator, verifyOptions, visiblePayload,
} from './helpers/sdjwt.js';
import {
  DID, DID_STATUS, didBody, didIssuerContext, didSigner, didStatusToken, didUrl, dpkiWorld, ED25519_JWK, issuerSigner, json, KID, OTHER_DID, tirBody, tirUrl,
} from './helpers/dpki.js';

const holder = await holderKey();
const diploma = (signer = issuerSigner, o: { iss?: string; status?: { idx: number; uri: string } } = {}) =>
  issueDiploma({ ...didIssuerContext(signer), iss: o.iss ?? DID, cnfJwk: holder.publicJwk, status: o.status ?? DID_STATUS, claims: DIPLOMA });
const stored = await diploma();
const didPayload = (patch: Record<string, unknown> = {}) => ({ ...visiblePayload(), iss: DID, status: { status_list: DID_STATUS }, ...patch });
/** A hand-made DID-path credential (no x5c) signed by `signer`, kid `kid`. */
const crafted = (o: { kid?: unknown; payload?: Record<string, unknown>; header?: Record<string, unknown>; signer?: typeof issuerSigner } = {}) =>
  craft({ signer: o.signer ?? issuerSigner, header: { x5c: undefined, kid: 'kid' in o ? o.kid : KID, ...o.header }, payload: o.payload ?? didPayload() });

function expect(r: CredentialVerificationResult, id: string, code: string) {
  assert.equal(r.ok, false);
  assert.equal(check(r, id as never).code, code, JSON.stringify(codes(r)));
  assert.equal(r.credential?.claims, undefined, 'no claims unless everything passed');
}
const GATED_FAIL = (code: string) => [['structure', null], ['algorithm', null], ['did_resolution', code], ['signature', 'SKIPPED'], ['validity_time', 'SKIPPED'], ['credential_type', 'SKIPPED'], ['issuer_trust', 'SKIPPED'], ['status', 'SKIPPED'], ['holder_binding', 'SKIPPED']];

describe('did_resolution: checks before any network call', () => {
  test('kid without a fragment (or with two, or empty) is KEY_NOT_FOUND, no request', async () => {
    for (const kid of [DID, `${DID}#`, `${DID}#a#b`, 'did:#key-1']) {
      const w = await dpkiWorld();
      const r = await verifyStoredCredential(await crafted({ kid }), w.options);
      assert.deepEqual(codes(r), GATED_FAIL(ErrorCodes.KEY_NOT_FOUND).slice(0, -1), kid); // no disclosures: no holder_binding
      assert.equal(w.calls.length, 0);
    }
  });
  test('iss different from the DID in kid is ISSUER_MISMATCH, no request', async () => {
    for (const iss of [ISS, OTHER_DID, `${DID}#key-1`, `${DID} `]) {
      const w = await dpkiWorld();
      expect(await verifyStoredCredential(await crafted({ payload: didPayload({ iss }) }), w.options), 'did_resolution', ErrorCodes.ISSUER_MISMATCH);
      assert.equal(w.calls.length, 0, iss);
    }
  });
  test('a malformed DID and a DID of another network are DID_RESOLUTION_FAILED, no request', async () => {
    for (const did of ['did:certnet:local:a.b', 'did:certnet:testnet:a1b2c3d4e5f67890', 'did:web:example.com', 'did:jwk:eyJrdHkiOiJFQyJ9']) {
      const w = await dpkiWorld();
      expect(await verifyStoredCredential(await crafted({ kid: `${did}#key-1`, payload: didPayload({ iss: did }) }), w.options), 'did_resolution', ErrorCodes.DID_RESOLUTION_FAILED);
      assert.equal(w.calls.length, 0, did);
    }
  });
  test('a DID other than did:certnet is DID_RESOLUTION_FAILED even when the configured resolver knows it and the registry trusts it', async () => {
    const jwkSigner = await didSigner('placeholder');
    const did = `did:jwk:${base64UrlEncode(utf8Encode(JSON.stringify(jwkSigner.publicJwk)))}`;
    const signer = Object.assign(jwkSigner, { kid: `${did}#0` });
    assert.ok((await didJwkResolver.resolve(did)).didDocument, 'the resolver would give the key');
    const compact = await crafted({ kid: signer.kid, signer, payload: didPayload({ iss: did }) });
    let asked = 0;
    const dpki = { resolver: didJwkResolver, trustRegistry: { lookupIssuer: async () => (asked++, { trusted: true as const }) } };
    const r = await verifyStoredCredential(compact, verifyOptions({ dpki, statusChecker: fakeStatus() }));
    assert.deepEqual(codes(r), GATED_FAIL(ErrorCodes.DID_RESOLUTION_FAILED).slice(0, -1));
    assert.equal(asked, 0);
  });
  test('the DID path not configured is DID_RESOLUTION_FAILED', async () => {
    const r = await verifyStoredCredential(stored, verifyOptions());
    assert.deepEqual(codes(r), GATED_FAIL(ErrorCodes.DID_RESOLUTION_FAILED));
    assert.equal(r.credential, undefined);
    await assert.rejects(verifyStoredCredential(stored, verifyOptions({ dpki: { resolver: { resolve: async () => ({}) as never } } as never })), TypeError);
  });
  test('an alg other than ES256 with a DID kid: ALG_NOT_ALLOWED, the skipped list names did_resolution, no request', async () => {
    const w = await dpkiWorld();
    const r = await verifyStoredCredential(await crafted({ header: { alg: 'ES384' } }), w.options);
    assert.deepEqual(codes(r).slice(0, 4), [['structure', null], ['algorithm', 'ALG_NOT_ALLOWED'], ['did_resolution', 'SKIPPED'], ['signature', 'SKIPPED']]);
    assert.equal(r.checks.some((c) => c.id === 'certificate_chain'), false);
    assert.equal(w.calls.length, 0);
  });
  test('both x5c and a DID kid is MALFORMED at structure, and the skipped list names certificate_chain', async () => {
    const w = await dpkiWorld();
    const r = await verifyStoredCredential(await crafted({ header: { x5c: x5c('vc') } }), w.options);
    assert.deepEqual(codes(r).slice(0, 4), [['structure', 'MALFORMED'], ['algorithm', 'SKIPPED'], ['certificate_chain', 'SKIPPED'], ['signature', 'SKIPPED']]);
    assert.equal(r.checks.some((c) => c.id === 'did_resolution'), false);
    assert.equal(w.calls.length, 0);
  });
});

describe('did_resolution: the gateway answer', () => {
  const withDid = async (route: unknown, compact?: string) => {
    const w = await dpkiWorld({ routes: { [didUrl(DID)]: route as never } });
    return verifyStoredCredential(compact ?? stored, w.options);
  };
  test('DID not found (404), refused (422), deactivated (410 or metadata) are DID_RESOLUTION_FAILED', async () => {
    for (const route of [{ status: 404, body: '' }, { status: 422, body: '' }, { status: 410, body: '' }, json(didBody({ metadata: { deactivated: true } }))]) {
      expect(await withDid(route), 'did_resolution', ErrorCodes.DID_RESOLUTION_FAILED);
    }
  });
  test('document.id of another DID, a method controlled by another DID or with a foreign id: DID_RESOLUTION_FAILED', async () => {
    const vm = didBody().document.verificationMethod[0]!;
    for (const body of [
      didBody({ document: { id: OTHER_DID } }),
      didBody({ document: { verificationMethod: [{ ...vm, controller: OTHER_DID }] } }),
      didBody({ document: { verificationMethod: [vm, { ...vm, id: `${OTHER_DID}#key-1` }] } }),
    ]) expect(await withDid(json(body)), 'did_resolution', ErrorCodes.DID_RESOLUTION_FAILED);
  });
  test('a resolver of its own that returns the document together with deactivated metadata: DID_RESOLUTION_FAILED', async () => {
    const w = await dpkiWorld();
    const live = await w.resolver.resolve(DID);
    assert.ok(live.didDocument);
    const resolver = { resolve: async () => ({ ...live, didDocumentMetadata: { deactivated: true } }) };
    expect(await verifyStoredCredential(stored, { ...w.options, dpki: { ...w.options.dpki!, resolver } }), 'did_resolution', ErrorCodes.DID_RESOLUTION_FAILED);
    assert.equal(check(await verifyStoredCredential(stored, { ...w.options, dpki: { ...w.options.dpki!, resolver: { resolve: async () => live } } }), 'did_resolution').ok, true, 'the same document, active');
  });
  test('gateway 503, timeout, oversized, non-JSON: DID_RESOLUTION_UNAVAILABLE', async () => {
    for (const route of [{ status: 503, body: '' }, new Error('timeout after 5000 ms'), ok(JSON.stringify({ ...didBody(), pad: 'a'.repeat(70_000) })), ok('<html>')]) {
      const r = await withDid(route);
      assert.deepEqual(codes(r), GATED_FAIL(ErrorCodes.DID_RESOLUTION_UNAVAILABLE));
    }
  });
  test('key missing, or not in assertionMethod: KEY_NOT_FOUND', async () => {
    expect(await withDid(json(didBody({ kid: `${DID}#key-2` }))), 'did_resolution', ErrorCodes.KEY_NOT_FOUND);
    expect(await withDid(json(didBody({ document: { assertionMethod: [] } }))), 'did_resolution', ErrorCodes.KEY_NOT_FOUND);
    expect(await withDid(json(didBody({ document: { assertionMethod: undefined } }))), 'did_resolution', ErrorCodes.KEY_NOT_FOUND);
  });
  test('an Ed25519 key, a P-256 point off the curve, a private member: ALG_NOT_ALLOWED', async () => {
    const off = { ...issuerSigner.publicJwk, y: issuerSigner.publicJwk.x };
    for (const jwk of [ED25519_JWK, off, { ...issuerSigner.publicJwk, d: issuerSigner.publicJwk.x }, { ...issuerSigner.publicJwk, crv: 'P-384' }]) {
      expect(await withDid(json(didBody({ jwk }))), 'did_resolution', ErrorCodes.ALG_NOT_ALLOWED);
    }
  });
  test('a signature by another key than the DID key: SIGNATURE_INVALID', async () => {
    const r = await withDid(json(didBody()), await crafted({ signer: await didSigner() }));
    assert.equal(check(r, 'did_resolution').ok, true);
    expect(r, 'signature', ErrorCodes.SIGNATURE_INVALID);
  });
});

describe('issuer_trust on the DID path', () => {
  const withTir = async (route: unknown, compact = stored) => {
    const w = await dpkiWorld({ routes: { [tirUrl(DID)]: route as never } });
    return { r: await verifyStoredCredential(compact, w.options), w };
  };
  const at = (s: number) => new Date(NOW.getTime() + s * 1000).toISOString();
  test('rejected, not found, wrong type, before validFrom, after validUntil: ISSUER_NOT_TRUSTED, and no status request', async () => {
    for (const route of [
      json(tirBody({ recognition: 'rejected', reason: 'withdrawn' })), { status: 404, body: '' }, json(tirBody({ vcTypes: ['UniversityDegreeCredential'] })),
      json(tirBody({ validFrom: at(3600) })), json(tirBody({ validUntil: at(-3600) })),
    ]) {
      const { r, w } = await withTir(route);
      expect(r, 'issuer_trust', ErrorCodes.ISSUER_NOT_TRUSTED);
      assert.equal(check(r, 'status').code, ErrorCodes.SKIPPED);
      assert.equal(w.callsTo(DID_STATUS.uri), 0);
    }
  });
  test('an answer about another DID, 503, timeout: TRUST_LIST_UNAVAILABLE', async () => {
    for (const route of [json(tirBody({ issuerDid: OTHER_DID })), { status: 503, body: '' }, new Error('timeout after 5000 ms')]) {
      expect((await withTir(route)).r, 'issuer_trust', ErrorCodes.TRUST_LIST_UNAVAILABLE);
    }
  });
  test('a registry of its own: only trusted === true trusts; a failure other than TrustListUnavailableError is ISSUER_NOT_TRUSTED', async () => {
    const w = await dpkiWorld();
    const withRegistry = (lookupIssuer: () => Promise<unknown>) => verifyStoredCredential(stored, { ...w.options, dpki: { ...w.options.dpki!, trustRegistry: { lookupIssuer } as never } });
    for (const answer of [{ trusted: 'yes' }, { trusted: 1 }, { trusted: {} }, null, undefined, true]) {
      expect(await withRegistry(async () => answer), 'issuer_trust', ErrorCodes.ISSUER_NOT_TRUSTED);
    }
    for (const error of [new Error('boom'), new TypeError('bad'), 'a string']) {
      expect(await withRegistry(async () => Promise.reject(error)), 'issuer_trust', ErrorCodes.ISSUER_NOT_TRUSTED);
    }
    assert.equal((await withRegistry(async () => ({ trusted: true }))).ok, true);
  });
  test('a product event on the DID path is ISSUER_NOT_TRUSTED without asking the registry', async () => {
    const event = { ma_san_pham: '(01)09520123456788(21)A1', cong_doan: 'san_xuat', thoi_diem: '2026-05-30T00:00:00Z', dia_diem: 'HN', mo_ta: 'lô 1' };
    const w = await dpkiWorld({ routes: { [tirUrl(DID, VCT.productEvent)]: json(tirBody({ vcTypes: [VCT.productEvent] })) } });
    const r = await verifyStoredCredential(await crafted({ payload: { ...didPayload({ vct: VCT.productEvent }), ...event } }), w.options);
    expect(r, 'issuer_trust', ErrorCodes.ISSUER_NOT_TRUSTED);
    assert.equal(w.callsTo(tirUrl(DID, VCT.productEvent)), 0);
  });
});

describe('status on the DID path', () => {
  const withStatus = async (route: unknown, compact = stored) => {
    const w = await dpkiWorld({ routes: { [DID_STATUS.uri]: route as never } });
    return verifyStoredCredential(compact, w.options);
  };
  test('revoked, suspended, unavailable', async () => {
    expect(await withStatus(ok(await didStatusToken({ [DID_STATUS.idx]: 1 }))), 'status', ErrorCodes.REVOKED);
    expect(await withStatus(ok(await didStatusToken({ [DID_STATUS.idx]: 2 }))), 'status', ErrorCodes.SUSPENDED);
    expect(await withStatus({ status: 404, body: '' }), 'status', ErrorCodes.STATUS_UNAVAILABLE);
  });
  test('a list signed by another DID, by a key not in assertionMethod, with a wrong sub, with x5c too: STATUS_UNAVAILABLE', async () => {
    const other = await didSigner(`${OTHER_DID}#key-1`);
    const w1 = await dpkiWorld({ routes: { [DID_STATUS.uri]: ok(await didStatusToken({}, { signer: other })), [didUrl(OTHER_DID)]: json(didBody({ did: OTHER_DID, jwk: other.publicJwk })) } });
    expect(await verifyStoredCredential(stored, w1.options), 'status', ErrorCodes.STATUS_UNAVAILABLE);
    assert.equal(w1.callsTo(didUrl(OTHER_DID)), 0, 'the other DID is not even resolved');

    const key2 = await didSigner(`${DID}#key-2`);
    const twoKeys = didBody({ document: { verificationMethod: [...didBody().document.verificationMethod, { id: `${DID}#key-2`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: key2.publicJwk }], authentication: [KID, `${DID}#key-2`] } });
    const w2 = await dpkiWorld({ routes: { [didUrl(DID)]: json(twoKeys), [DID_STATUS.uri]: ok(await didStatusToken({}, { signer: key2 })) } });
    expect(await verifyStoredCredential(stored, w2.options), 'status', ErrorCodes.STATUS_UNAVAILABLE);

    expect(await withStatus(ok(await didStatusToken({}, { uri: `${DID_STATUS.uri}0` }))), 'status', ErrorCodes.STATUS_UNAVAILABLE);

    const list = createStatusList();
    const payload = { sub: DID_STATUS.uri, iat: NOW.getTime() / 1000, exp: NOW.getTime() / 1000 + 3600, ttl: 900, status_list: list.encode() };
    const both = await rawJws({ alg: 'ES256', typ: 'statuslist+jwt', kid: KID, x5c: x5c('status') }, payload, issuerSigner);
    expect(await withStatus(ok(both)), 'status', ErrorCodes.STATUS_UNAVAILABLE);
  });
  test('a status URI outside the DID-path form is STATUS_UNAVAILABLE without asking the checker', async () => {
    for (const uri of [`${DID}/status/1`, 'https://truong-did.example.vn/status/1', `${DID_STATUS.uri}?x=1`, 'https://truong-did.example.vn/a/../status/1']) {
      const status = fakeStatus();
      const w = await dpkiWorld({ status });
      expect(await verifyStoredCredential(await crafted({ payload: didPayload({ status: { status_list: { idx: 7, uri } } }) }), w.options), 'status', ErrorCodes.STATUS_UNAVAILABLE);
      assert.equal(status.calls, 0, uri);
    }
  });
  test('a status URI on an IPv4 literal or a single-label host is STATUS_UNAVAILABLE without asking the checker, and is refused at issuance', async () => {
    for (const uri of ['https://2130706433/s/status/1', 'https://0x7f000001/s/status/1', 'https://169.254.169.254/latest/status/1', 'https://0/s/status/1', 'https://localhost/s/status/1']) {
      const status = fakeStatus();
      const w = await dpkiWorld({ status });
      expect(await verifyStoredCredential(await crafted({ payload: didPayload({ status: { status_list: { idx: 7, uri } } }) }), w.options), 'status', ErrorCodes.STATUS_UNAVAILABLE);
      assert.equal(status.calls, 0, uri);
      await assert.rejects(diploma(issuerSigner, { status: { idx: 1, uri } }), TypeError, uri);
    }
  });
  test('the checker: DID issuers need a didResolver; DID and X.509 lists never share a cache entry', async () => {
    const s = scriptedFetch({ [DID_STATUS.uri]: ok(await didStatusToken()) });
    const base = { fetch: s.fetch, verifier: webCryptoVerifier, chainValidator: validator, trustRegistry: fakeTrust(), clock: { now: () => NOW } };
    assert.equal(await createStatusListChecker(base).check(DID_STATUS, { did: DID }), 'unavailable');
    const w = await dpkiWorld();
    assert.equal(await w.statusChecker.check(DID_STATUS, { maToChuc: 'VATVN-0100000001' }), 'unavailable', 'a DID list is no X.509 list');
    assert.equal(await w.statusChecker.check(DID_STATUS, { did: DID }), 'valid');
    assert.equal(await w.statusChecker.check(DID_STATUS, { maToChuc: 'VATVN-0100000001' }), 'unavailable', 'not served from the DID entry');
    assert.equal(await w.statusChecker.check(DID_STATUS, { did: OTHER_DID }), 'unavailable', 'nor for another DID');
    assert.equal(await w.statusChecker.check(DID_STATUS, { did: DID, maToChuc: 'VATVN-0100000001' } as never), 'unavailable', 'both');
    assert.equal(await w.statusChecker.check(DID_STATUS, { did: 'did:web:example.com' }), 'unavailable');
  });
  test('the checker re-checks the key on every use', async () => {
    const w = await dpkiWorld();
    assert.equal(await w.statusChecker.check(DID_STATUS, { did: DID }), 'valid');
    w.routes[didUrl(DID)] = json(didBody({ document: { assertionMethod: [] } }));
    w.clock.advance(61);
    assert.equal(await w.statusChecker.check(DID_STATUS, { did: DID }), 'unavailable');
    // Another key under the same kid: the held list was signed by a key the DID no longer has.
    const swapped = await dpkiWorld();
    assert.equal(await swapped.statusChecker.check(DID_STATUS, { did: DID }), 'valid');
    swapped.routes[didUrl(DID)] = json(didBody({ jwk: (await didSigner()).publicJwk }));
    swapped.clock.advance(61);
    assert.equal(await swapped.statusChecker.check(DID_STATUS, { did: DID }), 'unavailable');
  });
  test('verifyDidStatusListToken: the failure reasons', async () => {
    const { resolver } = await dpkiWorld({ routes: { [didUrl(OTHER_DID)]: json(didBody({ did: OTHER_DID })) } });
    const o = { uri: DID_STATUS.uri, did: DID, didResolver: resolver, verifier: webCryptoVerifier, now: NOW };
    const reason = async (token: string) => {
      const r = await verifyDidStatusListToken(token, o);
      return r.ok ? 'ok' : r.reason;
    };
    assert.equal(await reason(await didStatusToken()), 'ok');
    assert.equal(await reason(await didStatusToken({}, { signer: await didSigner(`${OTHER_DID}#key-1`) })), 'not_trusted');
    assert.equal(await reason(await didStatusToken({}, { signer: await didSigner(`${DID}#key-2`) })), 'key');
    assert.equal(await reason(await didStatusToken({}, { uri: `${DID_STATUS.uri}0` })), 'claims');
    const payload = { sub: DID_STATUS.uri, iat: NOW.getTime() / 1000, exp: NOW.getTime() / 1000 + 3600, ttl: 900, status_list: createStatusList().encode() };
    for (const kid of [KID, 'key-1']) {
      assert.equal(await reason(await rawJws({ alg: 'ES256', typ: 'statuslist+jwt', kid, x5c: x5c('status') }, payload, issuerSigner)), 'malformed', kid);
    }
  });
});

describe('issuance with a DID signer', () => {
  test('issueDiploma writes kid and no x5c, iss is the DID', async () => {
    const decoded = decodeJws(stored.split('~')[0], 16_384);
    assert.ok(decoded.ok);
    assert.deepEqual(decoded.jws.header, { typ: 'dc+sd-jwt', kid: KID, alg: 'ES256' });
  });
  test('refused: x5c and a DID kid, iss not the DID, a kid not did:certnet, a status URI outside the DID form, a product event', async () => {
    const x509 = (await issuerContext()).signer;
    await assert.rejects(diploma(Object.assign({ ...x509 }, { kid: KID })), TypeError);
    await assert.rejects(diploma(issuerSigner, { iss: OTHER_DID }), TypeError);
    await assert.rejects(diploma(issuerSigner, { iss: 'https://api-identra.awncorp.vn/issuers/truong-mau' }), TypeError);
    for (const kid of ['did:web:example.com#key-1', 'did:certnet:local:a.b#key-1', DID]) {
      const signer = await didSigner(kid);
      await assert.rejects(diploma(signer, { iss: kid.split('#')[0]! }), TypeError, kid);
    }
    for (const uri of [`${DID}/status/1`, `${DID_STATUS.uri}?x=1`, 'https://truong-did.example.vn/status/1']) {
      await assert.rejects(diploma(issuerSigner, { status: { idx: 1, uri } }), TypeError, uri);
    }
    await assert.rejects(issueProductEvent({
      ...didIssuerContext(), iss: DID, status: DID_STATUS,
      claims: { ma_san_pham: '(01)09520123456788(21)A1', cong_doan: 'san_xuat', thoi_diem: '2026-05-30T00:00:00Z', dia_diem: 'HN', mo_ta: 'lô 1' },
    }), /X\.509 trust path only/);
  });
  test('signJws and createStatusListToken: a DID kid goes into the header, never with x5c', async () => {
    const jws = decodeJws(await signJws({ typ: 'x' }, utf8Encode('{}'), issuerSigner), 4096);
    assert.ok(jws.ok);
    assert.deepEqual(jws.jws.header, { alg: 'ES256', typ: 'x', kid: KID });
    const x509 = (await issuerContext()).signer;
    await assert.rejects(signJws({}, utf8Encode('{}'), Object.assign({ ...x509 }, { kid: KID })), TypeError);
    await assert.rejects(signJws({ kid: 'other' }, utf8Encode('{}'), issuerSigner), TypeError);
    const plain = decodeJws(await signJws({}, utf8Encode('{}'), Object.assign({ ...x509 }, { kid: 'not-a-did' })), 4096);
    assert.ok(plain.ok);
    assert.equal(plain.jws.header['kid'], undefined, 'a kid that is not a DID is not written');
    const token = decodeJws(await didStatusToken(), 131_072);
    assert.ok(token.ok);
    assert.deepEqual(token.jws.header, { alg: 'ES256', typ: 'statuslist+jwt', kid: KID });
    for (const signer of [Object.assign({ ...x509 }, { kid: KID }), await didSigner('did:web:example.com#k')]) {
      await assert.rejects(createStatusListToken({ list: createStatusList(), uri: DID_STATUS.uri, signer, now: NOW }), TypeError);
    }
  });
});

describe('end to end on the DID path', () => {
  test('a stored diploma verifies with trustPath did, issuerDid, no fingerprint, no issuer name, claims', async () => {
    const w = await dpkiWorld();
    const r = await verifyStoredCredential(stored, w.options);
    assert.deepEqual(codes(r), [
      ['structure', null], ['algorithm', null], ['did_resolution', null], ['signature', null], ['validity_time', null],
      ['credential_type', null], ['issuer_trust', null], ['status', null], ['holder_binding', null],
    ]);
    assert.equal(r.ok, true);
    assert.deepEqual(r.credential, { trustPath: 'did', vct: VCT.diploma, iss: DID, issuerDid: DID, issuer: null, iat: Math.floor(NOW.getTime() / 1000), status: DID_STATUS, cnfJwk: holder.publicJwk, claims: DIPLOMA });
    assert.equal(r.chainChecks, undefined);
    assert.equal(w.x509Trust.calls, 0, 'the X.509 trust list is never consulted');
    assert.equal(w.callsTo(didUrl(DID)), 1, 'credential and status list share one cached resolution');
    assert.equal(w.callsTo(tirUrl(DID)), 1);
  });
  test('a presentation with a KB-JWT verifies and gives only the disclosed claims', async () => {
    const w = await dpkiWorld();
    const compact = await createPresentation({ compact: stored, disclose: ['ho_ten', 'nganh'], holderSigner: holder, audience: AUD, nonce: NONCE, now: NOW, hasher: webCryptoHasher });
    const r = await verifyPresentation(compact, { ...w.options, presentation: { nonce: NONCE, audience: AUD } });
    assert.equal(r.ok, true, JSON.stringify(codes(r)));
    assert.equal(r.credential?.trustPath, 'did');
    assert.deepEqual(r.credential?.claims, { ho_ten: DIPLOMA.ho_ten, nganh: DIPLOMA.nganh });
    const wrongNonce = await verifyPresentation(compact, { ...w.options, presentation: { nonce: 'other', audience: AUD } });
    expect(wrongNonce, 'holder_binding', ErrorCodes.NONCE_MISMATCH);
  });
  test('a recognition withdrawn between two checks fails the second at issuer_trust', async () => {
    const w = await dpkiWorld();
    assert.equal((await verifyStoredCredential(stored, w.options)).ok, true);
    w.routes[tirUrl(DID)] = json(tirBody({ recognition: 'rejected' }));
    expect(await verifyStoredCredential(stored, w.options), 'issuer_trust', ErrorCodes.ISSUER_NOT_TRUSTED);
  });
});

describe('the two paths stay apart', () => {
  test('X.509 credentials give the same checks and credential with or without the DID path', async () => {
    const x509Diploma = await issueDiploma({ ...(await issuerContext()), iss: ISS, cnfJwk: holder.publicJwk, status: STATUS, claims: DIPLOMA });
    const cases = [
      x509Diploma,
      await craft({ header: { x5c: ['AAAA', 'AAAA'] } }),
      await craft({ header: { x5c: x5c('evil-vc', 'evil-issuing') } }),
      await craft({ header: { x5c: x5c('expired') } }),
      await craft({ header: { x5c: undefined } }),
      await craft({ header: { x5c: undefined, kid: 'key-1' } }),
      await craft({ payload: { ...visiblePayload(), iss: 'https://evil.example/issuers/x' } }),
    ];
    for (const compact of cases) {
      const w = await dpkiWorld();
      const without = await verifyStoredCredential(compact, verifyOptions());
      const withDpki = await verifyStoredCredential(compact, { ...verifyOptions(), dpki: w.options.dpki! });
      assert.deepEqual(withDpki, without);
      assert.equal(w.calls.length, 0, 'the gateway is never asked about an X.509 credential');
      if (without.credential) assert.equal(without.credential.trustPath, 'x509');
    }
    assert.equal((await verifyStoredCredential(x509Diploma, verifyOptions())).ok, true);
  });
  test('a valid X.509 credential cannot be made to pass by adding a DID kid', async () => {
    const w = await dpkiWorld();
    expect(await verifyStoredCredential(await craft({ header: { kid: KID } }), w.options), 'structure', ErrorCodes.MALFORMED);
    expect(await verifyStoredCredential(await craft({ header: { kid: KID }, payload: didPayload() }), w.options), 'structure', ErrorCodes.MALFORMED);
  });
  test('a DID credential cannot borrow an X.509 issuer name: the X.509 trust list is never asked, issuer stays null', async () => {
    const w = await dpkiWorld();
    const r = await verifyStoredCredential(stored, { ...w.options, trustRegistry: fakeTrust() });
    assert.equal(r.ok, true);
    assert.equal(r.credential?.issuer, null);
    assert.equal('fingerprint' in r.credential!, false);
    const asX509Issuer = await verifyStoredCredential(await crafted({ payload: didPayload({ iss: ISS, status: { status_list: STATUS } }) }), w.options);
    expect(asX509Issuer, 'did_resolution', ErrorCodes.ISSUER_MISMATCH);
    assert.equal(asX509Issuer.credential, undefined);
  });
});

// Presentation and step 9 (holder_binding): ADR-0008 sections 4-6.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { base64UrlEncode, createPresentation, decodeCredentialUnverified, ErrorCodes, issueDiploma, type Signer } from '@identra/sdk-core';
import { webCryptoHasher, webCryptoRandom } from '@identra/sdk-core/webcrypto';
import {
  addKb, AUD, check, codes, craft, DIPLOMA, disclosure, holderKey, ISS, issuerContext, NONCE, NOW_S, presentationOptions, STATUS,
  verifyOptions, visiblePayload, verifyAny,
} from './helpers/sdjwt.js';
import { NOW } from './helpers/pki.js';

async function stored(holder?: Signer) {
  holder ??= await holderKey();
  const compact = await issueDiploma({ ...(await issuerContext()), iss: ISS, cnfJwk: holder.publicJwk, status: STATUS, claims: DIPLOMA });
  return { compact, holder };
}
const present = (compact: string, holder: Signer, disclose = ['ho_ten', 'nganh']) =>
  createPresentation({ compact, disclose, holderSigner: holder, audience: AUD, nonce: NONCE, now: NOW, hasher: webCryptoHasher });
const withoutKb = (presentation: string) => presentation.slice(0, presentation.lastIndexOf('~') + 1);
const holderCode = async (compact: string, presentation = true) =>
  check(await verifyAny(compact, presentation ? presentationOptions() : verifyOptions()), 'holder_binding');

describe('presentation round trip', () => {
  test('the verifier sees ho_ten and nganh, not ngay_sinh', async () => {
    const { compact, holder } = await stored();
    const p = await present(compact, holder);
    assert.deepEqual(decodeCredentialUnverified(withoutKb(p)).disclosures.map((d) => d.name).sort(), ['ho_ten', 'nganh']);
    const kb = p.slice(p.lastIndexOf('~') + 1).split('.');
    assert.deepEqual(JSON.parse(Buffer.from(kb[0]!, 'base64url').toString()), { typ: 'kb+jwt', alg: 'ES256' });
    assert.deepEqual(Object.keys(JSON.parse(Buffer.from(kb[1]!, 'base64url').toString())).sort(), ['aud', 'iat', 'nonce', 'sd_hash']);
    const r = await verifyAny(p, presentationOptions());
    assert.equal(r.ok, true, JSON.stringify(codes(r)));
    assert.deepEqual(r.credential?.claims, { ho_ten: DIPLOMA.ho_ten, nganh: DIPLOMA.nganh });
    assert.equal(Object.keys(r.credential?.claims ?? {}).includes('ngay_sinh'), false);
  });
  test('disclosing nothing still proves possession', async () => {
    const { compact, holder } = await stored();
    const r = await verifyAny(await present(compact, holder, []), presentationOptions());
    assert.equal(r.ok, true);
    assert.deepEqual(r.credential?.claims, {});
  });
  test('createPresentation refuses programmer errors', async () => {
    const { compact, holder } = await stored();
    const other = await holderKey();
    await assert.rejects(present(compact, holder, ['email']), TypeError);
    await assert.rejects(present(compact, holder, ['ho_ten', 'ho_ten']), TypeError);
    await assert.rejects(present(compact, other), TypeError, 'not the cnf key');
    await assert.rejects(present(await present(compact, holder), holder), TypeError, 'already has a KB-JWT');
    await assert.rejects(present(await craft({}), holder, []), TypeError, 'no cnf');
  });
});

describe('DISCLOSURE_INVALID, one test per rule', () => {
  const D = ErrorCodes.DISCLOSURE_INVALID;
  test('a disclosure whose digest is not in _sd (stored, and re-bound with a valid KB-JWT)', async () => {
    const { compact, holder } = await stored();
    const forged = `${compact}${disclosure('email', 'a@example.com')}~`;
    for (const c of [await holderCode(forged, false), await holderCode(await addKb(forged, holder))]) {
      assert.equal(c.code, D);
      assert.match(c.detail!, /not referenced/);
    }
  });
  test('the same disclosure twice', async () => {
    const { compact } = await stored();
    const first = compact.split('~')[1]!;
    const c = await holderCode(`${compact}${first}~`, false);
    assert.equal(c.code, D);
    assert.match(c.detail!, /duplicate/);
  });
  test('two disclosures with the same claim name, both referenced', async () => {
    const c = await holderCode(await craft({ disclosures: [disclosure('ho_ten', 'A'), disclosure('ho_ten', 'B')] }), false);
    assert.equal(c.code, D);
    assert.match(c.detail!, /one claim name/);
  });
  test('a disclosure clashing with a visible payload claim', async () => {
    const compact = await craft({ payload: { ...visiblePayload(), nganh: 'plain' }, disclosures: [disclosure('nganh', 'hidden')] });
    const c = await holderCode(compact, false);
    assert.equal(c.code, D);
    assert.match(c.detail!, /clashes/);
  });
  test('reserved names _sd, ... and _sd_alg', async () => {
    for (const name of ['_sd', '...', '_sd_alg']) {
      const c = await holderCode(await craft({ disclosures: [disclosure(name, ['x'])] }), false);
      assert.equal(c.code, D, name);
      assert.match(c.detail!, /reserved/);
    }
  });
  test('every metadata claim delivered by a disclosure, iat included', async () => {
    for (const name of ['iss', 'vct', 'iat', 'nbf', 'exp', 'cnf', 'status']) {
      const c = await holderCode(await craft({ disclosures: [disclosure(name, 1)] }), false);
      assert.equal(c.code, D, name);
      assert.match(c.detail!, /metadata/, name);
    }
  });
  test('array-element and nested disclosures', async () => {
    const element = base64UrlEncode(Buffer.from(JSON.stringify([base64UrlEncode(webCryptoRandom.bytes(16)), 'value'])));
    assert.equal((await holderCode(await craft({ disclosures: [element] }), false)).code, D);
    const inner = disclosure('duong', 'Hai Bà Trưng');
    const nestedValue = disclosure('dia_chi', { _sd: ['x'] });
    assert.match((await holderCode(await craft({ disclosures: [nestedValue] }), false)).detail!, /nested/);
    void inner; // a nested _sd in the payload itself is a step-1 shape rule (sd-jwt-verify.test.ts)
  });
  test('a non-string salt', async () => {
    assert.equal((await holderCode(await craft({ disclosures: [disclosure('ho_ten', 'A', 7 as never)] }), false)).code, D);
  });
});

test('a disclosure named __proto__ stays a data property', async () => {
  const r = await verifyAny(await craft({ disclosures: [disclosure('__proto__', { polluted: true })] }), verifyOptions());
  assert.equal(r.ok, true);
  assert.deepEqual(Object.getOwnPropertyDescriptor(r.credential!.claims!, '__proto__')?.value, { polluted: true });
  assert.equal(Object.getPrototypeOf(r.credential!.claims!), Object.prototype);
});

describe('KB_INVALID, NONCE_MISMATCH, AUD_MISMATCH', () => {
  const K = ErrorCodes.KB_INVALID;
  async function bound() {
    const { compact, holder } = await stored();
    return { sdJwt: withoutKb(await present(compact, holder)), holder, compact };
  }
  test('KB-JWT missing', async () => {
    const { compact } = await stored();
    const c = await holderCode(compact);
    assert.equal(c.code, K);
    assert.match(c.detail!, /missing/);
  });
  test('bad signature, and a signature by another key than cnf', async () => {
    const { sdJwt, holder } = await bound();
    const kb = (await addKb(sdJwt, holder)).slice(sdJwt.length).split('.');
    const c = await holderCode(`${sdJwt}${kb[0]}.${kb[1]}.${base64UrlEncode(webCryptoRandom.bytes(64))}`);
    assert.equal(c.code, K);
    assert.match(c.detail!, /signature/);
    assert.equal((await holderCode(await addKb(sdJwt, await holderKey()))).code, K);
  });
  test('sd_hash no longer matches after a disclosure is added or removed', async () => {
    const { sdJwt, holder, compact } = await bound();
    const p = await addKb(sdJwt, holder);
    const kb = p.slice(sdJwt.length);
    const parts = sdJwt.split('~');
    const removed = `${parts.slice(0, 2).join('~')}~${kb}`;
    const extra = compact.split('~').slice(1, -1).find((d) => !sdJwt.includes(d))!;
    const added = `${sdJwt}${extra}~${kb}`;
    for (const tampered of [removed, added]) {
      const c = await holderCode(tampered);
      assert.equal(c.code, K);
      assert.match(c.detail!, /sd_hash/);
    }
  });
  test('stale or future iat (300 s plus 60 s skew)', async () => {
    const { sdJwt, holder } = await bound();
    const t = Math.floor(NOW_S);
    for (const iat of [t - 361, t + 61, undefined]) assert.equal((await holderCode(await addKb(sdJwt, holder, { payload: { iat } }))).code, K, String(iat));
    for (const iat of [t - 359, t + 59]) assert.equal((await holderCode(await addKb(sdJwt, holder, { payload: { iat } }))).code, null, String(iat));
  });
  test('wrong typ and a disallowed alg', async () => {
    const { sdJwt, holder } = await bound();
    for (const header of [{ typ: 'JWT' }, { typ: undefined }, { alg: 'HS256' }, { alg: 'none' }]) {
      assert.equal((await holderCode(await addKb(sdJwt, holder, { header }))).code, K, JSON.stringify(header));
    }
  });
  test('a credential without a usable cnf.jwk', async () => {
    const holder = await holderKey();
    assert.equal((await holderCode(await addKb(await craft({}), holder))).code, K);
    const badCnf = await craft({ payload: visiblePayload({ ...holder.publicJwk, crv: 'P-384' }) });
    assert.equal((await holderCode(await addKb(badCnf, holder))).code, K);
  });
  test('NONCE_MISMATCH and AUD_MISMATCH, only after the signature verified', async () => {
    const { sdJwt, holder } = await bound();
    assert.equal((await holderCode(await addKb(sdJwt, holder, { payload: { nonce: 'other' } }))).code, ErrorCodes.NONCE_MISMATCH);
    assert.equal((await holderCode(await addKb(sdJwt, holder, { payload: { aud: 'other' } }))).code, ErrorCodes.AUD_MISMATCH);
    assert.equal((await holderCode(await addKb(sdJwt, holder, { payload: { aud: 'other', nonce: 'other' } }))).code, ErrorCodes.NONCE_MISMATCH);
    assert.equal((await holderCode(await addKb(sdJwt, await holderKey(), { payload: { nonce: 'other' } }))).code, K);
  });
});

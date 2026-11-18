// End to end with NO trust or status fakes: a demo-like world from the test PKI serves a real trust
// list token and a real status list token through an in-memory fetch (reached through
// createMappedFetch, as a development deployment does); a diploma is issued, presented and verified
// with the real createSignedTrustListRegistry and createStatusListChecker.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  createMappedFetch, createPresentation, createSignedTrustListRegistry, createStatusList, createStatusListChecker, createStatusListToken,
  issueDiploma, VCT, verifyPresentation, type HttpFetch, type Signer, type StatusList, type TrustListContent,
} from '@identra/sdk-core';
import { webCryptoHasher, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { demoContent, fakeClock, FP, otherOrgStatus, statusSigner, TRUST_URL, trustToken } from './helpers/lists.js';
import { AUD, DIPLOMA, holderKey, ISS, issuerContext, NONCE, validator } from './helpers/sdjwt.js';

const STATUS_URI = `${ISS}/status/1`;
const DEV = 'http://identra.test:4000';

/** The issuer server of the world: an in-memory origin that counts requests per path. */
function server() {
  const bodies = new Map<string, string>();
  const requests: string[] = [];
  const fetch: HttpFetch = async (url) => {
    assert.ok(url.startsWith(`${DEV}/`), `only the development origin is reached: ${url}`);
    const path = url.slice(DEV.length);
    requests.push(path);
    const body = bodies.get(path);
    if (body === undefined) throw new Error('host unreachable');
    return { status: 200, headers: { get: () => null }, text: async () => body };
  };
  const path = (canonical: string) => canonical.slice('https://api-identra.awncorp.vn'.length);
  return {
    fetch: createMappedFetch(fetch, { 'https://api-identra.awncorp.vn': DEV }),
    publish: (canonical: string, body: string | undefined) => (body === undefined ? bodies.delete(path(canonical)) : bodies.set(path(canonical), body)),
    statusFetches: () => requests.filter((p) => p.includes('/status/')).length,
  };
}

async function world(o: { content?: TrustListContent; statusSignerOverride?: Signer } = {}) {
  const clock = fakeClock();
  const srv = server();
  const list: StatusList = createStatusList();
  const signer = o.statusSignerOverride ?? (await statusSigner());
  const publishStatus = async () => srv.publish(STATUS_URI, await createStatusListToken({ list, uri: STATUS_URI, signer, now: clock.now() }));
  srv.publish(TRUST_URL, await trustToken(o.content, clock.now()));
  await publishStatus();
  const common = { fetch: srv.fetch, verifier: webCryptoVerifier, chainValidator: validator, clock };
  const trustRegistry = createSignedTrustListRegistry({ url: TRUST_URL, ...common });
  // The server-side verifier: maxAgeSeconds 0 so that a revocation is seen at once.
  const newChecker = () => createStatusListChecker({ ...common, trustRegistry, maxAgeSeconds: 0 });
  let statusChecker = newChecker();
  const holder = await holderKey();
  const ctx = { ...(await issuerContext()), clock };
  const issue = (idx: number) => issueDiploma({ ...ctx, iss: ISS, cnfJwk: holder.publicJwk, status: { idx, uri: STATUS_URI }, claims: DIPLOMA });
  const verify = async (idx = 42) => {
    const presentation = await createPresentation({ compact: await issue(idx), disclose: ['ho_ten'], holderSigner: holder, audience: AUD, nonce: NONCE, now: clock.now(), hasher: webCryptoHasher });
    return verifyPresentation(presentation, {
      verifier: webCryptoVerifier, hasher: webCryptoHasher, chainValidator: validator, trustRegistry, statusChecker,
      supportedVcts: [VCT.diploma], now: clock.now(), presentation: { nonce: NONCE, audience: AUD },
    });
  };
  const code = (r: Awaited<ReturnType<typeof verify>>, id: string) => r.checks.find((c) => c.id === id)?.code;
  return { clock, srv, list, publishStatus, verify, code, freshChecker: () => void (statusChecker = newChecker()) };
}

describe('status list and trust list, end to end', () => {
  test('ok; then revoke -> REVOKED; suspend -> SUSPENDED', async () => {
    const w = await world();
    const ok = await w.verify();
    assert.equal(ok.ok, true, JSON.stringify(ok.checks));
    assert.deepEqual(ok.credential?.issuer, { maToChuc: 'VATVN-0100000001', ten: 'Trường Mẫu (TEST)' });
    assert.equal(w.srv.statusFetches(), 1);

    w.clock.advance(5);
    w.list.setStatus(42, 1);
    await w.publishStatus();
    const revoked = await w.verify();
    assert.equal(revoked.ok, false);
    assert.equal(w.code(revoked, 'status'), 'REVOKED');

    w.list.setStatus(7, 2);
    await w.publishStatus();
    assert.equal(w.code(await w.verify(7), 'status'), 'SUSPENDED');
    assert.equal(w.code(await w.verify(8), 'status'), null, 'other entries stay valid');
  });

  test("removing the issuer's fingerprint from the trust list -> ISSUER_NOT_TRUSTED, and no status request", async () => {
    const content = await demoContent();
    content.issuers[0]!.chung_thu = content.issuers[0]!.chung_thu.filter((c) => c.sha256 !== FP.vc);
    const w = await world({ content });
    const r = await w.verify();
    assert.equal(w.code(r, 'issuer_trust'), 'ISSUER_NOT_TRUSTED');
    assert.equal(w.code(r, 'status'), 'SKIPPED');
    assert.equal(w.srv.statusFetches(), 0);
  });

  test('a status list signed by another organisation -> STATUS_UNAVAILABLE', async () => {
    const w = await world({ statusSignerOverride: (await otherOrgStatus()).signer });
    const r = await w.verify();
    assert.equal(w.code(r, 'issuer_trust'), null);
    assert.equal(w.code(r, 'status'), 'STATUS_UNAVAILABLE');
  });

  test('trust list expired and unreachable -> TRUST_LIST_UNAVAILABLE', async () => {
    const w = await world();
    assert.equal((await w.verify()).ok, true);
    w.srv.publish(TRUST_URL, undefined);
    w.clock.advance(3600);
    assert.equal((await w.verify()).ok, true, 'the held trust list serves until its exp');
    w.clock.advance(86_400 - 3600 + 60);
    const r = await w.verify();
    assert.equal(w.code(r, 'issuer_trust'), 'TRUST_LIST_UNAVAILABLE');
    assert.equal(w.code(r, 'status'), 'SKIPPED');
  });

  test('status host unreachable with no cached list -> STATUS_UNAVAILABLE', async () => {
    const w = await world();
    w.srv.publish(STATUS_URI, undefined);
    w.freshChecker();
    const r = await w.verify();
    assert.equal(w.code(r, 'issuer_trust'), null);
    assert.equal(w.code(r, 'status'), 'STATUS_UNAVAILABLE');
    assert.equal(w.srv.statusFetches(), 1);
  });
});

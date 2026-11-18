// scripts/pki/make-trust-list-source.mjs on a freshly generated DEMO PKI, and createTrustListService:
// the output passes the core validator, the token verifies, every fingerprint resolves through the
// registry, and the re-signing rules.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { createSignedTrustListRegistry, validateTrustListContent, VCT, verifyTrustListToken, type HttpFetch, type TrustListContent } from '@identra/sdk-core';
import { webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { createFileKeyStore, createTrustListService } from '@identra/sdk-server';
import { fakeClock, freshDemoPki, pemCerts, REPO, trustListSource, validatorFor } from './helpers.js';

const DEMO = freshDemoPki();
const keyStore = createFileKeyStore(DEMO);
const chainValidator = validatorFor(DEMO);
const fp = (path: string) => createHash('sha256').update(pemCerts(join(DEMO, path))[0]!).digest('base64url');

test('the source script: content, fingerprints, organisation ids, validity', () => {
  const before = Date.now();
  const content = trustListSource(DEMO) as TrustListContent;
  assert.equal(validateTrustListContent(content).ok, true);
  assert.deepEqual(content.issuers.map((e) => [e.ma_to_chuc, e.ten, e.vct, e.cong_doan, e.chung_thu.map((c) => c.muc_dich)]), [
    ['VATVN-0100000001', 'Trường Đại học Mẫu (DEMO)', [VCT.diploma], undefined, ['vc', 'status']],
    ['VATVN-0100000002', 'Công ty Sản xuất Mẫu (DEMO)', [VCT.productEvent], ['san_xuat'], ['vc', 'status']],
    ['VATVN-0100000003', 'Trung tâm Kiểm định Mẫu (DEMO)', [VCT.productEvent], ['kiem_dinh'], ['vc', 'status']],
    ['VATVN-0100000004', 'Công ty Phân phối Mẫu (DEMO)', [VCT.productEvent], ['phan_phoi'], ['vc', 'status']],
  ]);
  assert.deepEqual(content.issuers[1]!.chung_thu.map((c) => c.sha256), [fp('orgs/nha-san-xuat/vc-product.cert.pem'), fp('orgs/nha-san-xuat/status.cert.pem')]);
  assert.deepEqual(content.verifiers, [{
    ma_to_chuc: 'VATVN-0100000005', ten: 'Nhà tuyển dụng Mẫu (DEMO)', chung_thu: [{ sha256: fp('orgs/nha-tuyen-dung-mau/request.cert.pem'), muc_dich: 'request' }],
    validFrom: content.verifiers[0]!.validFrom, validUntil: content.verifiers[0]!.validUntil,
  }]);
  // truong-mau: validFrom is the latest notBefore, validUntil the earliest notAfter of its certificates
  // (vc lives 3 years, status 13 months: the earliest notAfter is the status certificate's).
  const date = (file: string, which: 'startdate' | 'enddate') =>
    Date.parse(execFileSync('openssl', ['x509', '-in', join(DEMO, file), '-noout', `-${which}`], { encoding: 'utf8' }).split('=')[1]!);
  const starts = ['orgs/truong-mau/vc.cert.pem', 'orgs/truong-mau/status.cert.pem'].map((f) => date(f, 'startdate'));
  assert.equal(Date.parse(content.issuers[0]!.validFrom), Math.max(...starts));
  assert.equal(Date.parse(content.issuers[0]!.validUntil), date('orgs/truong-mau/status.cert.pem', 'enddate'));
  assert.ok(Date.parse(content.issuers[0]!.validFrom) <= before);
});

test('the source script writes --out and refuses bad arguments', () => {
  const out = join(DEMO, 'trust-list.json');
  execFileSync('node', [join(REPO, 'scripts/pki/make-trust-list-source.mjs'), DEMO, '--out', out]);
  assert.equal(validateTrustListContent(JSON.parse(readFileSync(out, 'utf8'))).ok, true);
  assert.throws(() => execFileSync('node', [join(REPO, 'scripts/pki/make-trust-list-source.mjs')], { stdio: 'pipe' }), /usage/);
  assert.throws(() => execFileSync('node', [join(REPO, 'scripts/pki/make-trust-list-source.mjs'), DEMO, '--outfile', out], { stdio: 'pipe' }), /usage/);
});

test('the service token verifies and every listed fingerprint resolves through the registry', async () => {
  const content = trustListSource(DEMO) as TrustListContent;
  const clock = fakeClock();
  const service = createTrustListService({ source: () => content, keyStore, clock });
  const token = await service.token();
  const r = await verifyTrustListToken(token, { chainValidator, verifier: webCryptoVerifier, now: clock.now() });
  assert.ok(r.ok);
  assert.deepEqual({ issuers: r.payload.issuers, verifiers: r.payload.verifiers }, content);
  const fetch: HttpFetch = async () => ({ status: 200, headers: { get: () => null }, text: async () => token });
  const registry = createSignedTrustListRegistry({ url: 'https://api-identra.awncorp.vn/trust-list', fetch, verifier: webCryptoVerifier, chainValidator, clock });
  for (const e of [...content.issuers, ...content.verifiers]) {
    for (const c of e.chung_thu) {
      const entry = await registry.lookup(c.sha256);
      assert.equal(entry?.maToChuc, e.ma_to_chuc);
      assert.equal(entry?.mucDich, c.muc_dich);
    }
  }
});

const iatOf = (token: string) => JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString()).iat as number;

test('re-signed when the source changes or after one hour, always with a greater iat', async () => {
  const clock = fakeClock();
  let content = trustListSource(DEMO) as TrustListContent;
  const service = createTrustListService({ source: () => content, keyStore, clock });
  const t1 = await service.token();
  assert.equal(await service.token(), t1);
  content = { ...content, verifiers: [] };
  const t2 = await service.token();
  assert.notEqual(t2, t1);
  assert.equal(iatOf(t2), iatOf(t1) + 1, 'same second: iat + 1');
  clock.advance(3599);
  assert.equal(await service.token(), t2);
  clock.advance(1);
  const t3 = await service.token();
  assert.notEqual(t3, t2);
  // A restarted service given its last token continues above it, even with a clock stepped back
  // (up to the 60 s that verifiers accept).
  clock.advance(-30);
  const restarted = createTrustListService({ source: () => content, keyStore, clock, lastToken: t3 });
  assert.equal(iatOf(await restarted.token()), iatOf(t3) + 1);
});

test('an invalid source: the last good token is served unchanged until its exp and onError is told', async () => {
  const clock = fakeClock();
  let content: unknown = trustListSource(DEMO);
  const errors: string[] = [];
  const service = createTrustListService({ source: () => content, keyStore, clock, onError: (reason) => errors.push(reason) });
  const good = await service.token();
  const bad = structuredClone(content) as TrustListContent;
  bad.issuers[0]!.chung_thu[0]!.sha256 = 'not-a-fingerprint';
  content = bad;
  clock.advance(7200);
  assert.equal(await service.token(), good, 'not re-signed');
  // Only the machine reason: no validator detail, nothing of the source.
  assert.deepEqual(errors, ['source_invalid']);
  const throwing = createTrustListService({ source: () => { throw new Error('{"secret": "file content"}'); }, keyStore, clock });
  await assert.rejects(throwing.token(), (e: Error) => e.message === 'trust list source_threw', 'no good token: the call throws, without the source error');
  clock.advance(86_400 - 7200);
  await assert.rejects(service.token(), (e: Error) => e.message === 'trust list source_invalid', 'after exp the good token is no longer served');
});

test('signer_not_before is published by default as the signer certificate notBefore; the option overrides it', async () => {
  const clock = fakeClock();
  const notBefore = Math.floor(Date.parse(execFileSync('openssl', ['x509', '-in', join(DEMO, 'trust-list-signer/trust-list.cert.pem'), '-noout', '-startdate'], { encoding: 'utf8' }).split('=')[1]!) / 1000);
  const byDefault = await verifyTrustListToken(await createTrustListService({ source: () => trustListSource(DEMO), keyStore, clock }).token(), { chainValidator, verifier: webCryptoVerifier, now: clock.now() });
  assert.ok(byDefault.ok);
  assert.equal(byDefault.payload.signer_not_before, notBefore);
  const earlier = await verifyTrustListToken(await createTrustListService({ source: () => trustListSource(DEMO), keyStore, clock, signerNotBefore: notBefore - 86_400 }).token(), { chainValidator, verifier: webCryptoVerifier, now: clock.now() });
  assert.equal(earlier.ok && earlier.payload.signer_not_before, notBefore - 86_400);
  const service = createTrustListService({ source: () => trustListSource(DEMO), keyStore, clock, signerNotBefore: notBefore });
  const r = await verifyTrustListToken(await service.token(), { chainValidator, verifier: webCryptoVerifier, now: clock.now(), minSignerNotBefore: notBefore });
  assert.ok(r.ok);
  assert.equal(r.payload.signer_not_before, notBefore);
  await assert.rejects(createTrustListService({ source: () => trustListSource(DEMO), keyStore, clock, signerNotBefore: notBefore + 1 }).token(), /signerNotBefore must be/);
});

test('onError reports source_threw while the last good token is served', async () => {
  const clock = fakeClock();
  let fail = false;
  const reasons: string[] = [];
  const service = createTrustListService({ source: () => { if (fail) throw new Error('EACCES /etc/identra/trust.json'); return trustListSource(DEMO); }, keyStore, clock, onError: (r) => reasons.push(r) });
  const good = await service.token();
  fail = true;
  clock.advance(7200);
  assert.equal(await service.token(), good);
  assert.deepEqual(reasons, ['source_threw']);
});

test('current() describes the held token for monitoring', async () => {
  const clock = fakeClock();
  const content = trustListSource(DEMO) as TrustListContent;
  const service = createTrustListService({ source: () => content, keyStore, clock });
  assert.equal(service.current(), null);
  const token = await service.token();
  const notAfter = Math.floor(Date.parse(execFileSync('openssl', ['x509', '-in', join(DEMO, 'trust-list-signer/trust-list.cert.pem'), '-noout', '-enddate'], { encoding: 'utf8' }).split('=')[1]!) / 1000);
  assert.deepEqual(service.current(), { iat: iatOf(token), exp: iatOf(token) + 86_400, issuers: content.issuers.length, verifiers: content.verifiers.length, signerNotAfter: notAfter });
});

test('lastIatStore keeps iat strictly increasing across a restart; a failing store fails the call', async () => {
  const clock = fakeClock(new Date(Date.now() + 600_000));
  const content = trustListSource(DEMO);
  let saved: number | null = null;
  const store = { get: async () => saved, set: async (iat: number) => void (saved = iat) };
  const first = await createTrustListService({ source: () => content, keyStore, clock, lastIatStore: store }).token();
  assert.equal(saved, iatOf(first));
  clock.advance(-30); // restart with a clock that stepped back
  const second = await createTrustListService({ source: () => content, keyStore, clock, lastIatStore: store }).token();
  assert.equal(iatOf(second), iatOf(first) + 1);
  assert.equal(saved, iatOf(second));
  const broken = { get: async () => null, set: async () => { throw new Error('db down'); } };
  await assert.rejects(createTrustListService({ source: () => content, keyStore, clock, lastIatStore: broken }).token(), /db down/);
  await assert.rejects(createTrustListService({ source: () => content, keyStore, clock, lastIatStore: { get: async () => 1.5, set: async () => {} } }).token(), TypeError);
});

const certTime = (field: 'startdate' | 'enddate') =>
  Math.floor(Date.parse(execFileSync('openssl', ['x509', '-in', join(DEMO, 'trust-list-signer/trust-list.cert.pem'), '-noout', `-${field}`], { encoding: 'utf8' }).split('=')[1]!) / 1000);

test('rapid source rewrites never push iat more than 5 s ahead; the last content is served soon after', async () => {
  const clock = fakeClock(new Date(Date.now() + 600_000));
  const base = trustListSource(DEMO) as TrustListContent;
  let content: TrustListContent = base;
  const service = createTrustListService({ source: () => content, keyStore, clock });
  for (let i = 0; i < 200; i++) {
    content = { ...base, issuers: base.issuers.map((e, j) => (j === 0 ? { ...e, ten: `Rewrite ${i}` } : e)) };
    const token = await service.token();
    const nowS = Math.floor(clock.now().getTime() / 1000);
    assert.ok(iatOf(token) <= nowS + 5, `rewrite ${i}: iat ${iatOf(token) - nowS} s ahead`);
    const r = await verifyTrustListToken(token, { chainValidator, verifier: webCryptoVerifier, now: clock.now() });
    assert.ok(r.ok, `rewrite ${i}`);
    clock.advance(0.035);
  }
  let seconds = 0;
  for (;;) {
    const r = await verifyTrustListToken(await service.token(), { chainValidator, verifier: webCryptoVerifier, now: clock.now() });
    if (r.ok && r.payload.issuers[0]!.ten === 'Rewrite 199') break;
    assert.ok(++seconds <= 6, 'served within 6 s after the burst');
    clock.advance(1);
  }
});

test('a remembered iat more than 60 s ahead is ignored and reported', async () => {
  const clock = fakeClock(new Date(Date.now() + 600_000));
  const nowS = Math.floor(clock.now().getTime() / 1000);
  const reasons: string[] = [];
  const service = createTrustListService({ source: () => trustListSource(DEMO), keyStore, clock, onError: (r) => reasons.push(r), lastIatStore: { get: async () => nowS + 977, set: async () => {} } });
  assert.equal(iatOf(await service.token()), nowS);
  assert.deepEqual(reasons, ['last_iat_in_future']);
});

test('an expired signer certificate signs nothing: the held token is served until its exp, then the call fails', async () => {
  const notAfter = certTime('enddate');
  const clock = fakeClock(new Date((notAfter - 3600) * 1000));
  let content = trustListSource(DEMO) as TrustListContent;
  const reasons: string[] = [];
  const service = createTrustListService({ source: () => content, keyStore, clock, onError: (r) => reasons.push(r) });
  const held = await service.token();
  assert.equal(service.current()?.signerNotAfter, notAfter);
  clock.advance(7200);
  content = { ...content, verifiers: [] };
  assert.equal(await service.token(), held, 'not replaced by a token that would not verify');
  assert.deepEqual(reasons, ['signer_expired']);
  clock.advance(86_400);
  await assert.rejects(service.token(), /trust list signer_expired/);
  const early = createTrustListService({ source: () => content, keyStore, clock: fakeClock(new Date((certTime('startdate') - 10) * 1000)) });
  await assert.rejects(early.token(), /trust list signer_expired/, 'not yet valid either');
});

// Certificate chain validation, steps 1-3 of docs/architecture.md section 4, on both crypto backends.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, test } from 'node:test';
import { createCertificateChainValidator, ErrorCodes, parseCertificate, type Hasher, type Verifier } from '@identra/sdk-core';
import { webCryptoHasher, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { nobleHasher, nobleVerifier } from './helpers/noble.js';
import { b64, ca, leaf, NOW, x5c } from './helpers/pki.js';

const ISS = 'https://api-identra.awncorp.vn/issuers';
const BACKENDS: [string, Verifier, Hasher][] = [
  ['webcrypto', webCryptoVerifier, webCryptoHasher],
  ['noble', nobleVerifier, nobleHasher],
];
const at = (iso: string, deltaSeconds = 0) => new Date(new Date(iso).getTime() + deltaSeconds * 1000);

for (const [backend, verifier, hasher] of BACKENDS) {
  const pin = (...roots: string[]) => createCertificateChainValidator({ trustedRoots: roots.map(ca), verifier, hasher });
  const validator = pin('root');
  const code = async (chain: unknown, now = NOW, v = validator) =>
    (await v.validate({ x5c: chain as string[], profile: 'vc', now })).code;

  describe(`chain validation (${backend})`, () => {
    test('a good vc chain passes every step and returns the leaf and its fingerprint', async () => {
      const r = await validator.validate({ x5c: x5c('vc'), profile: 'vc', now: NOW, expectedIssuerUri: `${ISS}/truong-mau` });
      assert.equal(r.ok, true);
      assert.equal(r.code, null);
      assert.deepEqual(
        r.checks.map((c) => [c.id, c.ok, c.code]),
        ['chain_format', 'chain_signatures', 'chain_validity', 'chain_constraints', 'leaf_key', 'issuer_uri'].map((id) => [id, true, null]),
      );
      assert.equal(r.fingerprint, createHash('sha256').update(leaf('vc')).digest('base64url'));
      assert.equal(r.leaf?.subject.organizationIdentifier, 'VATVN-0100000001');
    });

    test('good chains for every purpose and a Vietnamese subject pass', async () => {
      for (const name of ['vc-product', 'status', 'request', 'utf8']) {
        const profile = name === 'status' || name === 'request' ? name : 'vc';
        const r = await validator.validate({ x5c: x5c(name), profile, now: NOW });
        assert.equal(r.ok, true, name);
      }
      const r = await validator.validate({ x5c: x5c('utf8'), profile: 'vc', now: NOW });
      assert.equal(r.leaf?.subject.O, 'Trường Mẫu TEST');
    });

    test('a failed step lists every later step as SKIPPED', async () => {
      const r = await validator.validate({ x5c: x5c('evil-vc', 'evil-issuing'), profile: 'vc', now: NOW, expectedIssuerUri: `${ISS}/truong-mau` });
      assert.deepEqual(
        r.checks.map((c) => [c.id, c.code, c.skipped ?? false]),
        [
          ['chain_format', null, false],
          ['chain_signatures', 'CERT_CHAIN_UNTRUSTED', false],
          ['chain_validity', 'SKIPPED', true],
          ['chain_constraints', 'SKIPPED', true],
          ['leaf_key', 'SKIPPED', true],
          ['issuer_uri', 'SKIPPED', true],
        ],
      );
      assert.equal(r.ok, false);
      assert.equal(r.leaf, undefined);
      assert.equal(r.fingerprint, undefined);
    });

    describe('CERT_CHAIN_MALFORMED', () => {
      const M = ErrorCodes.CERT_CHAIN_MALFORMED;
      test('wrong number of certificates', async () => {
        assert.equal(await code([b64(leaf('vc'))]), M);
        assert.equal(await code([...x5c('vc'), b64(ca('root'))]), M);
        assert.equal(await code([]), M);
        assert.equal(await code('not an array'), M);
      });
      test('the pinned root inside x5c', async () => {
        assert.equal(await code([b64(leaf('vc')), b64(ca('root'))]), M);
      });
      test('a self-signed certificate that is not pinned', async () => {
        assert.equal(await code([b64(leaf('vc')), b64(ca('evil-root'))]), M);
      });
      test('entries that are not strict base64 of a DER certificate', async () => {
        const good = b64(ca('issuing'));
        const vc = b64(leaf('vc'));
        // empty, not base64, truncated, embedded newline, base64url alphabet, base64 of 3 zero bytes, not a string
        for (const bad of ['', '!!!!', vc.slice(0, -1), `${vc.slice(0, 40)}\n${vc.slice(40)}`, `_${vc.slice(1)}`, 'AAAA', 42]) {
          assert.equal(await code([bad, good]), M, String(bad).slice(0, 20));
        }
      });
      test('a certificate larger than 4 KB', async () => {
        const big = leaf('big');
        assert.ok(big.length > 4096 && parseCertificate(big).subject.CN, 'fixture is a parseable certificate over 4 KB');
        assert.equal(await code([b64(big), b64(ca('issuing'))]), M);
        assert.equal(await code(['A'.repeat(100_000), b64(ca('issuing'))]), M);
      });
      test('a trailing byte after the certificate', async () => {
        const der = leaf('vc');
        const withTrailer = new Uint8Array(der.length + 1);
        withTrailer.set(der);
        assert.equal(await code([b64(withTrailer), b64(ca('issuing'))]), M);
      });
    });

    describe('CERT_CHAIN_UNTRUSTED', () => {
      const U = ErrorCodes.CERT_CHAIN_UNTRUSTED;
      test('an impostor PKI with byte-identical names', async () => {
        assert.deepEqual(parseCertificate(ca('evil-issuing')).subjectName, parseCertificate(ca('issuing')).subjectName);
        assert.equal(await code(x5c('evil-vc', 'evil-issuing')), U);
        assert.equal(await code(x5c('evil-vc', 'issuing')), U);
      });
      test('a chain under a root that is not pinned', async () => {
        assert.equal(await code(x5c('vc'), NOW, pin('evil-root')), U); // same name, other key
        assert.equal(await code(x5c('vc'), NOW, pin('root2')), U); // other name
      });
      test('one byte of the signed TBS changed', async () => {
        const der = leaf('vc').slice();
        const at = Buffer.from(der).indexOf('Truong Mau TEST (vc)');
        assert.ok(at > 0);
        der[at] = 'X'.charCodeAt(0);
        parseCertificate(der); // still a well-formed certificate
        assert.equal(await code([b64(der), b64(ca('issuing'))]), U);
      });
      test('issuer and subject names that do not chain', async () => {
        assert.equal(await code([b64(leaf('vc')), b64(ca('issuing-under-root2'))]), U);
      });
      test('signatures that are not ECDSA P-256 / SHA-256', async () => {
        assert.equal(await code(x5c('sha384')), U);
        assert.equal(await code(x5c('under-issuing-p384', 'issuing-p384')), U);
      });
    });

    describe('CERT_NOT_YET_VALID and CERT_EXPIRED, with 60 s of clock skew', () => {
      test('a leaf that is not yet valid (notBefore 2026-12-01)', async () => {
        assert.equal(await code(x5c('not-yet-valid')), ErrorCodes.CERT_NOT_YET_VALID);
        assert.equal(await code(x5c('not-yet-valid'), at('2026-12-01T00:00:00Z', -61)), ErrorCodes.CERT_NOT_YET_VALID);
        assert.equal(await code(x5c('not-yet-valid'), at('2026-12-01T00:00:00Z', -59)), null);
      });
      test('an expired leaf (notAfter 2026-03-01)', async () => {
        assert.equal(await code(x5c('expired')), ErrorCodes.CERT_EXPIRED);
        assert.equal(await code(x5c('expired'), at('2026-03-01T00:00:00Z', 61)), ErrorCodes.CERT_EXPIRED);
        assert.equal(await code(x5c('expired'), at('2026-03-01T00:00:00Z', 59)), null);
      });
      test('an expired issuing CA', async () => {
        const r = await validator.validate({ x5c: x5c('under-issuing-expired', 'issuing-expired'), profile: 'vc', now: NOW });
        assert.equal(r.code, ErrorCodes.CERT_EXPIRED);
        assert.match(r.checks[2]!.detail!, /issuing CA/);
      });
      test('an expired pinned root', async () => {
        const v = pin('root-expired');
        const r = await v.validate({ x5c: x5c('under-root-expired', 'issuing-under-root-expired'), profile: 'vc', now: NOW });
        assert.equal(r.code, ErrorCodes.CERT_EXPIRED);
        assert.match(r.checks[2]!.detail!, /root/);
        assert.equal(await code(x5c('under-root-expired', 'issuing-under-root-expired'), at('2026-03-01T00:00:00Z', 59), v), null);
      });
    });
  });
}

test('programmer errors throw', async () => {
  const v = createCertificateChainValidator({ trustedRoots: [ca('root')], verifier: webCryptoVerifier, hasher: webCryptoHasher });
  await assert.rejects(v.validate({ x5c: x5c('vc'), profile: 'nope' as 'vc', now: NOW }), TypeError);
  await assert.rejects(v.validate({ x5c: x5c('vc'), profile: 'vc', now: new Date('x') }), TypeError);
  await assert.rejects(v.validate({ x5c: x5c('status'), profile: 'status', now: NOW, expectedIssuerUri: `${ISS}/truong-mau` }), TypeError);
  assert.throws(() => createCertificateChainValidator({ trustedRoots: [], verifier: webCryptoVerifier, hasher: webCryptoHasher }), TypeError);
  const three = [ca('root'), ca('root2'), ca('evil-root')];
  assert.throws(() => createCertificateChainValidator({ trustedRoots: three, verifier: webCryptoVerifier, hasher: webCryptoHasher }), TypeError);
});

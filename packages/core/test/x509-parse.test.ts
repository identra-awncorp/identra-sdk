// parseCertificate, checked against node:crypto's X509Certificate (OpenSSL) as an independent oracle.
import assert from 'node:assert/strict';
import { verify, X509Certificate } from 'node:crypto';
import { readdirSync } from 'node:fs';
import { test } from 'node:test';
import { parseCertificate } from '@identra/sdk-core';
import { ca, leaf, REPO } from './helpers/pki.js';

const names = (dir: string) => readdirSync(new URL(`.pki/test/${dir}`, REPO));
const all: [string, Uint8Array][] = [
  ...names('ca').map((n): [string, Uint8Array] => [`ca/${n}`, ca(n)]),
  ...names('leaf').filter((f) => f.endsWith('.cert.pem')).map((f): [string, Uint8Array] => [f, leaf(f.slice(0, -9))]),
];

// Second TLV of the certificate, sliced straight out of the DER.
function tbsSlice(d: Uint8Array): Uint8Array {
  const header = (p: number) => (d[p + 1]! < 0x80 ? 2 : 2 + (d[p + 1]! & 0x7f));
  const length = (p: number) => {
    const l = d[p + 1]!;
    if (l < 0x80) return l;
    let v = 0;
    for (let i = 0; i < (l & 0x7f); i++) v = v * 256 + d[p + 2 + i]!;
    return v;
  };
  const start = header(0);
  return d.slice(start, start + header(start) + length(start));
}

test('every test PKI certificate parses; dates, keys and tbs match OpenSSL', () => {
  assert.equal(all.length, 48);
  for (const [name, der] of all) {
    const c = parseCertificate(der);
    const o = new X509Certificate(der);
    assert.deepEqual(c.tbs, tbsSlice(der), `${name} tbs`);
    assert.equal(c.notBefore.getTime(), new Date(o.validFrom).getTime(), `${name} notBefore`);
    assert.equal(c.notAfter.getTime(), new Date(o.validTo).getTime(), `${name} notAfter`);
    if (c.publicJwk) {
      const jwk = o.publicKey.export({ format: 'jwk' });
      assert.deepEqual([jwk.crv, c.publicJwk.x, c.publicJwk.y], ['P-256', jwk.x, jwk.y], `${name} jwk`);
    } else {
      assert.notEqual(o.publicKey.asymmetricKeyDetails?.namedCurve, 'prime256v1', `${name} P-256 key not recognised`);
    }
  }
});

test('the parsed signature is r||s over tbs, verified by OpenSSL with the issuer key', () => {
  for (const [name, issuer] of [['vc', 'issuing'], ['status', 'issuing'], ['under-root2', 'issuing-under-root2']] as const) {
    const c = parseCertificate(leaf(name));
    const issuerKey = new X509Certificate(ca(issuer)).publicKey;
    assert.ok(verify('sha256', c.tbs, { key: issuerKey, dsaEncoding: 'ieee-p1363' }, c.signature!), name);
  }
});

test('vc leaf fields', () => {
  const c = parseCertificate(leaf('vc'));
  assert.deepEqual(c.subject, { C: 'VN', O: 'Truong Mau TEST', organizationIdentifier: 'VATVN-0100000001', CN: 'Truong Mau TEST (vc)' });
  assert.deepEqual(c.sanUris, ['https://api-identra.awncorp.vn/issuers/truong-mau']);
  assert.deepEqual(c.basicConstraints, { cA: false });
  assert.deepEqual(c.keyUsage, { digitalSignature: true, keyCertSign: false, cRLSign: false });
  assert.deepEqual(c.criticalExtensions, ['2.5.29.19', '2.5.29.15']);
  assert.equal(c.signatureAlgorithm, '1.2.840.10045.4.3.2');
  assert.equal(c.publicKeyAlgorithm, '1.2.840.10045.2.1');
  assert.equal(c.publicKeyCurve, '1.2.840.10045.3.1.7');
  assert.deepEqual(c.issuerName, parseCertificate(ca('issuing')).subjectName);
});

test('CA profiles, foreign keys and a Vietnamese subject', () => {
  assert.deepEqual(parseCertificate(ca('root')).basicConstraints, { cA: true });
  assert.deepEqual(parseCertificate(ca('root')).keyUsage, { digitalSignature: false, keyCertSign: true, cRLSign: true });
  assert.deepEqual(parseCertificate(ca('issuing')).basicConstraints, { cA: true, pathLenConstraint: 0 });
  assert.equal(parseCertificate(leaf('rsa')).publicKeyAlgorithm, '1.2.840.113549.1.1.1');
  assert.equal(parseCertificate(leaf('rsa')).publicJwk, undefined);
  assert.equal(parseCertificate(leaf('p384')).publicKeyCurve, '1.3.132.0.34');
  assert.equal(parseCertificate(leaf('p384')).publicJwk, undefined);
  assert.equal(parseCertificate(leaf('sha384')).signatureAlgorithm, '1.2.840.10045.4.3.3');
  assert.equal(parseCertificate(leaf('sha384')).signature, undefined);
  assert.equal(parseCertificate(leaf('utf8')).subject.O, 'Trường Mẫu TEST');
});

test('GeneralizedTime: the root notAfter (2050) is encoded and parsed as GeneralizedTime', () => {
  const der = ca('root');
  const at = Buffer.from(der).indexOf('20500101000000Z');
  assert.deepEqual([der[at - 2], der[at - 1]], [0x18, 15], 'tag 0x18 = GeneralizedTime');
  assert.equal(parseCertificate(der).notAfter.toISOString(), '2050-01-01T00:00:00.000Z');
  const issuing = ca('issuing');
  assert.equal(issuing[Buffer.from(issuing).indexOf('400101000000Z') - 2], 0x17, 'issuing CA notAfter 2040 is a UTCTime');
  assert.equal(parseCertificate(issuing).notAfter.toISOString(), '2040-01-01T00:00:00.000Z');
});

test('only strict DER is accepted', () => {
  const der = leaf('vc');
  assert.equal(der[0], 0x30);
  assert.equal(der[1], 0x82);
  // Same certificate with the outer length in a non-minimal 3-byte form (valid BER, not DER).
  const ber = new Uint8Array(der.length + 1);
  ber.set([0x30, 0x83, 0x00, der[2]!, der[3]!]);
  ber.set(der.subarray(4), 5);
  const withTrailer = new Uint8Array(der.length + 1);
  withTrailer.set(der);
  for (const [name, bad] of [
    ['BER length', ber],
    ['trailing byte', withTrailer],
    ['truncated', der.subarray(0, der.length - 1)],
    ['empty', new Uint8Array(0)],
    ['garbage', new Uint8Array(100).fill(0x30)],
  ] as const) {
    assert.throws(() => parseCertificate(bad), TypeError, name);
  }
});

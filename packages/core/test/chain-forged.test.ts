// Chain validation and parsing against forged certificates (exact keyUsage, leaf subject,
// on-curve keys, parse strictness, time edges) and the gaps of the GĐ1 mutation review.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, test } from 'node:test';
import { createCertificateChainValidator, ErrorCodes, parseCertificate, type CertificateProfile } from '@identra/sdk-core';
import { webCryptoHasher, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { caKey, forge, keyUsageRest, leafKey, withExtension, withoutExtension, extRest, type Tbs } from './helpers/forge.js';
import { b64, ca, leaf, NOW, x5c } from './helpers/pki.js';

const ISS = 'https://api-identra.awncorp.vn/issuers/truong-mau';
const pin = (...roots: Uint8Array[]) => createCertificateChainValidator({ trustedRoots: roots, verifier: webCryptoVerifier, hasher: webCryptoHasher });
const validator = pin(ca('root'));
async function result(chain: Uint8Array[], profile: CertificateProfile = 'vc', v = validator, now = NOW) {
  const x = chain.map(b64);
  return v.validate(profile === 'vc' ? { x5c: x, profile, now, expectedIssuerUri: ISS } : { x5c: x, profile, now });
}
async function expectCode(chain: Uint8Array[], code: string, detail?: RegExp, profile: CertificateProfile = 'vc', v = validator, now = NOW) {
  const r = await result(chain, profile, v, now);
  assert.equal(r.code, code, JSON.stringify(r.checks));
  if (detail) assert.match(r.checks.find((c) => !c.ok)!.detail!, detail);
}
const reLeaf = (edit: (t: Tbs) => void) => forge(leaf('vc'), edit, caKey('issuing'));
const issuing = ca('issuing');

describe('exact keyUsage (ADR-0015 section 15)', () => {
  // DER BIT STRINGs: [0x03, length, unused bits, bytes...]
  const bits = {
    digitalSignatureNonRepudiation: [0x03, 0x02, 0x06, 0xc0],
    digitalSignatureKeyCertSign: [0x03, 0x02, 0x02, 0x84],
    digitalSignatureDecipherOnly: [0x03, 0x03, 0x07, 0x80, 0x80],
    keyCertSignOnly: [0x03, 0x02, 0x02, 0x04],
    keyCertSignCrlSignDigitalSignature: [0x03, 0x02, 0x01, 0x86],
    keyCertSignCrlSignDecipherOnly: [0x03, 0x03, 0x07, 0x06, 0x80],
  };
  test('leaf: exactly digitalSignature', async () => {
    for (const ku of [bits.digitalSignatureNonRepudiation, bits.digitalSignatureKeyCertSign, bits.digitalSignatureDecipherOnly]) {
      await expectCode([reLeaf((t) => withExtension(t, 'keyUsage', keyUsageRest(ku))), issuing], ErrorCodes.CERT_CONSTRAINT_INVALID, /leaf keyUsage/);
    }
    await expectCode([reLeaf((t) => withoutExtension(t, 'keyUsage')), issuing], ErrorCodes.CERT_CONSTRAINT_INVALID, /leaf keyUsage/);
    assert.equal(parseCertificate(reLeaf((t) => withExtension(t, 'keyUsage', keyUsageRest(bits.digitalSignatureDecipherOnly)))).keyUsage?.decipherOnly, true, 'bit 8 lives in the second byte');
  });
  test('issuing CA and root: exactly keyCertSign and cRLSign', async () => {
    const leafOf = (ca: Uint8Array) => [reLeaf(() => undefined), ca];
    for (const ku of [bits.keyCertSignOnly, bits.keyCertSignCrlSignDigitalSignature, bits.keyCertSignCrlSignDecipherOnly]) {
      const badIssuing = forge(issuing, (t) => withExtension(t, 'keyUsage', keyUsageRest(ku)), caKey('root'));
      await expectCode(leafOf(badIssuing), ErrorCodes.CERT_CONSTRAINT_INVALID, /issuing CA keyUsage/);
      const badRoot = forge(ca('root'), (t) => withExtension(t, 'keyUsage', keyUsageRest(ku)), caKey('root'));
      await expectCode(x5c('vc').map((s) => Buffer.from(s, 'base64')), ErrorCodes.CERT_CONSTRAINT_INVALID, /root keyUsage/, 'vc', pin(badRoot));
    }
  });
});

describe('leaf subject per ADR-0015 section 9, for every profile', () => {
  const subject = (edit: (rdns: Tbs['subject']['rdns']) => void) => (t: Tbs) => edit(t.subject.rdns);
  const cases: [string, (rdns: Tbs['subject']['rdns']) => void][] = [
    ['C=US', (r) => void (r[0]![0]!.value = { TAG: 'printable', data: 'US' })],
    ['organizationIdentifier not VATVN', (r) => void (r[2]![0]!.value = { TAG: 'utf8', data: 'NTRVN-0100000001' })],
    ['tax code too short', (r) => void (r[2]![0]!.value = { TAG: 'utf8', data: 'VATVN-123' })],
    ['branch suffix malformed', (r) => void (r[2]![0]!.value = { TAG: 'utf8', data: 'VATVN-0100000001-1' })],
    ['empty O', (r) => void (r[1]![0]!.value = { TAG: 'utf8', data: '' })],
  ];
  test('vc leaves', async () => {
    for (const [name, edit] of cases) await expectCode([reLeaf(subject(edit)), issuing], ErrorCodes.CERT_CONSTRAINT_INVALID, /leaf subject/).catch((e) => assert.fail(`${name}: ${e.message}`));
    assert.equal((await result([reLeaf(subject((r) => void (r[2]![0]!.value = { TAG: 'utf8', data: 'VATVN-0100000001-001' }))), issuing])).ok, true, 'branch suffix -NNN');
  });
  test('the trust-list signer', async () => {
    const ts = forge(leaf('trust-list'), subject((r) => void (r[0]![0]!.value = { TAG: 'printable', data: 'US' })), caKey('root'));
    await expectCode([ts], ErrorCodes.CERT_CONSTRAINT_INVALID, /leaf subject/, 'trust-list');
  });
});

describe('P-256 keys must lie on the curve (F3)', () => {
  const withKey = (point: number[]) => (t: Tbs) => void (t.spki.publicKey = Uint8Array.from(point));
  test('an off-curve or all-zero leaf key is CERT_KEY_NOT_ALLOWED', async () => {
    for (const point of [[4, ...Array(32).fill(1), ...Array(32).fill(2)], [4, ...Array(64).fill(0)]]) {
      const forged = reLeaf(withKey(point));
      assert.equal(parseCertificate(forged).publicJwk, undefined);
      await expectCode([forged, issuing], ErrorCodes.CERT_KEY_NOT_ALLOWED);
    }
  });
  test('an issuing CA with an off-curve key cannot verify anything', async () => {
    const badIssuing = forge(issuing, withKey([4, ...Array(32).fill(1), ...Array(32).fill(2)]), caKey('root'));
    await expectCode([reLeaf(() => undefined), badIssuing], ErrorCodes.CERT_CHAIN_UNTRUSTED);
  });
});

describe('gaps of the GĐ1 mutation review', () => {
  test('the same key but a different issuer name does not chain', async () => {
    const renamed = reLeaf((t) => void (t.issuer.rdns[2]![0]!.value = { TAG: 'utf8', data: 'Identra TEST Issuing CA 2' }));
    await expectCode([renamed, issuing], ErrorCodes.CERT_CHAIN_UNTRUSTED, /issuer name/);
  });
  test('a pinned certificate inside x5c is MALFORMED even when it is not self-issued', async () => {
    // Pinning the issuing CA itself: without the pinned-root rule the chain would only fail later.
    await expectCode([leaf('vc'), issuing], ErrorCodes.CERT_CHAIN_MALFORMED, /pinned root/, 'vc', pin(issuing));
  });
  test('an unknown critical extension on the root', async () => {
    const root = forge(ca('root'), (t) => t.extensions!.list.push({ oid: '1.3.6.1.4.1.55555.9', rest: extRest(true, [0x05, 0x00]) }), caKey('root'));
    await expectCode([leaf('vc'), issuing], ErrorCodes.CERT_CONSTRAINT_INVALID, /unknown critical extension 1\.3\.6\.1\.4\.1\.55555\.9/, 'vc', pin(root));
  });
  test('duplicate extension, duplicate subject attribute, non-v3, inner/outer algorithm mismatch are MALFORMED', async () => {
    const forged = [
      reLeaf((t) => t.extensions!.list.push({ ...t.extensions!.list[0]! })),
      reLeaf((t) => t.subject.rdns.splice(2, 0, [{ oid: '2.5.4.10', value: { TAG: 'utf8', data: 'Other O' } }])),
      reLeaf((t) => void (t.version = undefined)),
      reLeaf((t) => void (t.signature = { ...t.signature, algorithm: 'ecdsa-with-SHA384' })),
    ];
    for (const der of forged) {
      assert.throws(() => parseCertificate(der), TypeError);
      await expectCode([der, issuing], ErrorCodes.CERT_CHAIN_MALFORMED);
    }
  });
  test('a certificate labelled ecdsa-with-SHA384 is UNTRUSTED even when its bytes are a valid SHA-256 signature', async () => {
    const relabelled = forge(leaf('vc'), null, caKey('issuing'), { sigAlg: 'ecdsa-with-SHA384', hash: 'sha256' });
    assert.equal(parseCertificate(relabelled).signatureAlgorithm, '1.2.840.10045.4.3.3');
    await expectCode([relabelled, issuing], ErrorCodes.CERT_CHAIN_UNTRUSTED);
    await expectCode([forge(leaf('vc'), null, caKey('issuing'), { sigAlg: 'ecdsa-with-SHA384', hash: 'sha384' }), issuing], ErrorCodes.CERT_CHAIN_UNTRUSTED);
  });
  test('validity at the exact skew boundary (60 s, inclusive)', async () => {
    const at = (iso: string, ms: number) => new Date(new Date(iso).getTime() + ms);
    const expired = [leaf('expired'), issuing];
    assert.equal((await result(expired, 'vc', validator, at('2026-03-01T00:00:00Z', 60_000))).ok, true);
    await expectCode(expired, ErrorCodes.CERT_EXPIRED, undefined, 'vc', validator, at('2026-03-01T00:00:00Z', 60_001));
    const future = [leaf('not-yet-valid'), issuing];
    assert.equal((await result(future, 'vc', validator, at('2026-12-01T00:00:00Z', -60_000))).ok, true);
    await expectCode(future, ErrorCodes.CERT_NOT_YET_VALID, undefined, 'vc', validator, at('2026-12-01T00:00:00Z', -60_001));
  });
  test('CERT_NOT_YET_VALID for the issuing CA and for the root', async () => {
    const later = (t: Tbs) => void (t.validity.notBefore = { TAG: 'utc', data: '261201000000Z' });
    await expectCode([leaf('vc'), forge(issuing, later, caKey('root'))], ErrorCodes.CERT_NOT_YET_VALID, /issuing CA/);
    await expectCode([leaf('vc'), issuing], ErrorCodes.CERT_NOT_YET_VALID, /root/, 'vc', pin(forge(ca('root'), later, caKey('root'))));
  });
  test('the trust-list signer cannot act as an issuing CA', async () => {
    const ts = leaf('trust-list');
    const tsSubject = structuredClone((await import('micro-key-producer/x509.js')).X509.decode(ts).tbs.subject);
    const byTs = forge(leaf('vc'), (t) => void (t.issuer = tsSubject), leafKey('trust-list'));
    await expectCode([byTs, ts], ErrorCodes.CERT_CONSTRAINT_INVALID, /issuing CA must have CA:TRUE/);
  });
});

describe('parseCertificate strictness (F4, F5)', () => {
  test('any corruption throws TypeError and nothing else', () => {
    const der = leaf('vc');
    let parsed = 0;
    for (let i = 0; i < 600; i++) {
      const bad = der.slice();
      const at = randomBytes(2).readUInt16BE() % bad.length;
      bad[at] = bad[at]! ^ (1 + (randomBytes(1)[0]! % 255));
      try {
        parseCertificate(bad);
        parsed++;
      } catch (e) {
        assert.ok(e instanceof TypeError, `byte ${at}: ${(e as Error).constructor.name}: ${(e as Error).message}`);
      }
    }
    assert.ok(parsed < 600);
  });
  test('GeneralizedTime years before 1950 are refused; 1950-2049 are accepted (leniency)', () => {
    const at = (data: string) => forge(leaf('vc'), (t) => void (t.validity.notBefore = { TAG: 'generalized', data }), caKey('issuing'));
    for (const data of ['00490101000000Z', '19491231235959Z']) assert.throws(() => parseCertificate(at(data)), /1950/, data);
    assert.equal(parseCertificate(at('19500101000000Z')).notBefore.toISOString(), '1950-01-01T00:00:00.000Z');
    assert.equal(parseCertificate(at('20260101000000Z')).notBefore.toISOString(), '2026-01-01T00:00:00.000Z');
    const utc = (data: string) => parseCertificate(forge(leaf('vc'), (t) => void (t.validity.notBefore = { TAG: 'utc', data }), caKey('issuing'))).notBefore.getUTCFullYear();
    assert.deepEqual([utc('490101000000Z'), utc('500101000000Z')], [2049, 1950]);
  });
});

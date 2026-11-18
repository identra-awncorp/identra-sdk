// Certificate chain validation, steps 4-6 of docs/architecture.md section 4, profiles, pinned
// roots, and the DEMO PKI produced by scripts/pki/make-demo-pki.sh.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { createCertificateChainValidator, ErrorCodes, parseCertificate, type CertificateProfile } from '@identra/sdk-core';
import { webCryptoHasher, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { nobleHasher, nobleVerifier } from './helpers/noble.js';
import { b64, ca, leaf, NOW, pemCerts, pemFile, x5c } from './helpers/pki.js';

const ISS = 'https://api-identra.awncorp.vn/issuers';
const pin = (...roots: string[]) =>
  createCertificateChainValidator({ trustedRoots: roots.map(ca), verifier: webCryptoVerifier, hasher: webCryptoHasher });
const validator = pin('root');
const run = (chain: string[], profile: CertificateProfile = 'vc', v = validator, expectedIssuerUri = `${ISS}/truong-mau`) =>
  v.validate(profile === 'vc' ? { x5c: chain, profile, now: NOW, expectedIssuerUri } : { x5c: chain, profile, now: NOW });

describe('CERT_CONSTRAINT_INVALID, one test per sub-rule', () => {
  const cases: [string, string[], RegExp, ReturnType<typeof pin>?][] = [
    ['leaf with CA:TRUE', x5c('ca-true'), /leaf must have basicConstraints CA:FALSE/],
    ['leaf without basicConstraints', x5c('no-basic-constraints'), /leaf must have basicConstraints CA:FALSE/],
    ['leaf without digitalSignature', x5c('no-digital-signature'), /digitalSignature/],
    ['leaf without organizationIdentifier', x5c('no-org-id'), /leaf subject must be C=VN, O, organizationIdentifier=VATVN-/],
    ['leaf without O', x5c('no-o'), /leaf subject must be C=VN, O, organizationIdentifier=VATVN-/],
    ['leaf without C', x5c('no-c'), /leaf subject must be C=VN, O, organizationIdentifier=VATVN-/],
    ['issuing CA without pathlen:0', x5c('under-issuing-no-pathlen', 'issuing-no-pathlen'), /issuing CA must have CA:TRUE and pathLenConstraint 0/],
    ['issuing CA with CA:FALSE', x5c('under-issuing-ca-false', 'issuing-ca-false'), /issuing CA must have CA:TRUE/],
    ['issuing CA without keyCertSign', x5c('under-issuing-no-key-cert-sign', 'issuing-no-key-cert-sign'), /issuing CA keyUsage must be exactly keyCertSign and cRLSign/],
    ['root with CA:FALSE', x5c('under-root-ca-false', 'issuing-under-root-ca-false'), /root must have CA:TRUE/, pin('root-ca-false')],
    ['root without keyCertSign', x5c('under-root-no-key-cert-sign', 'issuing-under-root-no-key-cert-sign'), /root keyUsage must be exactly keyCertSign and cRLSign/, pin('root-no-key-cert-sign')],
    ['unknown critical extension', x5c('critical-ext'), /unknown critical extension 1\.3\.6\.1\.4\.1\.55555\.1/],
  ];
  for (const [name, chain, detail, v] of cases) {
    test(name, async () => {
      const r = await run(chain, 'vc', v);
      assert.equal(r.code, ErrorCodes.CERT_CONSTRAINT_INVALID);
      assert.match(r.checks[3]!.detail!, detail);
    });
  }
});

describe('CERT_KEY_NOT_ALLOWED', () => {
  test('RSA and P-384 leaf keys', async () => {
    assert.equal((await run(x5c('rsa'))).code, ErrorCodes.CERT_KEY_NOT_ALLOWED);
    assert.equal((await run(x5c('p384'))).code, ErrorCodes.CERT_KEY_NOT_ALLOWED);
  });
});

describe('ISSUER_MISMATCH', () => {
  test('expected issuer URI is not a SAN URI of the leaf', async () => {
    assert.equal((await run(x5c('wrong-san'), 'vc', validator, `${ISS}/truong-mau`)).code, ErrorCodes.ISSUER_MISMATCH);
    assert.equal((await run(x5c('status'), 'vc', validator, `${ISS}/truong-mau`)).code, ErrorCodes.ISSUER_MISMATCH);
    assert.equal((await run(x5c('vc'), 'vc', validator, `${ISS}/nha-san-xuat`)).code, ErrorCodes.ISSUER_MISMATCH);
  });
  test('the match is exact string equality with a SAN URI', async () => {
    for (const near of [`${ISS}/truong-mau/`, `${ISS}/Truong-mau`, `${ISS}/truong-mau#x`, 'https://API-identra.awncorp.vn/issuers/truong-mau', `${ISS}/truong-ma`]) {
      assert.equal((await run(x5c('vc'), 'vc', validator, near)).code, ErrorCodes.ISSUER_MISMATCH, near);
    }
  });
  test('expectedIssuerUri is required for vc and forbidden for the other profiles', async () => {
    await assert.rejects(validator.validate({ x5c: x5c('vc'), profile: 'vc', now: NOW } as never), TypeError);
    for (const profile of ['status', 'request', 'trust-list'] as const) {
      await assert.rejects(validator.validate({ x5c: x5c('status'), profile, now: NOW, expectedIssuerUri: `${ISS}/truong-mau` } as never), TypeError);
    }
  });
});

describe('profile trust-list', () => {
  test('accepts exactly one CA:FALSE certificate signed directly by the root', async () => {
    assert.equal((await run([b64(leaf('trust-list'))], 'trust-list')).ok, true);
    const r = await run([b64(leaf('trust-list-no-org-id'))], 'trust-list');
    assert.equal(r.code, ErrorCodes.CERT_CONSTRAINT_INVALID, 'the trust-list signer subject follows ADR-0015 section 9 too');
  });
  test('rejects a certificate issued by the issuing CA', async () => {
    assert.equal((await run([b64(leaf('vc'))], 'trust-list')).code, ErrorCodes.CERT_CHAIN_UNTRUSTED);
    assert.equal((await run(x5c('vc'), 'trust-list')).code, ErrorCodes.CERT_CHAIN_MALFORMED);
  });
  test('a root-signed leaf is not valid for the other profiles', async () => {
    for (const profile of ['vc', 'status', 'request'] as const) {
      assert.equal((await run([b64(leaf('trust-list'))], profile)).code, ErrorCodes.CERT_CHAIN_MALFORMED);
      assert.equal((await run([b64(leaf('trust-list')), b64(ca('root'))], profile)).code, ErrorCodes.CERT_CHAIN_MALFORMED);
    }
  });
  test('the noble backend agrees', async () => {
    const v = createCertificateChainValidator({ trustedRoots: [ca('root')], verifier: nobleVerifier, hasher: nobleHasher });
    assert.equal((await run([b64(leaf('trust-list'))], 'trust-list', v)).ok, true);
  });
});

describe('two pinned roots', () => {
  test('chains under either root validate', async () => {
    const v = pin('root', 'root2');
    assert.equal((await run(x5c('vc'), 'vc', v)).ok, true);
    assert.equal((await run(x5c('under-root2', 'issuing-under-root2'), 'vc', v)).ok, true);
    assert.equal((await run(x5c('under-root2', 'issuing-under-root2'))).code, ErrorCodes.CERT_CHAIN_UNTRUSTED);
  });
  test('two roots with the same name: every candidate is tried', async () => {
    const v = pin('evil-root', 'root');
    assert.equal((await run(x5c('vc'), 'vc', v)).ok, true);
    assert.equal((await run(x5c('evil-vc', 'evil-issuing'), 'vc', v)).ok, true);
  });
});

describe('DEMO PKI (make-demo-pki.sh), one day after it was made', () => {
  const demo = createCertificateChainValidator({
    trustedRoots: pemCerts(pemFile('demo/root.cert.pem')),
    verifier: webCryptoVerifier,
    hasher: webCryptoHasher,
  });
  const chainOf = (path: string) => pemCerts(pemFile(path)).map(b64);
  // A fixed instant derived from the set itself (its last certificate's notBefore + 1 day), so the
  // test does not depend on the wall clock or on when .pki/demo was generated.
  const now = new Date(parseCertificate(pemCerts(pemFile('demo/trust-list-signer/trust-list.cert.pem'))[0]!).notBefore.getTime() + 86_400_000);
  const orgs: [string, string, CertificateProfile, string?][] = [
    ['truong-mau', 'vc', 'vc', `${ISS}/truong-mau`],
    ['truong-mau', 'status', 'status'],
    ['nha-san-xuat', 'vc-product', 'vc', `${ISS}/nha-san-xuat`],
    ['kiem-dinh', 'vc-product', 'vc', `${ISS}/kiem-dinh`],
    ['phan-phoi', 'vc-product', 'vc', `${ISS}/phan-phoi`],
    ['phan-phoi', 'status', 'status'],
    ['nha-tuyen-dung-mau', 'request', 'request'],
  ];
  for (const [org, purpose, profile, iss] of orgs) {
    test(`${org} ${purpose}`, async () => {
      const r = await demo.validate({ x5c: chainOf(`demo/orgs/${org}/${purpose}.chain.pem`), profile, now, ...(iss ? { expectedIssuerUri: iss } : {}) });
      assert.equal(r.code, null);
      assert.match(r.leaf!.subject.O!, /DEMO/);
      assert.match(r.leaf!.subject.organizationIdentifier!, /^VATVN-01000000\d\d$/);
    });
  }
  test('trust-list signer', async () => {
    const r = await demo.validate({ x5c: chainOf('demo/trust-list-signer/trust-list.cert.pem'), profile: 'trust-list', now });
    assert.equal(r.code, null);
  });
  test('lifetimes follow ADR-0015 section 14 and the root notAfter is a GeneralizedTime year', () => {
    const years = (path: string) => {
      const { notBefore, notAfter } = pemCerts(pemFile(path)).map((d) => parseCertificate(d))[0]!;
      return (notAfter.getTime() - notBefore.getTime()) / (365.2425 * 86400_000);
    };
    assert.ok(Math.abs(years('demo/root.cert.pem') - 25) < 0.01);
    assert.ok(Math.abs(years('demo/ca/issuing/ca.cert.pem') - 15) < 0.01);
    assert.ok(Math.abs(years('demo/orgs/truong-mau/vc.cert.pem') - 3) < 0.01);
    assert.ok(Math.abs(years('demo/orgs/nha-san-xuat/vc-product.cert.pem') - 11) < 0.01);
    for (const p of ['demo/orgs/truong-mau/status.cert.pem', 'demo/orgs/nha-tuyen-dung-mau/request.cert.pem', 'demo/trust-list-signer/trust-list.cert.pem']) {
      const y = years(p);
      assert.ok(y > 1.07 && y < 1.1, `${p}: 13 months, got ${y} years`);
    }
  });
});

// GĐ2 end to end (ADR-0007 "Sản phẩm GĐ2"): issue a diploma with the DEMO truong-mau `vc` key,
// store it, present only ho_ten + nganh to a verifier, verify with the policy, then show that a
// tampered disclosure fails. Exits non-zero when any expectation is not met.
// Run with `npm run example:gd2` (builds, generates the DEMO PKI into .pki/demo if needed).
import { createHash, randomInt } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  base64Decode,
  base64UrlEncode,
  createCertificateChainValidator,
  createPresentation,
  decodeCredentialUnverified,
  issueDiploma,
  utf8Encode,
  VCT,
  verifyPresentation,
} from '@identra/sdk-core';
import {
  createWebCryptoSigner,
  generateWebCryptoKeyPair,
  webCryptoHasher,
  webCryptoRandom,
  webCryptoVerifier,
} from '@identra/sdk-core/webcrypto';

const DEMO = new URL('../.pki/demo/', import.meta.url);
const read = (path) => readFileSync(new URL(path, DEMO), 'utf8');
const pemCerts = (pem) => [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g)].map((m) => m[1].replace(/\s+/g, ''));

let failures = 0;
function expect(condition, message) {
  console.log(`${condition ? '  ok  ' : '  FAIL'} ${message}`);
  if (!condition) failures++;
}
function printChecks(result) {
  for (const c of result.checks) console.log(`    ${c.ok ? '✓' : '✗'} ${c.id.padEnd(18)} ${c.code ?? ''}${c.detail ? `  (${c.detail})` : ''}`);
}

// --- Issuer: Trường Mẫu DEMO, signing with its `vc` certificate ---------------------------------
const ISS = 'https://api-identra.awncorp.vn/issuers/truong-mau';
const x5c = pemCerts(read('orgs/truong-mau/vc.chain.pem'));
const issuer = await createWebCryptoSigner({ privateKey: read('orgs/truong-mau/vc.key.pem'), x5c });
const clock = { now: () => new Date() };

// --- Wallet: a fresh holder key ------------------------------------------------------------------
const holderKeys = await generateWebCryptoKeyPair();
const holder = await createWebCryptoSigner({ privateKey: holderKeys.privateKey, publicJwk: holderKeys.publicJwk });

console.log('1. Issue a diploma');
const stored = await issueDiploma({
  signer: issuer,
  hasher: webCryptoHasher,
  random: webCryptoRandom,
  clock,
  iss: ISS,
  cnfJwk: holder.publicJwk,
  status: { idx: randomInt(131_072), uri: `${ISS}/status/1` },
  claims: {
    ho_ten: 'Nguyễn Văn A',
    ngay_sinh: '2001-02-03',
    ma_sinh_vien: 'SV123456',
    nganh: 'Khoa học máy tính',
    hang_tot_nghiep: 'Giỏi',
    nam_tot_nghiep: '2024',
    so_hieu_bang: 'B-0001',
  },
});
console.log(`   compact: ${stored.length} bytes, ${stored.split('~').length - 2} disclosures (wallet stores it as is)`);

// --- Verifier setup: pinned DEMO root, in-memory trust list and status list ----------------------
const leafFingerprint = createHash('sha256').update(base64Decode(x5c[0])).digest('base64url');
const trustRegistry = {
  async lookup(fingerprint) {
    if (fingerprint !== leafFingerprint) return null;
    return { maToChuc: 'VATVN-0100000001', ten: 'Trường Mẫu DEMO', mucDich: 'vc', vct: [VCT.diploma] };
  },
};
const statusChecker = { async check() { return 'valid'; } };
const chainValidator = createCertificateChainValidator({
  trustedRoots: pemCerts(read('root.cert.pem')).map(base64Decode),
  verifier: webCryptoVerifier,
  hasher: webCryptoHasher,
});
const AUDIENCE = 'x509_hash:demo-verifier';
const nonce = base64UrlEncode(webCryptoRandom.bytes(16));
const options = {
  verifier: webCryptoVerifier,
  hasher: webCryptoHasher,
  chainValidator,
  trustRegistry,
  statusChecker,
  supportedVcts: [VCT.diploma],
  now: new Date(),
  presentation: { nonce, audience: AUDIENCE },
};

console.log('2. Present only ho_ten and nganh');
const presentation = await createPresentation({
  compact: stored, disclose: ['ho_ten', 'nganh'], holderSigner: holder, audience: AUDIENCE, nonce, now: new Date(), hasher: webCryptoHasher,
});
const sent = decodeCredentialUnverified(presentation.slice(0, presentation.lastIndexOf('~') + 1)).disclosures.map((d) => d.name);
expect(sent.length === 2 && sent.includes('ho_ten') && sent.includes('nganh'), `presentation carries only: ${sent.join(', ')}`);

console.log('3. Verify the presentation');
const result = await verifyPresentation(presentation, options);
printChecks(result);
expect(result.ok, 'every check passes');
expect(result.credential?.issuer?.ten === 'Trường Mẫu DEMO', `issuer from the trust list: ${result.credential?.issuer?.ten}`);
expect(result.credential?.claims?.ho_ten === 'Nguyễn Văn A' && result.credential?.claims?.nganh === 'Khoa học máy tính', 'verifier sees ho_ten and nganh');
expect(!('ngay_sinh' in (result.credential?.claims ?? {})), 'ngay_sinh was not disclosed');

console.log('4. Tamper with a disclosure (ho_ten changed, KB-JWT re-signed so only the digest can catch it)');
const parts = presentation.split('~');
const [salt] = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
parts[1] = base64UrlEncode(utf8Encode(JSON.stringify([salt, 'ho_ten', 'Trần Văn B'])));
const sdJwt = `${parts.slice(0, -1).join('~')}~`;
const sdHash = base64UrlEncode(await webCryptoHasher.sha256(utf8Encode(sdJwt)));
const kbHeader = base64UrlEncode(utf8Encode(JSON.stringify({ typ: 'kb+jwt', alg: 'ES256' })));
const kbPayload = base64UrlEncode(utf8Encode(JSON.stringify({ iat: Math.floor(Date.now() / 1000), aud: AUDIENCE, nonce, sd_hash: sdHash })));
const kbSignature = base64UrlEncode(await holder.sign(utf8Encode(`${kbHeader}.${kbPayload}`)));
const tampered = await verifyPresentation(`${sdJwt}${kbHeader}.${kbPayload}.${kbSignature}`, options);
printChecks(tampered);
expect(!tampered.ok, 'the tampered presentation is rejected');
expect(tampered.checks.find((c) => c.id === 'holder_binding')?.code === 'DISCLOSURE_INVALID', 'holder_binding reports DISCLOSURE_INVALID');
expect(tampered.credential?.claims === undefined, 'no claims are returned');

if (failures > 0) {
  console.error(`gd2-e2e: ${failures} expectation(s) failed`);
  process.exit(1);
}
console.log('gd2-e2e: all expectations met');

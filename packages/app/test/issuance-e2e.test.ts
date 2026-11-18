// GĐ5 end to end over REAL HTTP (127.0.0.1:47640): the sdk-server issuer mounted at the paths of
// vc-api.md section 4, a real trust list and status list served by the same listener, and the
// wallet reaching the canonical origin through createMappedFetch. resolve -> accept -> credential
// in the vault -> verifyStoredCredential -> presented with createPresentation and accepted by
// verifyPresentation. Run once with the wallet on noble (as on a phone) and once on WebCrypto.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import {
  createCertificateChainValidator, createMappedFetch, createPresentation, createSignedTrustListRegistry, createStatusListChecker,
  jwkThumbprint, VCT, verifyPresentation, verifyStoredCredential,
} from '@identra/sdk-core';
import { webCryptoHasher, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { createWorld, DIPLOMA, ISS, nodeHttpFetch, ORIGIN, rootDer, startListener, TRUST_URL, type Listener } from './helpers/world.js';

let listener: Listener;
before(async () => (listener = await startListener(47640)));
after(() => listener.close());

for (const backend of ['noble', 'webcrypto'] as const) {
  test(`full issuance over HTTP, wallet on ${backend}; the credential is then presented and verified`, async () => {
    const world = await createWorld(listener);
    const { wallet, keyStore, vault, secrets, rows } = world.newWallet(backend);
    const { offerId, offerUri, txCode } = await world.offer();
    listener.requests.length = 0;

    const resolved = await wallet.offers.resolve(offerUri);
    assert.equal(resolved.ok, true, JSON.stringify(resolved));
    if (!resolved.ok) return;
    assert.deepEqual(resolved.offer, {
      issuerUri: ISS,
      issuerOrigin: ORIGIN,
      issuerDisplay: [{ name: 'Trường Mẫu', locale: 'vi' }, { name: 'Sample University', locale: 'en' }],
      configuration: { id: 'bang-tot-nghiep-v1', vct: VCT.diploma, display: [{ name: 'Bằng tốt nghiệp', locale: 'vi' }, { name: 'Diploma', locale: 'en' }] },
      txCode: { length: 6, inputMode: 'numeric', description: 'Nhập mã PIN 6 chữ số được cấp cùng mã QR' },
    });
    assert.equal(secrets.size, 0, 'resolve creates no key');
    assert.deepEqual(listener.requests, [
      `GET /issuers/truong-mau/offers/${offerId}`,
      'GET /.well-known/openid-credential-issuer/issuers/truong-mau',
      'GET /.well-known/oauth-authorization-server/issuers/truong-mau',
    ]);

    const accepted = await wallet.offers.accept(resolved.offer, { txCode });
    assert.equal(accepted.ok, true, JSON.stringify(accepted));
    if (!accepted.ok) return;
    assert.deepEqual({ ...accepted, credentialId: typeof accepted.credentialId }, { ok: true, credentialId: 'string', vct: VCT.diploma, issuerName: 'Trường Mẫu (TEST)', status: 'valid' });
    assert.equal(rows.size, 1);
    assert.equal(secrets.size, 1);
    // The credential request and response went encrypted (ADR-0010 point 9, OpenID4VCI 1.0 section 10).
    const sent = listener.log.find((l) => l.path === '/issuers/truong-mau/credential')!;
    assert.deepEqual([sent.contentType, sent.responseType, sent.status], ['application/jwt', 'application/jwt', 200]);
    assert.equal(sent.body.includes('proofs'), false);

    // The server's side: the record, the status entry, the offer state.
    assert.equal(world.issued.length, 1);
    const event = world.issued[0]!;
    assert.equal(event.offerId, offerId);
    assert.match(event.statusUri, /^https:\/\/api-identra\.awncorp\.vn\/issuers\/truong-mau\/status\/1$/);
    assert.deepEqual(await world.issuer.offerStatus(offerId), { status: 'issued', subjectRef: 'sv001', credentialId: 'cred-1' });

    // What the wallet stored verifies independently, with a fresh registry and checker over the same HTTP.
    const row = [...rows.values()][0]!;
    const holder = await keyStore.signer(row.key_id);
    assert.equal(event.cnfThumbprint, await jwkThumbprint(holder.publicJwk, webCryptoHasher));
    const fetch = createMappedFetch(nodeHttpFetch, { [ORIGIN]: listener.localOrigin });
    const chainValidator = createCertificateChainValidator({ trustedRoots: [rootDer()], verifier: webCryptoVerifier, hasher: webCryptoHasher });
    const trustRegistry = createSignedTrustListRegistry({ url: TRUST_URL, fetch, verifier: webCryptoVerifier, chainValidator, clock: world.clock });
    const statusChecker = createStatusListChecker({ fetch, verifier: webCryptoVerifier, chainValidator, trustRegistry, clock: world.clock, maxAgeSeconds: 0 });
    const options = { verifier: webCryptoVerifier, hasher: webCryptoHasher, chainValidator, trustRegistry, statusChecker, supportedVcts: [VCT.diploma], now: world.clock.now() };
    const details = await wallet.credentials.get(accepted.credentialId);
    assert.equal(details.ok, true);
    if (!details.ok) return;
    assert.deepEqual(details.credential.claims, DIPLOMA);
    assert.equal(details.credential.issuerName, 'Trường Mẫu (TEST)');
    assert.equal(details.credential.status, 'valid');
    assert.equal(details.credential.iat, Math.floor(world.clock.now().getTime() / 1000));

    const listed = await wallet.credentials.list();
    assert.deepEqual(listed.map((c) => [c.id, c.vct, c.issuerUri, c.status]), [[accepted.credentialId, VCT.diploma, ISS, 'valid']]);

    // Present ho_ten and nganh to a verifier: the issued credential is fully usable.
    const stored = await vault.open(accepted.credentialId);
    assert.equal((await verifyStoredCredential(stored, options)).ok, true);
    const presentation = await createPresentation({ compact: stored, disclose: ['ho_ten', 'nganh'], holderSigner: holder, audience: 'x509_hash:test-verifier', nonce: 'nonce-1', now: world.clock.now(), hasher: webCryptoHasher });
    const verified = await verifyPresentation(presentation, { ...options, presentation: { nonce: 'nonce-1', audience: 'x509_hash:test-verifier' } });
    assert.equal(verified.ok, true, JSON.stringify(verified.checks));
    assert.deepEqual(verified.credential?.claims, { ho_ten: DIPLOMA.ho_ten, nganh: DIPLOMA.nganh });

    // Status refresh, then revocation seen after the list's cache lifetime, then removal.
    assert.deepEqual(await wallet.credentials.refreshStatus(accepted.credentialId).then((r) => r.ok && r.status), 'valid');
    await world.statusService.setStatus('truong-mau', 1, event.statusIdx, 'revoked');
    world.clock.advance(901);
    const refreshed = await wallet.credentials.refreshStatus(accepted.credentialId);
    assert.equal(refreshed.ok && refreshed.status, 'revoked');
    assert.equal((await wallet.credentials.list())[0]!.status, 'revoked');
    assert.deepEqual(await wallet.credentials.remove(accepted.credentialId), { ok: true });
    assert.equal(rows.size, 0);
    assert.equal(secrets.size, 0);
    assert.deepEqual(await wallet.credentials.get(accepted.credentialId), { ok: false, code: 'CREDENTIAL_NOT_FOUND' });
  });
}

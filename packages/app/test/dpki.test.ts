// The DID trust path (ADR-0020) in the wallet over REAL HTTP (127.0.0.1:47646): a DID issuer of the
// SDK (truong-did, DID signer, DID-signed status lists) received through the wallet's real
// OpenID4VCI flow, the receipt rule of `identra_issuer_did`, "not checked yet" versus refused, the
// stored record and its views, re-checks, and a presentation to the SDK verifier. The CertNet gateway
// is a FAKE (helpers/world.ts fakeGateway); keys are generated at run time.
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { decodeCredentialUnverified, VCT } from '@identra/sdk-core';
import { buildCatalogue } from '@identra/sdk-app';
import { createWorld, DID, DID_ISS, fakeGateway, ISS, newSession, startListener, type Handler, type Listener, type World } from './helpers/world.js';

let listener: Listener;
before(async () => (listener = await startListener(47646)));
after(() => listener.close());

type TestWallet = ReturnType<World['newWallet']>;
const OTHER_DID = 'did:certnet:local:khacdid0002';

async function resolved(world: World, w: TestWallet) {
  const created = await world.offer();
  const r = await w.wallet.offers.resolve(created.offerUri);
  assert.equal(r.ok, true, JSON.stringify(r));
  return { ...created, offer: (r as Extract<typeof r, { ok: true }>).offer };
}

/** Rewrites the credential issuer metadata the world serves for issuer `name`. */
function patchMetadata(name: string, patch: (m: Record<string, unknown>) => void) {
  const key = `GET /.well-known/openid-credential-issuer/issuers/${name}`;
  const inner = listener.routes.get(key)!;
  const patched: Handler = async (req) => {
    const r = await inner(req);
    const m = JSON.parse(r.body) as Record<string, unknown>;
    patch(m);
    return { ...r, body: JSON.stringify(m) };
  };
  listener.routes.set(key, patched);
}

const codeAt = (checks: { id: string; code: string | null }[] | undefined, id: string) => checks?.find((c) => c.id === id)?.code;

describe('receiving from a DID issuer', () => {
  test('end to end: received, stored with its trust path and DID, shown without a name, re-checked, catalogued by URL, presented, removed', async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const { offer, txCode } = await resolved(world, w);
    assert.equal(offer.issuerUri, DID_ISS);
    const accepted = await w.wallet.offers.accept(offer, { txCode });
    assert.deepEqual({ ...accepted, credentialId: 'x' }, { ok: true, credentialId: 'x', vct: VCT.diploma, issuerName: null, issuerDid: DID, status: 'valid' });
    if (!accepted.ok) return;
    const row = [...w.rows.values()][0]!;
    assert.deepEqual([row.issuer, row.issuer_did, row.status_cache], [DID_ISS, DID, 'valid']);
    assert.equal(decodeCredentialUnverified(await w.vault.open(row.id)).payload['iss'], DID);
    // The gateway was reached only through the resolver and the trust registry.
    assert.ok(world.gateway.state.calls.length > 0);
    assert.ok(world.gateway.state.calls.every((u) => u.startsWith(`${world.gateway.base}/v1/dids/`) || u.startsWith(`${world.gateway.base}/v1/trust-registry/issuers/`)));
    assert.equal(listener.requests.some((r) => r.includes('/v1/')), false);

    const [summary] = await w.wallet.credentials.list();
    assert.deepEqual({ ...summary, statusCheckedAt: null, createdAt: null }, {
      id: accepted.credentialId, vct: VCT.diploma, issuerUri: DID_ISS, trustPath: 'did', issuerDid: DID, status: 'valid', statusCheckedAt: null, createdAt: null,
    });
    const details = await w.wallet.credentials.get(accepted.credentialId);
    assert.ok(details.ok);
    assert.deepEqual([details.credential.trustPath, details.credential.issuerDid, details.credential.issuerName], ['did', DID, null]);
    const refreshed = await w.wallet.credentials.refreshStatus(accepted.credentialId);
    assert.deepEqual([refreshed.ok, refreshed.ok && refreshed.status], [true, 'valid']);
    assert.ok(refreshed.ok && refreshed.checks.some((c) => c.id === 'did_resolution' && c.ok));
    // The backup catalogue names the credential issuer URL, where the credential can be asked for again.
    assert.deepEqual(buildCatalogue(await w.vault.list()), { version: 1, items: [{ vct: VCT.diploma, issuer: DID_ISS }] });

    // Presented to the SDK verifier (X.509-identified, DID path on).
    const verifier = await world.newVerifier({ dpki: true });
    const session = await newSession(verifier);
    const request = await w.wallet.presentations.resolve(session.qr);
    assert.ok(request.ok, JSON.stringify(request));
    assert.deepEqual(request.request.matches.map((m) => [m.credentialId, m.trustPath, m.issuerDid, m.issuerName]), [[accepted.credentialId, 'did', DID, null]]);
    assert.deepEqual(await w.wallet.presentations.submit(request.request, { credentialId: accepted.credentialId, claimSetIndex: 1 }), { ok: true });
    const done = (await verifier.session(session.id))!;
    assert.equal(done.status, 'verified', JSON.stringify(done.result));
    assert.deepEqual([done.result?.trustPath, done.result?.issuerDid, 'issuer' in done.result!], ['did', DID, false]);

    assert.deepEqual(await w.wallet.credentials.remove(accepted.credentialId), { ok: true });
    assert.deepEqual([w.rows.size, w.secrets.size], [0, 0]);
  });

  test('ISSUER_MISMATCH for every combination the metadata does not declare; nothing is stored and the key is deleted', async () => {
    const cases: [string, () => Promise<World>][] = [
      ['metadata names another DID than the credential iss', async () => {
        const world = await createWorld(listener, { did: {} });
        patchMetadata('truong-did', (m) => (m['identra_issuer_did'] = OTHER_DID));
        return world;
      }],
      ['metadata names a DID but the credential is X.509', async () => {
        const world = await createWorld(listener);
        patchMetadata('truong-mau', (m) => (m['identra_issuer_did'] = DID));
        return world;
      }],
      ['no DID in the metadata but a DID credential', async () => {
        const world = await createWorld(listener, { did: {} });
        patchMetadata('truong-did', (m) => delete m['identra_issuer_did']);
        return world;
      }],
      ['the DID credential has its status list on another host', () => createWorld(listener, { did: { statusOrigin: 'https://status.truong-did.example.vn' } })],
    ];
    for (const [name, make] of cases) {
      const world = await make();
      const w = world.newDidWallet();
      const { offer, txCode } = await resolved(world, w);
      assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'ISSUER_MISMATCH', retryable: false, codeRedeemed: true }, name);
      assert.deepEqual([w.rows.size, w.secrets.size], [0, 0], name);
    }
  });

  test('a malformed identra_issuer_did makes the offer invalid before anything is spent, with or without dpki', async () => {
    for (const bad of ['did:web:truong.example.vn', 'did:certnet:local:', 'did:certnet:other:abc', `${DID}#key-1`, 42, null, '']) {
      const world = await createWorld(listener, { did: {} });
      patchMetadata('truong-did', (m) => (m['identra_issuer_did'] = bad));
      for (const w of [world.newDidWallet(), world.newWallet()]) {
        const created = await world.offer();
        assert.deepEqual(await w.wallet.offers.resolve(created.offerUri), { ok: false, code: 'OFFER_INVALID' }, String(bad));
      }
      assert.equal(listener.requests.some((r) => r.includes('/token')), false);
    }
  });

  test('resolve says which path the issuer declared: its unverified DID without a gateway request, null for an X.509 issuer', async () => {
    const world = await createWorld(listener, { did: {} });
    const { offer } = await resolved(world, world.newDidWallet());
    assert.equal(offer.issuerDid, DID);
    assert.deepEqual(world.gateway.state.calls, []);
    const x509 = await createWorld(listener);
    assert.equal((await resolved(x509, x509.newWallet())).offer.issuerDid, null);
    assert.equal((await resolved(x509, x509.newDidWallet())).offer.issuerDid, null);
  });

  test('without dpki: an offer of a DID issuer is TRUST_PATH_UNSUPPORTED at resolve, before any PIN or key; a DID credential is never accepted', async () => {
    const world = await createWorld(listener, { did: {} });
    const plain = world.newWallet();
    assert.deepEqual(await plain.wallet.offers.resolve((await world.offer()).offerUri), { ok: false, code: 'TRUST_PATH_UNSUPPORTED' });
    assert.equal(listener.requests.some((r) => r.includes('/token')), false);
    assert.equal(plain.secrets.size, 0);
    patchMetadata('truong-did', (m) => delete m['identra_issuer_did']);
    const { offer, txCode } = await resolved(world, plain);
    const r = await plain.wallet.offers.accept(offer, { txCode });
    assert.deepEqual([r.ok, !r.ok && r.code, !r.ok && codeAt(r.checks, 'did_resolution')], [false, 'CREDENTIAL_INVALID', 'DID_RESOLUTION_FAILED']);
    assert.deepEqual([plain.rows.size, plain.secrets.size], [0, 0]);
    assert.deepEqual(world.gateway.state.calls, []);
  });
});

describe('not checked yet versus refused', () => {
  test('DID unresolvable at receipt: nothing stored, retryable NETWORK_ERROR; the next accept verifies the same credential without asking the issuer again', async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const { offer, txCode } = await resolved(world, w);
    world.gateway.state.down = true;
    const first = await w.wallet.offers.accept(offer, { txCode });
    assert.deepEqual({ ...first, checks: undefined }, { ok: false, code: 'NETWORK_ERROR', retryable: true, codeRedeemed: true, checks: undefined });
    assert.equal(!first.ok && codeAt(first.checks, 'did_resolution'), 'DID_RESOLUTION_UNAVAILABLE');
    assert.deepEqual([w.rows.size, w.secrets.size], [0, 1], 'not stored; its key is kept for the retry');
    const again = await w.wallet.offers.accept(offer);
    assert.equal(!again.ok && again.code, 'NETWORK_ERROR', 'still down');
    world.gateway.state.down = false;
    const credentialRequests = listener.requests.filter((r) => r === 'POST /issuers/truong-did/credential').length;
    const ok = await w.wallet.offers.accept(offer);
    assert.deepEqual({ ...ok, credentialId: 'x' }, { ok: true, credentialId: 'x', vct: VCT.diploma, issuerName: null, issuerDid: DID, status: 'valid' });
    assert.equal(listener.requests.filter((r) => r === 'POST /issuers/truong-did/credential').length, credentialRequests, 'no second credential request');
    assert.deepEqual([w.rows.size, w.secrets.size], [1, 1]);

    // Abandoned while down: discard deletes the kept key.
    const w2 = world.newDidWallet();
    const second = await resolved(world, w2);
    world.gateway.state.down = true;
    assert.equal((await w2.wallet.offers.accept(second.offer, { txCode: second.txCode })).ok, false);
    assert.equal(w2.secrets.size, 1);
    await w2.wallet.offers.discard(second.offer);
    assert.deepEqual([w2.rows.size, w2.secrets.size], [0, 0]);
  });

  test('DID unresolvable for a credential the metadata did not announce: refused at once, nothing kept', async () => {
    const world = await createWorld(listener, { did: {} });
    patchMetadata('truong-did', (m) => delete m['identra_issuer_did']);
    const w = world.newDidWallet();
    const { offer, txCode } = await resolved(world, w);
    world.gateway.state.down = true;
    assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'ISSUER_MISMATCH', retryable: false, codeRedeemed: true });
    assert.deepEqual([w.rows.size, w.secrets.size], [0, 0]);
  });

  test('trust registry down at receipt: stored as not checked yet, then valid on a later re-check; rejected later: not valid; gateway down later: unknown', async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const { offer, txCode } = await resolved(world, w);
    world.gateway.state.tirDown = true;
    const accepted = await w.wallet.offers.accept(offer, { txCode });
    assert.deepEqual({ ...accepted, credentialId: 'x' }, { ok: true, credentialId: 'x', vct: VCT.diploma, issuerName: null, issuerDid: DID, status: 'unknown' });
    if (!accepted.ok) return;
    assert.equal([...w.rows.values()][0]!.status_cache, 'unavailable');
    const still = await w.wallet.credentials.refreshStatus(accepted.credentialId);
    assert.deepEqual([still.ok && still.status, still.ok && codeAt(still.checks, 'issuer_trust')], ['unknown', 'TRUST_LIST_UNAVAILABLE']);
    world.gateway.state.tirDown = false;
    assert.equal((await w.wallet.credentials.refreshStatus(accepted.credentialId) as { status: string }).status, 'valid');

    world.gateway.state.down = true;
    world.clock.advance(61); // past the resolver's cache of the DID document
    const down = await w.wallet.credentials.refreshStatus(accepted.credentialId);
    assert.deepEqual([down.ok && down.status, down.ok && codeAt(down.checks, 'did_resolution')], ['unknown', 'DID_RESOLUTION_UNAVAILABLE']);
    world.gateway.state.down = false;

    world.gateway.state.recognition = 'rejected';
    const rejected = await w.wallet.credentials.refreshStatus(accepted.credentialId);
    assert.deepEqual([rejected.ok && rejected.status, rejected.ok && codeAt(rejected.checks, 'issuer_trust')], ['invalid', 'ISSUER_NOT_TRUSTED']);
    assert.equal((await w.wallet.credentials.list())[0]!.status, 'invalid');
  });

  test('a stored DID credential re-checked in a wallet without dpki is unknown (nothing checked); with dpki a definitive DID failure stays invalid', async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const id = await world.issueTo(w);
    // The same key store and vault, the DID path switched off.
    const off = world.newWallet('noble', undefined, world.clock, { keyStore: w.keyStore, vault: w.vault });
    const unchecked = await off.wallet.credentials.refreshStatus(id);
    assert.deepEqual([unchecked.ok && unchecked.status, unchecked.ok && codeAt(unchecked.checks, 'did_resolution')], ['unknown', 'DID_RESOLUTION_FAILED']);
    assert.equal(w.rows.get(id)!.status_cache, 'unavailable');
    // A gateway that does not know the DID (404): definitive, so invalid.
    const unknownDid = world.newWallet('noble', undefined, world.clock, { keyStore: w.keyStore, vault: w.vault, dpki: fakeGateway().dpki(world.clock) });
    const failed = await unknownDid.wallet.credentials.refreshStatus(id);
    assert.deepEqual([failed.ok && failed.status, failed.ok && codeAt(failed.checks, 'did_resolution')], ['invalid', 'DID_RESOLUTION_FAILED']);
  });

  test('issuer rejected by the trust registry at receipt: refused as invalid', async () => {
    const world = await createWorld(listener, { did: {} });
    world.gateway.state.recognition = 'rejected';
    const w = world.newDidWallet();
    const { offer, txCode } = await resolved(world, w);
    const r = await w.wallet.offers.accept(offer, { txCode });
    assert.deepEqual([r.ok, !r.ok && r.code, !r.ok && r.retryable, !r.ok && codeAt(r.checks, 'issuer_trust')], [false, 'CREDENTIAL_INVALID', false, 'ISSUER_NOT_TRUSTED']);
    assert.deepEqual([w.rows.size, w.secrets.size], [0, 0]);
  });
});

describe('stored records', () => {
  test('a record written before the DID path (no issuer_did, or NULL from the new column) reads as X.509 and still opens', async () => {
    const world = await createWorld(listener);
    const w = world.newWallet();
    const id = await world.issueTo(w);
    const row = w.rows.get(id)!;
    assert.equal('issuer_did' in row, false, 'an X.509 row is written exactly as before');
    for (const old of [{ ...row }, { ...row, issuer_did: null }]) {
      w.rows.set(id, old);
      const [summary] = await w.wallet.credentials.list();
      assert.deepEqual([summary!.issuerUri, summary!.trustPath, summary!.issuerDid], [ISS, 'x509', null]);
      const details = await w.wallet.credentials.get(id);
      assert.deepEqual([details.ok, details.ok && details.credential.issuerName], [true, 'Trường Mẫu (TEST)']);
      assert.equal((await w.wallet.credentials.refreshStatus(id) as { status: string }).status, 'valid');
    }
  });

  test('the issuer DID is bound to the sealed credential: changing or dropping it makes the row unopenable', async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const id = await world.issueTo(w);
    const row = w.rows.get(id)!;
    for (const changed of [{ ...row, issuer_did: OTHER_DID }, { ...row, issuer_did: null }]) {
      w.rows.set(id, changed);
      await assert.rejects(w.vault.open(id), { code: 'UNDECRYPTABLE' });
    }
    w.rows.set(id, row);
    assert.equal(typeof (await w.vault.open(id)), 'string');
    await assert.rejects(w.vault.save({ compact: 'a.b.c~', vct: VCT.diploma, issuer: DID_ISS, issuerDid: 'did:web:x', keyId: 'k' }), TypeError);
  });
});

// The DID trust path (ADR-0020) in the wallet over REAL HTTP (127.0.0.1:47646): a DID issuer of the
// SDK (truong-did, DID signer, DID-signed status lists) received through the wallet's real
// OpenID4VCI flow, the receipt rule of `identra_issuer_did`, "not checked yet" versus refused, the
// stored record and its views, re-checks, and a presentation to the SDK verifier. The CertNet gateway
// is a FAKE (helpers/world.ts fakeGateway); keys are generated at run time.
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { base64Decode, base64UrlDecode, base64UrlEncode, decodeCredentialUnverified, signJws, utf8Decode, utf8Encode, VCT, type Signer } from '@identra/sdk-core';
import { webCryptoHasher, webCryptoRandom } from '@identra/sdk-core/webcrypto';
import {
  buildCatalogue, createInMemorySecretStorage, createSoftwareKeyStore, MAX_DID_LENGTH, MAX_PRESENTATION_PINS, MAX_PRESENTATION_SENDS, type ResolvedPresentation, type WalletKeyStore,
} from '@identra/sdk-app';
import { matchesDeclaredIssuer, onlyListsUnavailable } from '../dist/wallet/issuance.js';
import { createWorld, DID, DID_ISS, fakeGateway, ISS, leafSigner, newSession, ORIGIN, startListener, type Handler, type Listener, type World } from './helpers/world.js';

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

/** The verifier's "could not reach CertNet" answer (sdk-server ISSUER_REGISTRY_UNAVAILABLE). */
const REGISTRY_DOWN = { status: 503, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'issuer_registry_unavailable', error_description: 'x' }) };
const UNAVAILABLE = { ok: false, code: 'DID_RESOLUTION_UNAVAILABLE', delivered: true };
/** A response endpoint that answers every POST with REGISTRY_DOWN (set it after newVerifier mounted the routes); the bodies it received. */
function answerRegistryDown(): string[] {
  const posts: string[] = [];
  listener.routes.set('POST /oid4vp/response/*', async (req) => (posts.push(req.body), REGISTRY_DOWN));
  return posts;
}
async function resolvedRequest(w: TestWallet, verifier: Awaited<ReturnType<World['newVerifier']>>) {
  const r = await w.wallet.presentations.resolve((await newSession(verifier)).qr);
  assert.ok(r.ok, JSON.stringify(r));
  return r.request;
}

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

  test('the receipt rule is applied to the decoded credential before verification: nothing is fetched for a credential refused anyway', async () => {
    const cases: [string, () => Promise<World>][] = [
      ['status list on another host', () => createWorld(listener, { did: { statusOrigin: 'https://tracker.example.net' } })],
      ['iss is not the declared DID', async () => {
        const world = await createWorld(listener, { did: {} });
        patchMetadata('truong-did', (m) => (m['identra_issuer_did'] = OTHER_DID));
        return world;
      }],
      ['no DID declared, a DID credential', async () => {
        const world = await createWorld(listener, { did: {} });
        patchMetadata('truong-did', (m) => delete m['identra_issuer_did']);
        return world;
      }],
    ];
    for (const [name, make] of cases) {
      const world = await make();
      const w = world.newDidWallet();
      const { offer, txCode } = await resolved(world, w);
      assert.deepEqual(await w.wallet.offers.accept(offer, { txCode }), { ok: false, code: 'ISSUER_MISMATCH', retryable: false, codeRedeemed: true }, name);
      assert.deepEqual(world.gateway.state.calls, [], `${name}: no gateway request`);
      assert.equal(listener.requests.some((r) => r.includes('/status/')), false, `${name}: no status list request`);
      assert.deepEqual([w.rows.size, w.secrets.size], [0, 0], name);
    }
  });

  test('the receipt rule itself, including the parts that the checks before it mask end to end', () => {
    const statusUri = `${DID_ISS}/status/1`;
    const didDeclared = { issuerUri: DID_ISS, issuerDid: DID };
    assert.equal(matchesDeclaredIssuer({ trustPath: 'did', iss: DID, statusUri }, didDeclared), true);
    assert.equal(matchesDeclaredIssuer({ iss: DID, statusUri }, didDeclared), true, 'before verification');
    assert.equal(matchesDeclaredIssuer({ trustPath: 'x509', iss: DID, statusUri }, didDeclared), false, 'the X.509 path with the declared DID as iss');
    for (const iss of [OTHER_DID, DID_ISS, `${DID}#key-1`, undefined]) assert.equal(matchesDeclaredIssuer({ trustPath: 'did', iss, statusUri }, didDeclared), false, String(iss));
    for (const uri of ['https://status.truong-did.example.vn/issuers/truong-did/status/1', `${DID_ISS}/status/0`, `${DID_ISS}x/status/1`, `${DID_ISS}/status/1?x`, undefined]) {
      assert.equal(matchesDeclaredIssuer({ trustPath: 'did', iss: DID, statusUri: uri }, didDeclared), false, String(uri));
      assert.equal(matchesDeclaredIssuer({ iss: DID, statusUri: uri }, didDeclared), false, `before verification: ${String(uri)}`);
    }
    const x509Declared = { issuerUri: ISS, issuerDid: null };
    assert.equal(matchesDeclaredIssuer({ trustPath: 'x509', iss: ISS, statusUri: `${ISS}/status/1` }, x509Declared), true);
    assert.equal(matchesDeclaredIssuer({ iss: ISS, statusUri: undefined }, x509Declared), true, 'before verification');
    assert.equal(matchesDeclaredIssuer({ trustPath: 'did', iss: ISS, statusUri: `${ISS}/status/1` }, x509Declared), false, 'the DID path with the issuer URL as iss');
    assert.equal(matchesDeclaredIssuer({ iss: DID, statusUri: undefined }, x509Declared), false);

    // A DID credential whose only failure is its status list: "not checked yet" only with a status URI of the DID-path form.
    const checks = [{ id: 'signature', ok: true, code: null }, { id: 'status', ok: false, code: 'STATUS_UNAVAILABLE' }] as never;
    const listsDown = (uri: string) => onlyListsUnavailable({ checks, credential: { trustPath: 'did', vct: 'x', iss: DID, iat: 0, issuerDid: DID, issuer: null, status: { idx: 1, uri } } });
    assert.equal(listsDown(statusUri), true);
    for (const uri of [`${DID}/status/1`, 'https://localhost/issuers/truong-did/status/1', 'https://127.0.0.1/s/status/1', `${DID_ISS}/status/0`]) assert.equal(listsDown(uri), false, uri);
  });

  test('identra_issuer_did longer than MAX_DID_LENGTH is OFFER_INVALID; with dpki.network, a DID of another network is TRUST_PATH_UNSUPPORTED at resolve', async () => {
    const prefix = 'did:certnet:local:';
    const ofLength = (n: number) => prefix + 'a'.repeat(n - prefix.length);
    assert.equal(MAX_DID_LENGTH, 128);
    const longest = await createWorld(listener, { did: {} });
    patchMetadata('truong-did', (m) => (m['identra_issuer_did'] = ofLength(MAX_DID_LENGTH)));
    assert.equal((await resolved(longest, longest.newDidWallet())).offer.issuerDid, ofLength(MAX_DID_LENGTH));
    for (const did of [ofLength(MAX_DID_LENGTH + 1), `did:certnet:mainnet:${'A'.repeat(20_000)}`]) {
      const world = await createWorld(listener, { did: {} });
      patchMetadata('truong-did', (m) => (m['identra_issuer_did'] = did));
      for (const w of [world.newDidWallet(), world.newWallet()]) {
        assert.deepEqual(await w.wallet.offers.resolve((await world.offer()).offerUri), { ok: false, code: 'OFFER_INVALID' }, `${did.length} characters`);
      }
      assert.equal(listener.requests.some((r) => r.includes('/token')), false);
    }

    const world = await createWorld(listener, { did: {} }); // DID is of the network local
    const onNetwork = (network: string) => world.newDidWallet({ dpki: { ...world.gateway.dpki(world.clock), network: network as 'local' } });
    assert.equal((await resolved(world, onNetwork('local'))).offer.issuerDid, DID);
    assert.equal((await resolved(world, world.newDidWallet())).offer.issuerDid, DID, 'no network given: as before');
    for (const network of ['testnet', 'mainnet']) {
      const w = onNetwork(network);
      assert.deepEqual(await w.wallet.offers.resolve((await world.offer()).offerUri), { ok: false, code: 'TRUST_PATH_UNSUPPORTED' }, network);
      assert.equal(w.secrets.size, 0);
    }
    assert.equal(listener.requests.some((r) => r.includes('/token')), false, 'no PIN spent');
    assert.deepEqual(world.gateway.state.calls, []);
    assert.throws(() => onNetwork('devnet'), TypeError);
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
    // Refused by the receipt rule on the decoded payload, before verification (as with dpki).
    assert.deepEqual([r.ok, !r.ok && r.code, !r.ok && r.checks], [false, 'ISSUER_MISMATCH', undefined]);
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

  test('the verifier cannot reach the gateway: submit is DID_RESOLUTION_UNAVAILABLE, the request stays usable, and the same request verifies once it is back', async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const credentialId = await world.issueTo(w);
    const verifier = await world.newVerifier({ dpki: true });
    const session = await newSession(verifier);
    const request = await w.wallet.presentations.resolve(session.qr);
    assert.ok(request.ok);
    world.gateway.state.down = true;
    const seen = listener.log.length;
    for (let i = 0; i < 2; i++) {
      assert.deepEqual(await w.wallet.presentations.submit(request.request, { credentialId, claimSetIndex: 1 }), { ok: false, code: 'DID_RESOLUTION_UNAVAILABLE', delivered: true });
    }
    assert.deepEqual(listener.log.slice(seen).filter((l) => l.path.startsWith('/oid4vp/response/')).map((l) => l.status), [503, 503]);
    assert.equal((await verifier.session(session.id))?.status, 'request_retrieved');
    world.gateway.state.down = false;
    assert.deepEqual(await w.wallet.presentations.submit(request.request, { credentialId, claimSetIndex: 1 }), { ok: true });
    assert.equal((await verifier.session(session.id))?.status, 'verified');
    assert.deepEqual(await w.wallet.presentations.submit(request.request, { credentialId, claimSetIndex: 1 }), { ok: false, code: 'REQUEST_INVALID' }, 'answered: forgotten');
  });

  test('only a 503 with issuer_registry_unavailable is that failure: other answers stay VERIFIER_ERROR and the request is forgotten', async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const credentialId = await world.issueTo(w);
    const verifier = await world.newVerifier({ dpki: true });
    const json = (error: string) => JSON.stringify({ error, error_description: 'x' });
    for (const [status, body] of [[503, json('temporarily_unavailable')], [503, ''], [503, 'issuer_registry_unavailable'], [500, json('issuer_registry_unavailable')], [400, json('issuer_registry_unavailable')]] as const) {
      listener.routes.set('POST /oid4vp/response/*', async () => ({ status, headers: { 'Content-Type': 'application/json' }, body }));
      const request = await w.wallet.presentations.resolve((await newSession(verifier)).qr);
      assert.ok(request.ok);
      assert.deepEqual(await w.wallet.presentations.submit(request.request, { credentialId, claimSetIndex: 1 }), { ok: false, code: 'VERIFIER_ERROR' }, `${status} ${body}`);
      assert.deepEqual(await w.wallet.presentations.submit(request.request, { credentialId, claimSetIndex: 1 }), { ok: false, code: 'REQUEST_INVALID' }, `${status} ${body}`);
    }
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

describe('the verifier says it could not reach CertNet (503 issuer_registry_unavailable)', () => {
  test('an X.509 credential: VERIFIER_ERROR and the request is forgotten, in a wallet with or without dpki; a second submit sends nothing', async () => {
    const world = await createWorld(listener);
    for (const w of [world.newWallet(), world.newDidWallet()]) {
      const credentialId = await world.issueTo(w);
      const verifier = await world.newVerifier({ dpki: true });
      const posts = answerRegistryDown();
      const request = await resolvedRequest(w, verifier);
      assert.equal(request.matches[0]!.trustPath, 'x509');
      assert.deepEqual(await w.wallet.presentations.submit(request, { credentialId, claimSetIndex: 1 }), { ok: false, code: 'VERIFIER_ERROR' });
      assert.deepEqual(await w.wallet.presentations.submit(request, { credentialId, claimSetIndex: 0 }), { ok: false, code: 'REQUEST_INVALID' });
      assert.deepEqual(await w.wallet.presentations.submit(request, { credentialId, claimSetIndex: 1 }), { ok: false, code: 'REQUEST_INVALID' });
      assert.equal(posts.length, 1);
    }
  });

  test('a DID credential in a wallet without dpki: VERIFIER_ERROR and the request is forgotten', async () => {
    const world = await createWorld(listener, { did: {} });
    const holder = world.newDidWallet();
    const credentialId = await world.issueTo(holder);
    const off = world.newWallet('noble', undefined, world.clock, { keyStore: holder.keyStore, vault: holder.vault });
    const verifier = await world.newVerifier({ dpki: true });
    const posts = answerRegistryDown();
    const request = await resolvedRequest(off, verifier);
    assert.equal(request.matches[0]!.trustPath, 'did');
    assert.deepEqual(await off.wallet.presentations.submit(request, { credentialId, claimSetIndex: 1 }), { ok: false, code: 'VERIFIER_ERROR' });
    assert.deepEqual(await off.wallet.presentations.submit(request, { credentialId, claimSetIndex: 1 }), { ok: false, code: 'REQUEST_INVALID' });
    assert.equal(posts.length, 1);
  });

  test('a DID credential with dpki: kept with delivered: true and pinned to what was sent; another claim set or credential is refused and sends nothing', async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const first = await world.issueTo(w);
    const second = await world.issueTo(w);
    const verifier = await world.newVerifier({ dpki: true });
    const posts = answerRegistryDown();
    const sent = { credentialId: first, claimSetIndex: 1 };

    const kept = await resolvedRequest(w, verifier);
    assert.deepEqual(await w.wallet.presentations.submit(kept, sent), UNAVAILABLE);
    assert.deepEqual(await w.wallet.presentations.submit(kept, sent), UNAVAILABLE, 'the same selection is sent again');
    assert.equal(posts.length, 2);

    for (const other of [{ credentialId: first, claimSetIndex: 0 }, { credentialId: second, claimSetIndex: 1 }]) {
      const request = await resolvedRequest(w, verifier);
      assert.deepEqual(await w.wallet.presentations.submit(request, sent), UNAVAILABLE);
      const sentBefore: number = posts.length;
      assert.deepEqual(await w.wallet.presentations.submit(request, other), { ok: false, code: 'REQUEST_INVALID' }, JSON.stringify(other));
      assert.deepEqual(await w.wallet.presentations.submit(request, sent), { ok: false, code: 'REQUEST_INVALID' }, 'forgotten');
      assert.deepEqual(w.wallet.presentations.decline(request), { ok: false, code: 'REQUEST_INVALID' });
      assert.equal(posts.length, sentBefore, 'nothing sent');
    }
    // Still a programming error to name a choice that was never offered.
    const request = await resolvedRequest(w, verifier);
    assert.deepEqual(await w.wallet.presentations.submit(request, sent), UNAVAILABLE);
    await assert.rejects(w.wallet.presentations.submit(request, { credentialId: first, claimSetIndex: 5 }), TypeError);
  });

  test(`at most MAX_PRESENTATION_SENDS (${MAX_PRESENTATION_SENDS}) sends per request: the last 503 is VERIFIER_ERROR and the request is forgotten`, async () => {
    assert.equal(MAX_PRESENTATION_SENDS, 3);
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const credentialId = await world.issueTo(w);
    const verifier = await world.newVerifier({ dpki: true });
    const posts = answerRegistryDown();
    const request = await resolvedRequest(w, verifier);
    for (let i = 1; i < MAX_PRESENTATION_SENDS; i++) assert.deepEqual(await w.wallet.presentations.submit(request, { credentialId, claimSetIndex: 1 }), UNAVAILABLE, `send ${i}`);
    assert.deepEqual(await w.wallet.presentations.submit(request, { credentialId, claimSetIndex: 1 }), { ok: false, code: 'VERIFIER_ERROR' });
    assert.deepEqual(await w.wallet.presentations.submit(request, { credentialId, claimSetIndex: 1 }), { ok: false, code: 'REQUEST_INVALID' });
    assert.equal(posts.length, MAX_PRESENTATION_SENDS);
  });

  test('declined (or submitted again) while the POST is in flight: not put back when the 503 arrives', async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const credentialId = await world.issueTo(w);
    const verifier = await world.newVerifier({ dpki: true });
    const choice = { credentialId, claimSetIndex: 1 };
    for (const touch of ['decline', 'submit'] as const) {
      const request = await resolvedRequest(w, verifier);
      let during: unknown;
      let posts = 0;
      listener.routes.set('POST /oid4vp/response/*', async () => {
        posts++;
        during = touch === 'decline' ? w.wallet.presentations.decline(request) : await w.wallet.presentations.submit(request, choice);
        return REGISTRY_DOWN;
      });
      assert.deepEqual(await w.wallet.presentations.submit(request, choice), { ok: false, code: 'VERIFIER_ERROR' }, touch);
      assert.deepEqual(during, { ok: false, code: 'REQUEST_INVALID' }, touch);
      assert.deepEqual(await w.wallet.presentations.submit(request, choice), { ok: false, code: 'REQUEST_INVALID' }, `${touch}: not put back`);
      assert.equal(posts, 1, touch);
    }
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

type Verifier = Awaited<ReturnType<World['newVerifier']>>;
const INVALID = { ok: false, code: 'REQUEST_INVALID' };
const VERIFIER_ERROR = { ok: false, code: 'VERIFIER_ERROR' };

/**
 * A verifier's fixed QR whose request URI serves, on every fetch, the request object of a NEW session
 * (new nonce, state and response_uri) signed with the real request certificate; `edit` rewrites the
 * credential query, `signer` signs it as another verifier (client_id of its certificate). What a
 * hostile verifier controls behind a QR it cannot change.
 */
const clientIdOf = async (signer: Signer) => `x509_hash:${base64UrlEncode(await webCryptoHasher.sha256(base64Decode(signer.x5c![0]!)))}`;
async function fixedQr(verifier: Verifier) {
  const clientId = new URLSearchParams((await newSession(verifier)).qr.split('?')[1]).get('client_id')!;
  const served = { fetches: 0, seen: new Set<string>(), edit: null as ((cq: Record<string, unknown[]>) => void) | null, signer: null as Signer | null };
  listener.routes.set('GET /oid4vp/request/fixed', async () => {
    served.fetches++;
    const r = (await verifier.requestObject((await newSession(verifier)).requestId))!;
    const p = JSON.parse(utf8Decode(base64UrlDecode(r.body.split('.')[1]!))) as Record<string, unknown> & { dcql_query: { credentials: Record<string, unknown[]>[] } };
    served.seen.add(JSON.stringify([p['nonce'], p['state'], p['response_uri']]));
    if (!served.edit && !served.signer) return r;
    served.edit?.(p.dcql_query.credentials[0]!);
    if (served.signer) p['client_id'] = await clientIdOf(served.signer);
    return { ...r, body: await signJws({ typ: 'oauth-authz-req+jwt' }, utf8Encode(JSON.stringify(p)), served.signer ?? (await leafSigner('request'))) };
  });
  const qr = `openid4vp://?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(`${ORIGIN}/oid4vp/request/fixed`)}`;
  return { qr, served, clientId };
}

/** A software key store whose signer() reads (where the platform prompts) are counted and can be held. */
function promptingKeyStore() {
  const inner = createSoftwareKeyStore({ secrets: createInMemorySecretStorage(), random: webCryptoRandom });
  const prompts = { count: 0, hold: null as Promise<void> | null };
  const keyStore: WalletKeyStore = {
    create: () => inner.create(),
    delete: (id) => inner.delete(id),
    async signer(id) {
      prompts.count++;
      await prompts.hold;
      return inner.signer(id);
    },
  };
  return { keyStore, prompts };
}

async function resolveQr(w: TestWallet, qr: string): Promise<ResolvedPresentation> {
  const r = await w.wallet.presentations.resolve(qr);
  assert.ok(r.ok, JSON.stringify(r));
  return r.request;
}

describe('a delivered request stays pinned in the wallet, whatever object resolve returns for it (same client_id, same request_uri)', () => {
  test('the re-review scenario: 5 resolves x 3 sends of one QR, every POST answered with the 503: MAX_PRESENTATION_SENDS POSTs, all of the first selection', async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const credentialId = await world.issueTo(w);
    const verifier = await world.newVerifier({ dpki: true });
    const posts = answerRegistryDown();
    const { qr } = await fixedQr(verifier);
    const results: string[] = [];
    for (let round = 0; round < 5; round++) {
      const r = await w.wallet.presentations.resolve(qr);
      for (let i = 0; i < 3; i++) {
        results.push(r.ok ? (await w.wallet.presentations.submit(r.request, { credentialId, claimSetIndex: round % 2 }) as { code?: string }).code ?? 'ok' : `resolve ${r.code}`);
      }
    }
    assert.deepEqual(results.slice(0, 4), ['DID_RESOLUTION_UNAVAILABLE', 'DID_RESOLUTION_UNAVAILABLE', 'VERIFIER_ERROR', 'resolve REQUEST_INVALID']);
    assert.ok(results.slice(3).every((r) => r === 'resolve REQUEST_INVALID'), results.join());
    assert.equal(posts.length, MAX_PRESENTATION_SENDS);
    assert.equal(new Set(posts.map((b) => b.length)).size, 1, 'the same claims each time');
  });

  test('one send per resolve, alternating claim sets: only the first selection is sent, more or fewer claims are refused', async () => {
    const lengths: number[] = [];
    for (const first of [1, 0]) {
      const world = await createWorld(listener, { did: {} });
      const w = world.newDidWallet();
      const credentialId = await world.issueTo(w);
      const verifier = await world.newVerifier({ dpki: true });
      const posts = answerRegistryDown();
      const { qr } = await fixedQr(verifier);
      const results: unknown[] = [];
      for (let round = 0; round < 6; round++) {
        const r = await w.wallet.presentations.resolve(qr);
        results.push(r.ok ? await w.wallet.presentations.submit(r.request, { credentialId, claimSetIndex: (first + round) % 2 }) : r);
      }
      assert.deepEqual(results, [UNAVAILABLE, INVALID, UNAVAILABLE, INVALID, VERIFIER_ERROR, INVALID], `first ${first}`);
      assert.equal(posts.length, MAX_PRESENTATION_SENDS);
      assert.equal(new Set(posts.map((b) => b.length)).size, 1);
      lengths.push(posts[0]!.length);
    }
    assert.notEqual(lengths[0], lengths[1], 'the two claim sets are told apart by the POST size');
  });

  test('re-resolved: pinned, with the count carried over; another claim set or credential is refused before any prompt and sends nothing; used up: REQUEST_INVALID without a fetch', async () => {
    const world = await createWorld(listener, { did: {} });
    const { keyStore, prompts } = promptingKeyStore();
    const w = world.newDidWallet({ keyStore });
    const first = await world.issueTo(w);
    const second = await world.issueTo(w);
    const verifier = await world.newVerifier({ dpki: true });
    const posts = answerRegistryDown();
    const { qr, served } = await fixedQr(verifier);
    const sent = { credentialId: first, claimSetIndex: 1 };
    const submit = (r: ResolvedPresentation, c: typeof sent) => w.wallet.presentations.submit(r, c);

    const r1 = await resolveQr(w, qr);
    assert.equal(r1.pinned, null);
    assert.deepEqual(await submit(r1, sent), UNAVAILABLE);
    const r2 = await resolveQr(w, qr);
    assert.deepEqual(r2.pinned, { ...sent, sends: 1 });
    assert.ok(Date.parse(r2.expiresAt) > world.clock.now().getTime());
    for (const other of [{ credentialId: first, claimSetIndex: 0 }, { credentialId: second, claimSetIndex: 1 }]) {
      const r = await resolveQr(w, qr);
      assert.deepEqual(r.pinned, { ...sent, sends: 1 });
      const before = prompts.count;
      assert.deepEqual(await submit(r, other), INVALID, JSON.stringify(other));
      assert.equal(prompts.count, before, 'refused before the prompt');
      assert.deepEqual(await submit(r, sent), INVALID, 'that object is forgotten');
    }
    assert.equal(posts.length, 1);
    assert.deepEqual(await submit(r2, sent), UNAVAILABLE, 'the second send, from an object resolved while pinned');
    const r3 = await resolveQr(w, qr);
    const stale = await resolveQr(w, qr);
    assert.deepEqual([r3.pinned, stale.pinned], [{ ...sent, sends: 2 }, { ...sent, sends: 2 }]);
    assert.deepEqual(await submit(r3, sent), VERIFIER_ERROR, 'the third send: the last 503 is the verifier error');
    assert.deepEqual(await submit(stale, sent), INVALID, 'resolved before the bound was reached: nothing more');
    assert.deepEqual(await submit(r1, sent), INVALID, 'the first object too');
    assert.equal(posts.length, MAX_PRESENTATION_SENDS);
    const fetches = served.fetches;
    assert.deepEqual(await w.wallet.presentations.resolve(qr), INVALID);
    assert.equal(served.fetches, fetches, 'used up: not fetched again');
    assert.equal(served.seen.size, served.fetches, 'nonce, state and response_uri changed on every fetch');
  });

  test('objects resolved before the delivery obey it, also one being signed when it happens; decline lifts nothing; two objects never send at once', async () => {
    const world = await createWorld(listener, { did: {} });
    const { keyStore, prompts } = promptingKeyStore();
    const w = world.newDidWallet({ keyStore });
    const credentialId = await world.issueTo(w);
    const verifier = await world.newVerifier({ dpki: true });
    const posts = answerRegistryDown();
    const { qr } = await fixedQr(verifier);
    const narrow = { credentialId, claimSetIndex: 1 };
    const broad = { credentialId, claimSetIndex: 0 };
    const [a, b, c] = [await resolveQr(w, qr), await resolveQr(w, qr), await resolveQr(w, qr)];

    // c is at its prompt while a is delivered.
    let release!: () => void;
    prompts.hold = new Promise((r) => (release = r));
    const before = prompts.count;
    const signing = w.wallet.presentations.submit(c, broad);
    while (prompts.count === before) await new Promise((r) => setImmediate(r));
    prompts.hold = null;
    assert.deepEqual(await w.wallet.presentations.submit(a, narrow), UNAVAILABLE);
    release();
    assert.deepEqual(await signing, INVALID);
    assert.deepEqual(await w.wallet.presentations.submit(b, broad), INVALID, 'resolved before the delivery');
    assert.equal(posts.length, 1);

    assert.deepEqual(w.wallet.presentations.decline(a), { ok: true });
    const d = await resolveQr(w, qr);
    assert.deepEqual(d.pinned, { ...narrow, sends: 1 }, 'declining and scanning again unlocks nothing');
    assert.deepEqual(await w.wallet.presentations.submit(d, broad), INVALID);

    // Two objects submitted at once: one POST; the other is refused.
    const [e, f] = [await resolveQr(w, qr), await resolveQr(w, qr)];
    listener.routes.set('POST /oid4vp/response/*', async (req) => {
      posts.push(req.body);
      await new Promise((r) => setTimeout(r, 100));
      return REGISTRY_DOWN;
    });
    const both = await Promise.all([w.wallet.presentations.submit(e, narrow), w.wallet.presentations.submit(f, narrow)]);
    assert.deepEqual(both.map((r) => (r as { code: string }).code).sort(), ['DID_RESOLUTION_UNAVAILABLE', 'REQUEST_INVALID']);
    assert.equal(posts.length, 2);
    assert.deepEqual((await resolveQr(w, qr)).pinned, { ...narrow, sends: 2 });
  });

  test('the verifier changes what the pinned claim set asks for, or the credential is gone: REQUEST_INVALID, nothing sent', async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const credentialId = await world.issueTo(w);
    const verifier = await world.newVerifier({ dpki: true });
    const posts = answerRegistryDown();
    const { qr, served } = await fixedQr(verifier);
    const sent = { credentialId, claimSetIndex: 1 };
    // Index 1 asks for three claims instead of two.
    const widen = (cq: Record<string, unknown[]>) => (cq['claim_sets'] = [cq['claim_sets']![0], (cq['claim_sets']![0] as unknown[]).slice(0, 3)]);
    served.edit = widen;
    const early = await resolveQr(w, qr);
    assert.deepEqual(early.matches[0]!.claimSets[1]!.claims.length, 3);
    served.edit = null;
    assert.deepEqual(await w.wallet.presentations.submit(await resolveQr(w, qr), sent), UNAVAILABLE);
    assert.deepEqual(await w.wallet.presentations.submit(early, sent), INVALID, 'resolved before the delivery, other claims under the same index');
    served.edit = widen;
    assert.deepEqual(await w.wallet.presentations.resolve(qr), INVALID);
    // Index 1 asks for two claims again, but the two that were not sent.
    served.edit = (cq) => {
      const [all, sentIds] = cq['claim_sets'] as unknown[][];
      cq['claim_sets'] = [all, all!.filter((id) => !sentIds!.includes(id))];
    };
    assert.equal((await w.wallet.presentations.resolve(qr) as { code?: string }).code, 'REQUEST_INVALID');
    served.edit = null;
    assert.deepEqual((await resolveQr(w, qr)).pinned, { ...sent, sends: 1 });
    assert.deepEqual(await w.wallet.credentials.remove(credentialId), { ok: true });
    assert.deepEqual(await w.wallet.presentations.resolve(qr), INVALID, 'the pinned credential is no longer offered');
    assert.equal(posts.length, 1);
  });

  test('scope: another request URI of the same verifier, another wallet instance and another client_id are not pinned by it', async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const credentialId = await world.issueTo(w);
    const verifier = await world.newVerifier({ dpki: true });
    const posts = answerRegistryDown();
    const { qr, clientId, served } = await fixedQr(verifier);
    assert.deepEqual(await w.wallet.presentations.submit(await resolveQr(w, qr), { credentialId, claimSetIndex: 1 }), UNAVAILABLE);
    const fresh = await resolvedRequest(w, verifier);
    assert.equal(fresh.pinned, null, 'a new QR of the same verifier');
    assert.deepEqual(await w.wallet.presentations.submit(fresh, { credentialId, claimSetIndex: 0 }), UNAVAILABLE);
    // The memory is per wallet instance (documented): a wallet restarted on the same storage starts afresh.
    const restarted = world.newDidWallet({ keyStore: w.keyStore, vault: w.vault });
    assert.equal((await resolveQr(restarted, qr)).pinned, null);
    // The same request URI under another client_id: refuted by the request object's certificate...
    const other = (id: string) => qr.replace(encodeURIComponent(clientId), encodeURIComponent(id));
    assert.deepEqual(await w.wallet.presentations.resolve(other(`x509_hash:${'A'.repeat(43)}`)), { ok: false, code: 'CLIENT_ID_MISMATCH' });
    // ...or another verifier identity (here an untrusted one) serving that URI: another request, shown under its own name.
    served.signer = await leafSigner('vc');
    const elsewhere = await resolveQr(w, other(await clientIdOf(served.signer)));
    assert.deepEqual([elsewhere.verifier, elsewhere.pinned], [{ trusted: false }, null]);
    assert.deepEqual(await w.wallet.presentations.submit(elsewhere, { credentialId, claimSetIndex: 0, allowUntrusted: true }), UNAVAILABLE);
    assert.equal(posts.length, 3);
    served.signer = null;
    assert.deepEqual((await resolveQr(w, qr)).pinned, { credentialId, claimSetIndex: 1, sends: 1 }, 'the first one is still pinned');
  });

  test('declined while the POST is in flight: that object is gone, the request is still pinned to what the verifier received', async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const credentialId = await world.issueTo(w);
    const verifier = await world.newVerifier({ dpki: true });
    const { qr } = await fixedQr(verifier);
    const narrow = { credentialId, claimSetIndex: 1 };
    const request = await resolveQr(w, qr);
    let posts = 0;
    listener.routes.set('POST /oid4vp/response/*', async () => (posts++, w.wallet.presentations.decline(request), REGISTRY_DOWN));
    assert.deepEqual(await w.wallet.presentations.submit(request, narrow), VERIFIER_ERROR);
    assert.deepEqual(await w.wallet.presentations.submit(request, narrow), INVALID);
    const again = await resolveQr(w, qr);
    assert.deepEqual(again.pinned, { ...narrow, sends: 1 });
    assert.deepEqual(await w.wallet.presentations.submit(again, { credentialId, claimSetIndex: 0 }), INVALID);
    assert.equal(posts, 1);
  });

  test(`a pin lives ${600} s from the delivery (MAX_REQUEST_SECONDS); a request resolved while pinned expires with it; afterwards the QR resolves afresh`, async () => {
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const credentialId = await world.issueTo(w);
    const verifier = await world.newVerifier({ dpki: true });
    const posts = answerRegistryDown();
    const { qr } = await fixedQr(verifier);
    const narrow = { credentialId, claimSetIndex: 1 };
    assert.deepEqual(await w.wallet.presentations.submit(await resolveQr(w, qr), narrow), UNAVAILABLE);
    const delivered = world.clock.now().getTime();
    world.clock.advance(590);
    const late = await resolveQr(w, qr);
    assert.deepEqual(late.pinned, { ...narrow, sends: 1 });
    assert.equal(late.expiresAt, new Date(delivered + 600_000).toISOString(), 'its own exp would be 300 s later');
    world.clock.advance(9);
    assert.deepEqual((await resolveQr(w, qr)).pinned, { ...narrow, sends: 1 });
    world.clock.advance(1);
    assert.deepEqual(await w.wallet.presentations.submit(late, narrow), { ok: false, code: 'REQUEST_EXPIRED' });
    const after = await resolveQr(w, qr);
    assert.equal(after.pinned, null);
    assert.deepEqual(await w.wallet.presentations.submit(after, { credentialId, claimSetIndex: 0 }), UNAVAILABLE);
    assert.equal(posts.length, 2);
  });

  test(`at most MAX_PRESENTATION_PINS (${MAX_PRESENTATION_PINS}) live pins: the next such 503 is VERIFIER_ERROR and not kept; expired pins make room`, async () => {
    assert.equal(MAX_PRESENTATION_PINS, 32);
    const world = await createWorld(listener, { did: {} });
    const w = world.newDidWallet();
    const credentialId = await world.issueTo(w);
    const verifier = await world.newVerifier({ dpki: true });
    const posts = answerRegistryDown();
    const choice = { credentialId, claimSetIndex: 1 };
    for (let i = 0; i < MAX_PRESENTATION_PINS; i++) assert.deepEqual(await w.wallet.presentations.submit(await resolvedRequest(w, verifier), choice), UNAVAILABLE, `pin ${i}`);
    const over = await resolvedRequest(w, verifier);
    assert.deepEqual(await w.wallet.presentations.submit(over, choice), VERIFIER_ERROR);
    assert.deepEqual(await w.wallet.presentations.submit(over, choice), INVALID);
    assert.equal(posts.length, MAX_PRESENTATION_PINS + 1);
    world.clock.advance(600);
    assert.deepEqual(await w.wallet.presentations.submit(await resolvedRequest(w, verifier), choice), UNAVAILABLE);
  });
});

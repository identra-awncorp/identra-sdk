// What the wallet sends on the network and how much it reads (GĐ5 review F3, F6): per-call size caps,
// a streamed body cut at the cap, a stalled body aborted at the timeout, hosts it never contacts and
// the allowedOrigins pin. Listener 127.0.0.1:47644, raw server 127.0.0.1:47645.
import assert from 'node:assert/strict';
import http from 'node:http';
import { after, before, describe, test } from 'node:test';
import { createMappedFetch, type HttpFetch } from '@identra/sdk-core';
import { guardFetch } from '../dist/wallet/fetch.js';
import { createWorld, fetchStats, nodeHttpFetch, ORIGIN, startListener, type Listener } from './helpers/world.js';

let listener: Listener;
let raw: http.Server;
let mode: 'big' | 'drip' = 'big';
let closed = 0;
before(async () => {
  listener = await startListener(47644);
  raw = http.createServer((req, res) => {
    req.on('close', () => closed++);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    if (mode === 'drip') {
      const t = setInterval(() => res.write('a'), 50);
      res.on('close', () => clearInterval(t));
      return;
    }
    // 200 MB, chunked (no Content-Length), as fast as the client reads.
    const chunk = Buffer.alloc(1 << 20, 0x61);
    let n = 0;
    const pump = () => {
      while (n < 200) {
        n++;
        if (!res.write(chunk)) return void res.once('drain', pump);
      }
      res.end();
    };
    res.on('close', () => (n = 200));
    pump();
  });
  await new Promise<void>((r) => raw.listen(47645, '127.0.0.1', r));
});
after(async () => {
  raw.closeAllConnections();
  await new Promise((r) => raw.close(r));
  await listener.close();
});

describe('response size and time', () => {
  test('every wallet request carries its own cap (issuance and presentation)', async () => {
    const world = await createWorld(listener);
    const verifier = await world.newVerifier();
    const seen: [string, number | undefined][] = [];
    const recording: HttpFetch = (url, init) => (seen.push([`${init?.method ?? 'GET'} ${url.slice(listener.localOrigin.length).replace(/\/[A-Za-z0-9_-]{22}$/, '/:id')}`, init?.maxBytes]), nodeHttpFetch(url, init));
    const w = world.newWallet('noble', createMappedFetch(recording, { [ORIGIN]: listener.localOrigin }));
    const credentialId = await world.issueTo(w);
    const request = await w.wallet.presentations.resolve((await verifier.createSession({ scenario: 'ung-tuyen' }))!.qr);
    assert.ok(request.ok);
    assert.deepEqual(await w.wallet.presentations.submit(request.request, { credentialId, claimSetIndex: 1 }), { ok: true });
    assert.deepEqual(Object.fromEntries(seen), {
      'GET /issuers/truong-mau/offers/:id': 65_536,
      'GET /.well-known/openid-credential-issuer/issuers/truong-mau': 65_536,
      'GET /.well-known/oauth-authorization-server/issuers/truong-mau': 65_536,
      'POST /issuers/truong-mau/token': 16_384,
      'POST /issuers/truong-mau/nonce': 16_384,
      'POST /issuers/truong-mau/credential': 65_536,
      'GET /trust-list': 262_144,
      'GET /issuers/truong-mau/status/1': 131_072,
      'GET /oid4vp/request/:id': 65_536,
      'POST /oid4vp/response/:id': 16_384,
    });
  });

  test('a 200 MB chunked body stops being read just past the cap', async () => {
    mode = 'big';
    const world = await createWorld(listener);
    const w = world.newWallet('noble', createMappedFetch(nodeHttpFetch, { [ORIGIN]: 'http://127.0.0.1:47645' }));
    const before = fetchStats.bytesRead;
    const started = Date.now();
    const r = await w.wallet.offers.resolve(`openid-credential-offer://?credential_offer_uri=${encodeURIComponent(`${ORIGIN}/issuers/truong-mau/offers/AAAAAAAAAAAAAAAAAAAAAA`)}`);
    assert.equal(r.ok, false);
    const read = fetchStats.bytesRead - before;
    assert.ok(read > 65_536 && read < 65_536 + (2 << 20), `read ${read} bytes`);
    assert.ok(Date.now() - started < 3000);
  });

  test('a body that trickles is aborted at the timeout, and the connection is dropped', async () => {
    mode = 'drip';
    const closedBefore = closed;
    // Through the mapping the guard sees a canonical URL and the test fetch reaches the raw server.
    const mapped = guardFetch(createMappedFetch(nodeHttpFetch, { [ORIGIN]: 'http://127.0.0.1:47645' }), { allow: () => true, timeoutMs: 300 });
    const t0 = Date.now();
    await assert.rejects(mapped(`${ORIGIN}/x`), (e: unknown) => (e as { code?: string }).code === 'NETWORK_ERROR');
    assert.ok(Date.now() - t0 < 1500);
    await new Promise((r) => setTimeout(r, 200));
    assert.ok(closed > closedBefore, 'the server saw the request end');
  });
});

describe('hosts the wallet never contacts', () => {
  const offerQr = (origin: string) => `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(`${origin}/issuers/truong-mau/offers/AAAAAAAAAAAAAAAAAAAAAA`)}`;
  const vpQr = (origin: string) => `openid4vp://?client_id=x509_hash%3A${'A'.repeat(43)}&request_uri=${encodeURIComponent(`${origin}/oid4vp/request/AAAAAAAAAAAAAAAAAAAAAA`)}`;

  test('IP literals, localhost, hosts without a dot or ending in one; allowedOrigins pins the rest', async () => {
    const world = await createWorld(listener);
    const contacted: string[] = [];
    const recording = createMappedFetch((url, init) => (contacted.push(url), nodeHttpFetch(url, init)), { [ORIGIN]: listener.localOrigin });
    const open = world.newWallet('noble', recording);
    for (const origin of ['https://127.0.0.1', 'https://[::1]', 'https://0x7f.1', 'https://localhost', 'https://api.localhost', 'https://intranet', 'https://api-identra.awncorp.vn.']) {
      assert.deepEqual(await open.wallet.offers.resolve(offerQr(origin)), { ok: false, code: 'URL_NOT_ALLOWED' }, origin);
      assert.deepEqual(await open.wallet.presentations.resolve(vpQr(origin)), { ok: false, code: 'URL_NOT_ALLOWED' }, origin);
    }
    const pinned = world.newWallet('noble', recording, undefined, { allowedOrigins: [ORIGIN] });
    assert.deepEqual(await pinned.wallet.offers.resolve(offerQr('https://issuer.example')), { ok: false, code: 'URL_NOT_ALLOWED' });
    assert.deepEqual(await pinned.wallet.presentations.resolve(vpQr('https://verifier.example')), { ok: false, code: 'URL_NOT_ALLOWED' });
    assert.deepEqual(contacted, []);
    const r = await pinned.wallet.offers.resolve((await world.offer()).offerUri);
    assert.equal(r.ok && r.offer.issuerOrigin, ORIGIN);
    for (const bad of [['https://api-identra.awncorp.vn/'], ['http://api-identra.awncorp.vn'], ['https://127.0.0.1']]) {
      assert.throws(() => world.newWallet('noble', recording, undefined, { allowedOrigins: bad }), TypeError, bad[0]);
    }
  });
});

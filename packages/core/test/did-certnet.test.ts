// The did:certnet resolver and the CertNet trust registry (ADR-0020 sections 4, 5 and 9) against a
// scripted gateway whose answers follow the CertNet contract of 25/11 (4-openapi.yaml).
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  createCertNetDidResolver, createCertNetTrustRegistry, createMappedFetch, DID_CERTNET_ERRORS, isCertNetDid, isDidStatusListUri,
  TrustListUnavailableError, VCT, type DidResolutionResult,
} from '@identra/sdk-core';
import { NOW } from './helpers/pki.js';
import { fakeClock, ok, scriptedFetch, type Route } from './helpers/lists.js';
import { DID, didBody, didUrl, GATEWAY, KID, json, OTHER_DID, tirBody, tirUrl } from './helpers/dpki.js';

function resolverWith(routes: Record<string, Route | (() => Route)>, o: { cacheSeconds?: number; clock?: ReturnType<typeof fakeClock>; maxEntries?: number } = {}) {
  const clock = o.clock ?? fakeClock();
  const s = scriptedFetch(routes);
  const resolver = createCertNetDidResolver({
    gatewayUrl: GATEWAY, network: 'local', fetch: s.fetch, clock,
    ...(o.cacheSeconds !== undefined ? { cacheSeconds: o.cacheSeconds } : {}), ...(o.maxEntries !== undefined ? { maxEntries: o.maxEntries } : {}),
  });
  return { resolver, clock, ...s };
}
const errorOf = (r: DidResolutionResult) => r.didResolutionMetadata.error ?? null;

describe('did:certnet resolver', () => {
  test('resolves a contract-shaped answer with one GET of the encoded DID (5 s, 64 KiB)', async () => {
    const w = resolverWith({ [didUrl(DID)]: json(didBody()) });
    const r = await w.resolver.resolve(DID);
    assert.equal(errorOf(r), null);
    assert.equal(r.didDocument?.id, DID);
    assert.deepEqual(r.didDocument?.assertionMethod, [KID]);
    assert.deepEqual(w.calls, [{ url: `${GATEWAY}/v1/dids/did%3Acertnet%3Alocal%3Aa1b2c3d4e5f67890`, timeoutMs: 5000, maxBytes: 65_536 }]);
  });

  test('refuses, before any request, DIDs that are not did:certnet of the configured network', async () => {
    const w = resolverWith({});
    for (const did of ['did:certnet:a1b2', 'did:certnet:devnet:a1b2', 'did:certnet:local:', 'did:certnet:local:a.b', 'did:certnet:local:a%3Ab', 'did:certnet:local:a b',
      'did:certnet:local:ab#key-1', 'did:web:example.com', 'did:certnet:testnet:a1b2', 'did:certnet:mainnet:a1b2', 42, undefined]) {
      assert.equal(errorOf(await w.resolver.resolve(did as string)), DID_CERTNET_ERRORS.invalidDid, String(did));
    }
    assert.equal(w.calls.length, 0);
    assert.equal(isCertNetDid('did:certnet:testnet:z6MkSampleResolver001'), true);
    assert.equal(isCertNetDid('did:certnet:testnet:z6MkSampleResolver001', 'local'), false);
  });

  test('versionTime is an explicit failure, never ignored, and makes no request', async () => {
    const w = resolverWith({ [didUrl(DID)]: json(didBody()) });
    const r = await w.resolver.resolve(DID, { versionTime: '2026-11-01T00:00:00Z' });
    assert.equal(errorOf(r), DID_CERTNET_ERRORS.versionTimeNotSupported);
    assert.equal(r.didDocument, null);
    assert.equal(w.calls.length, 0);
  });

  test('404, 410 and 422 are definitive failures', async () => {
    for (const [status, error] of [[404, DID_CERTNET_ERRORS.notFound], [410, DID_CERTNET_ERRORS.deactivated], [422, DID_CERTNET_ERRORS.invalidDid]] as const) {
      const w = resolverWith({ [didUrl(DID)]: { status, body: JSON.stringify({ code: 'DID_NOT_FOUND', message: 'x' }) } });
      assert.equal(errorOf(await w.resolver.resolve(DID)), error, String(status));
    }
  });

  test('5xx, other statuses, timeout, rejection, oversized and non-JSON bodies are "temporarily unavailable"', async () => {
    const answers: Route[] = [
      { status: 503, body: '{"code":"CHAIN_UNAVAILABLE","message":"x"}' }, { status: 500, body: '' }, { status: 501, body: '' },
      { status: 302, body: '' }, { status: 201, body: JSON.stringify(didBody()) }, { status: 400, body: '' },
      new Error('timeout after 5000 ms'), new Error('ECONNREFUSED'),
      ok(JSON.stringify({ ...didBody(), pad: 'a'.repeat(65_536) })), ok('ứ'.repeat(30_000)), ok('<html>'), ok(''),
    ];
    for (const a of answers) {
      const w = resolverWith({ [didUrl(DID)]: a });
      const r = await w.resolver.resolve(DID);
      assert.equal(errorOf(r), DID_CERTNET_ERRORS.unavailable, a instanceof Error ? a.message : `${a.status} ${a.body.slice(0, 20)}`);
      assert.equal(r.didDocument, null);
    }
  });

  test('a 200 JSON answer that breaks the contract is a definitive failure', async () => {
    const vm = didBody().document.verificationMethod[0]!;
    const broken: [string, unknown][] = [
      ['not an object', [didBody()]],
      ['did of another DID', didBody({ top: { did: OTHER_DID } })],
      ['did missing', didBody({ top: { did: undefined } })],
      ['document.id of another DID', didBody({ document: { id: OTHER_DID } })],
      ['document missing', didBody({ top: { document: undefined } })],
      ['verificationMethod missing', didBody({ document: { verificationMethod: undefined } })],
      ['method controlled by another DID', didBody({ document: { verificationMethod: [{ ...vm, controller: OTHER_DID }] } })],
      ['method id of another DID', didBody({ document: { verificationMethod: [{ ...vm, id: `${OTHER_DID}#key-1` }] } })],
      ['method id equal to the DID', didBody({ document: { verificationMethod: [{ ...vm, id: DID }] } })],
      ['a second foreign method', didBody({ document: { verificationMethod: [vm, { ...vm, id: `${DID}#key-2`, controller: OTHER_DID }] } })],
      ['method without publicKeyJwk', didBody({ document: { verificationMethod: [{ ...vm, publicKeyJwk: undefined }] } })],
      ['method without type', didBody({ document: { verificationMethod: [{ ...vm, type: undefined }] } })],
      ['two methods with one id', didBody({ document: { verificationMethod: [vm, vm] } })],
      ['assertionMethod not a list of strings', didBody({ document: { assertionMethod: KID } })],
      ['authentication with an object', didBody({ document: { authentication: [{ id: KID }] } })],
      ['@context a string', didBody({ document: { '@context': 'https://www.w3.org/ns/did/v1' } })],
      ['metadata not an object', didBody({ top: { metadata: 'deactivated' } })],
      ['metadata.deactivated not a boolean', didBody({ metadata: { deactivated: 'true' } })],
    ];
    for (const [name, body] of broken) {
      const w = resolverWith({ [didUrl(DID)]: json(body) });
      assert.equal(errorOf(await w.resolver.resolve(DID)), DID_CERTNET_ERRORS.invalidDidDocument, name);
    }
    const w = resolverWith({ [didUrl(DID)]: json(didBody({ metadata: { deactivated: true } })) });
    assert.equal(errorOf(await w.resolver.resolve(DID)), DID_CERTNET_ERRORS.deactivated, 'metadata.deactivated');
  });

  test('gateway URL with a path prefix, and the development origin mapping', async () => {
    const s = scriptedFetch({ [`http://127.0.0.1:8000/certnet/v1/dids/${encodeURIComponent(DID)}`]: json(didBody()) });
    const fetch = createMappedFetch(s.fetch, { 'https://gateway.certnet.test': 'http://127.0.0.1:8000' });
    const resolver = createCertNetDidResolver({ gatewayUrl: `${GATEWAY}/certnet/`, network: 'local', fetch, clock: fakeClock() });
    assert.equal(errorOf(await resolver.resolve(DID)), null);
  });

  test('bad options are TypeErrors', () => {
    const base = { gatewayUrl: GATEWAY, network: 'local' as const, fetch: scriptedFetch({}).fetch, clock: fakeClock() };
    for (const gatewayUrl of ['http://gateway.certnet.test', 'https://gateway.certnet.test?x=1', 'https://gateway.certnet.test#f', 'https://u@gateway.certnet.test',
      'https://gateway.certnet.test/a/../b', 'https://gateway.certnet.test/%2e', 'gateway.certnet.test', '']) {
      assert.throws(() => createCertNetDidResolver({ ...base, gatewayUrl }), TypeError, gatewayUrl);
      assert.throws(() => createCertNetTrustRegistry({ ...base, gatewayUrl }), TypeError, gatewayUrl);
    }
    assert.throws(() => createCertNetDidResolver({ ...base, network: 'devnet' as never }), TypeError);
    assert.throws(() => createCertNetDidResolver({ ...base, cacheSeconds: 301 }), TypeError);
    assert.throws(() => createCertNetDidResolver({ ...base, cacheSeconds: -1 }), TypeError);
    assert.throws(() => createCertNetDidResolver({ ...base, clock: undefined as never }), TypeError);
    assert.throws(() => createCertNetDidResolver({ ...base, maxEntries: 0 }), TypeError);
  });
});

describe('did:certnet resolver cache', () => {
  test('a second resolution within 60 s makes no request; after 60 s it does', async () => {
    const w = resolverWith({ [didUrl(DID)]: json(didBody()) });
    await w.resolver.resolve(DID);
    w.clock.advance(59);
    assert.equal(errorOf(await w.resolver.resolve(DID)), null);
    assert.equal(w.calls.length, 1);
    w.clock.advance(1);
    await w.resolver.resolve(DID);
    assert.equal(w.calls.length, 2);
  });

  test('failures are never cached: 404 then 200, 503 then 200', async () => {
    for (const first of [{ status: 404, body: '' }, { status: 503, body: '' }]) {
      const w = resolverWith({ [didUrl(DID)]: first });
      assert.notEqual(errorOf(await w.resolver.resolve(DID)), null);
      w.routes[didUrl(DID)] = json(didBody());
      assert.equal(errorOf(await w.resolver.resolve(DID)), null);
      assert.equal(w.calls.length, 2);
    }
  });

  test('a clock stepped back makes the entry stale; cacheSeconds bounds the age; 0 disables the cache', async () => {
    const w = resolverWith({ [didUrl(DID)]: json(didBody()) });
    await w.resolver.resolve(DID);
    w.clock.advance(-1);
    await w.resolver.resolve(DID);
    assert.equal(w.calls.length, 2, 'stepped back');
    const capped = resolverWith({ [didUrl(DID)]: json(didBody()) }, { cacheSeconds: 300 });
    await capped.resolver.resolve(DID);
    capped.clock.advance(299);
    await capped.resolver.resolve(DID);
    capped.clock.advance(1);
    await capped.resolver.resolve(DID);
    assert.equal(capped.calls.length, 2, '300 s');
    const none = resolverWith({ [didUrl(DID)]: json(didBody()) }, { cacheSeconds: 0 });
    await none.resolver.resolve(DID);
    await none.resolver.resolve(DID);
    assert.equal(none.calls.length, 2, 'no cache');
  });

  test('callers get copies: changing a result does not change the cache', async () => {
    const w = resolverWith({ [didUrl(DID)]: json(didBody()) });
    const first = await w.resolver.resolve(DID);
    first.didDocument!.assertionMethod!.push(`${DID}#evil`);
    assert.deepEqual((await w.resolver.resolve(DID)).didDocument!.assertionMethod, [KID]);
  });

  test('concurrent resolutions of one uncached DID share one request; a shared failure is not cached', async () => {
    const w = resolverWith({ [didUrl(DID)]: json(didBody()), [didUrl(OTHER_DID)]: json(didBody({ did: OTHER_DID })) });
    const results = await Promise.all([w.resolver.resolve(DID), w.resolver.resolve(DID), w.resolver.resolve(DID), w.resolver.resolve(OTHER_DID)]);
    assert.deepEqual(results.map(errorOf), [null, null, null, null]);
    assert.equal(w.calls.length, 2, 'one request per DID');
    results[0]!.didDocument!.assertionMethod!.push(`${DID}#evil`);
    assert.deepEqual(results[1]!.didDocument!.assertionMethod, [KID], 'each caller still gets its own copy');
    const down = resolverWith({ [didUrl(DID)]: { status: 503, body: '' } });
    const failed = await Promise.all([down.resolver.resolve(DID), down.resolver.resolve(DID)]);
    assert.deepEqual(failed.map(errorOf), [DID_CERTNET_ERRORS.unavailable, DID_CERTNET_ERRORS.unavailable]);
    assert.equal(down.calls.length, 1);
    down.routes[didUrl(DID)] = json(didBody());
    assert.equal(errorOf(await down.resolver.resolve(DID)), null);
    assert.equal(down.calls.length, 2, 'the failure was not cached');
  });

  test('the least recently used DID is dropped first: one in constant use stays cached', async () => {
    const THIRD = 'did:certnet:local:third0001';
    const w = resolverWith({ [didUrl(DID)]: json(didBody()), [didUrl(OTHER_DID)]: json(didBody({ did: OTHER_DID })), [didUrl(THIRD)]: json(didBody({ did: THIRD })) }, { maxEntries: 2 });
    await w.resolver.resolve(DID);
    await w.resolver.resolve(OTHER_DID);
    await w.resolver.resolve(DID); // a hit: DID is now the most recently used
    await w.resolver.resolve(THIRD); // full: drops OTHER_DID, not DID
    await w.resolver.resolve(DID);
    assert.equal(w.calls.length, 3, 'DID still cached');
    await w.resolver.resolve(OTHER_DID);
    assert.equal(w.calls.length, 4, 'OTHER_DID was dropped');
  });

  test('at most maxEntries DIDs are held', async () => {
    const w = resolverWith({ [didUrl(DID)]: json(didBody()), [didUrl(OTHER_DID)]: json(didBody({ did: OTHER_DID })) }, { maxEntries: 1 });
    await w.resolver.resolve(DID);
    await w.resolver.resolve(OTHER_DID);
    await w.resolver.resolve(DID);
    assert.equal(w.calls.length, 3);
  });
});

describe('CertNet trust registry', () => {
  const registryWith = (routes: Record<string, Route | (() => Route)>) => {
    const s = scriptedFetch(routes);
    return { registry: createCertNetTrustRegistry({ gatewayUrl: GATEWAY, network: 'local', fetch: s.fetch }), ...s };
  };
  const lookup = (body: unknown, at = NOW, vct: string = VCT.diploma) => registryWith({ [tirUrl(DID, vct)]: json(body) }).registry.lookupIssuer(DID, vct, at);
  const s = (ms: number) => new Date(NOW.getTime() + ms).toISOString();

  test('a recognised issuer for exactly this vct, with one GET of the encoded DID and vcType', async () => {
    const w = registryWith({ [tirUrl(DID)]: json(tirBody()) });
    assert.deepEqual(await w.registry.lookupIssuer(DID, VCT.diploma, NOW), { trusted: true });
    assert.deepEqual(w.calls, [{ url: `${GATEWAY}/v1/trust-registry/issuers/did%3Acertnet%3Alocal%3Aa1b2c3d4e5f67890?vcType=https%3A%2F%2Fidentra.awncorp.vn%2Fvct%2Fbang-tot-nghiep%2Fv1`, timeoutMs: 5000, maxBytes: 65_536 }]);
  });

  test('not trusted: 404, rejected, another type, vct compared exactly, no vcTypes', async () => {
    assert.equal((await registryWith({ [tirUrl(DID)]: { status: 404, body: '{"code":"ISSUER_NOT_FOUND","message":"x"}' } }).registry.lookupIssuer(DID, VCT.diploma, NOW)).trusted, false);
    for (const patch of [{ recognition: 'rejected', reason: 'withdrawn' }, { vcTypes: ['UniversityDegreeCredential'] }, { vcTypes: [`${VCT.diploma}/x`] },
      { vcTypes: [VCT.diploma.toUpperCase()] }, { vcTypes: [] }, { vcTypes: undefined }]) {
      assert.equal((await lookup(tirBody(patch))).trusted, false, JSON.stringify(patch));
    }
  });

  test('the validity window, when present and not null, with 60 s skew', async () => {
    assert.equal((await lookup(tirBody({ validFrom: null, validUntil: null }))).trusted, true);
    assert.equal((await lookup(tirBody({ validFrom: s(60_000), validUntil: s(3600_000) }))).trusted, true, 'starts within the skew');
    assert.equal((await lookup(tirBody({ validFrom: s(61_000) }))).trusted, false, 'not yet valid');
    assert.equal((await lookup(tirBody({ validUntil: s(-60_000) }))).trusted, true, 'ended within the skew');
    assert.equal((await lookup(tirBody({ validUntil: s(-61_000) }))).trusted, false, 'expired');
    assert.equal((await lookup(tirBody({ validUntil: '2026-06-01T07:00:30+07:00' }))).trusted, true, 'offset form');
    assert.equal((await lookup(tirBody({ validUntil: '2026-06-01T06:58:58.999999999+07:00' }))).trusted, false, 'nanoseconds and offset');
  });

  test('a date-time that names no real instant, or an offset out of range, is no usable answer', async () => {
    for (const patch of [
      { validUntil: '2026-02-30T00:00:00Z' }, { validFrom: '2026-01-01T24:00:00Z' }, { validUntil: '2026-12-31T23:59:60Z' }, { validFrom: '0050-01-01T00:00:00Z' },
      { validFrom: '2026-01-01T00:00:00+24:00' }, { validUntil: '2027-01-01T00:00:00+00:60' }, { validFrom: '2026-01-01T00:00:00-24:00' },
    ]) {
      await assert.rejects(lookup(tirBody(patch)), TrustListUnavailableError, JSON.stringify(patch));
    }
    assert.equal((await lookup(tirBody({ validFrom: '2026-01-01T00:00:00+23:59', validUntil: '2027-01-01T00:00:00-23:59' }))).trusted, true, 'the largest offsets');
  });

  test('no usable answer rejects with TrustListUnavailableError', async () => {
    const answers: Route[] = [
      { status: 503, body: '' }, { status: 500, body: '' }, { status: 302, body: '' }, { status: 201, body: JSON.stringify(tirBody()) },
      new Error('timeout after 5000 ms'), ok('not json'), ok(JSON.stringify({ ...tirBody(), pad: 'a'.repeat(65_536) })),
      json(tirBody({ issuerDid: OTHER_DID })), json(tirBody({ issuerDid: undefined })), json(tirBody({ recognition: 'pending' })),
      json(tirBody({ vcTypes: VCT.diploma })), json(tirBody({ validUntil: '2026-02-30T00:00:00Z' })), json(tirBody({ validFrom: 1767225600 })), json([tirBody()]),
    ];
    for (const a of answers) {
      const w = registryWith({ [tirUrl(DID)]: a });
      await assert.rejects(w.registry.lookupIssuer(DID, VCT.diploma, NOW), TrustListUnavailableError, a instanceof Error ? a.message : `${a.status} ${a.body.slice(0, 40)}`);
    }
  });

  test('DIDs of another network or shape are not trusted without a request; nothing is cached; bad at is a TypeError', async () => {
    const w = registryWith({ [tirUrl(DID)]: json(tirBody()) });
    for (const did of ['did:certnet:testnet:a1b2', 'did:web:example.com', 'did:certnet:local:a.b']) assert.equal((await w.registry.lookupIssuer(did, VCT.diploma, NOW)).trusted, false);
    assert.equal(w.calls.length, 0);
    await w.registry.lookupIssuer(DID, VCT.diploma, NOW);
    w.routes[tirUrl(DID)] = json(tirBody({ recognition: 'rejected' }));
    assert.equal((await w.registry.lookupIssuer(DID, VCT.diploma, NOW)).trusted, false, 'a withdrawal is seen at once');
    assert.equal(w.calls.length, 2);
    await assert.rejects(w.registry.lookupIssuer(DID, VCT.diploma, new Date(NaN)), TypeError);
  });
});

test('isDidStatusListUri: no IPv4 address in any notation, no single-label host (SSRF)', () => {
  for (const host of [
    '2130706433', '0x7f000001', '0X7F000001', '017700000001', '127.0.0.1', '127.1', '169.254.169.254', '10.0.0.1', '0', '0.0.0.0', 'a.1', 'a.0x7f', 'a.b.123',
    'localhost', 'intranet', 'metadata', 'a.-b', 'a.9b',
  ]) {
    assert.equal(isDidStatusListUri(`https://${host}/issuers/x/status/1`), false, host);
    assert.equal(isDidStatusListUri(`https://${host}:8443/issuers/x/status/1`), false, `${host}:8443`);
  }
  for (const host of ['a.vn', 'status.truong-did.example.vn', '1.example.com', 'xn--bcher-kva.com', 'a-b.c1', '10.0.0.1.nip.io']) {
    assert.equal(isDidStatusListUri(`https://${host}/issuers/x/status/1`), true, host);
  }
});

test('isDidStatusListUri: no host under a special-use or internal last label (RFC 6761, 6762, internal suffixes); any port', () => {
  const refused = ['localhost', 'local', 'localdomain', 'internal', 'intranet', 'lan', 'home', 'corp', 'svc', 'arpa', 'test', 'example', 'invalid', 'onion'];
  for (const tld of refused) {
    for (const host of [`a.${tld}`, `a.b.${tld}`, `a.${tld}:8443`]) assert.equal(isDidStatusListUri(`https://${host}/issuers/x/status/1`), false, host);
  }
  for (const host of ['a.localhost', 'localhost.localdomain', 'metadata.google.internal', 'kubernetes.default.svc', 'host.docker.internal', 'home.arpa', 'gateway.certnet.test']) {
    assert.equal(isDidStatusListUri(`https://${host}/issuers/x/status/1`), false, host);
  }
  // Only the LAST label counts, and ports are not restricted.
  for (const host of ['api-identra.awncorp.vn', 'api-identra.awncorp.vn:8443', 'a.b:6379', 'localhost.example.com', 'internal.corp.awncorp.vn', 'status.truong.edu.vn', 'svc.io', 'a.testing', 'a.locals']) {
    assert.equal(isDidStatusListUri(`https://${host}/issuers/x/status/1`), true, host);
  }
});

test('isDidStatusListUri: the strict DID-path status URI form', () => {
  for (const good of ['https://truong.example.vn/issuers/x/status/1', 'https://a.vn:8443/s/status/999999999', 'https://a-b.vn/v1.2/status/12']) assert.equal(isDidStatusListUri(good), true, good);
  for (const bad of [
    'http://a.vn/s/status/1', 'https://a.vn/status/1', 'https://a.vn/s/status/0', 'https://a.vn/s/status/01', 'https://a.vn/s/status/1000000000',
    'https://a.vn/s/status/1?x=1', 'https://a.vn/s/status/1#f', 'https://u@a.vn/s/status/1', 'https://a.vn/../status/1', 'https://a.vn/s/../status/1',
    'https://a.vn/./status/1', 'https://a.vn//status/1', 'https://a.vn/%2e%2e/status/1', 'https://a.vn/s\\x/status/1', 'https://a.vn/s x/status/1',
    'https://A.vn/s/status/1', 'https://a.vn:0/s/status/1', 'https://a.vn/s/status/1/', ' https://a.vn/s/status/1', 42,
  ]) assert.equal(isDidStatusListUri(bad), false, String(bad));
});

// Fixtures for the DID trust path (ADR-0020): an issuer DID with a P-256 key generated at run time,
// gateway answers shaped exactly like the CertNet contract of 25/11 (4-openapi.yaml
// DidResolutionResult and TrustLookupResult), and a verifier wired to a scripted gateway.
import {
  createCertNetDidResolver,
  createCertNetTrustRegistry,
  createStatusList,
  createStatusListChecker,
  createStatusListToken,
  VCT,
  type Signer,
  type StatusChecker,
  type StatusValue,
} from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair, webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { NOW } from './pki.js';
import { fakeClock, ok, scriptedFetch, type Route } from './lists.js';
import { clock, fakeStatus, fakeTrust, validator, verifyOptions } from './sdjwt.js';

export const GATEWAY = 'https://gateway.certnet.test';
export const DID = 'did:certnet:local:a1b2c3d4e5f67890';
export const KID = `${DID}#key-1`;
export const OTHER_DID = 'did:certnet:local:0011223344556677';
export const DID_STATUS = { idx: 7, uri: 'https://truong-did.example.vn/issuers/truong-did/status/1' };
/** The Ed25519 key of the sample DID document of 1-did-certnet.md section 2. */
export const ED25519_JWK = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' };

/** A P-256 signer whose `kid` is `kid` (and no x5c). */
export async function didSigner(kid = KID): Promise<Signer> {
  const { privateKey, publicJwk } = await generateWebCryptoKeyPair();
  return Object.assign(await createWebCryptoSigner({ privateKey, publicJwk }), { kid });
}
export const issuerSigner = await didSigner();

export const didUrl = (did: string) => `${GATEWAY}/v1/dids/${encodeURIComponent(did)}`;
export const tirUrl = (did: string, vct: string = VCT.diploma) => `${GATEWAY}/v1/trust-registry/issuers/${encodeURIComponent(did)}?vcType=${encodeURIComponent(vct)}`;

/** A DidResolutionResult as the gateway sends it (one key in authentication and assertionMethod, like CreateDid). */
export function didBody(o: { did?: string; jwk?: object; kid?: string; document?: Record<string, unknown>; metadata?: Record<string, unknown>; top?: Record<string, unknown> } = {}) {
  const did = o.did ?? DID;
  const kid = o.kid ?? `${did}#key-1`;
  return {
    did,
    document: {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [{ id: kid, type: 'JsonWebKey2020', controller: did, publicKeyJwk: o.jwk ?? issuerSigner.publicJwk }],
      authentication: [kid],
      assertionMethod: [kid],
      ...o.document,
    },
    ...(o.metadata ? { metadata: o.metadata } : {}),
    chain: { blockHeight: 12, txHash: null, proof: null },
    ...o.top,
  };
}

/** A TrustLookupResult as the gateway sends it. */
export function tirBody(patch: Record<string, unknown> = {}) {
  return {
    issuerDid: DID,
    recognition: 'recognized',
    scopes: ['education'],
    vcTypes: [VCT.diploma],
    accreditingBody: { id: 'did:certnet:local:accreditor-01', name: 'Bo Giao Duc (TEST)' },
    chain: { blockHeight: 12, txHash: null, proof: null },
    ...patch,
  };
}

export const json = (v: unknown) => ok(JSON.stringify(v));

export async function didStatusToken(statuses: Record<number, StatusValue> = {}, o: { uri?: string; signer?: Signer; at?: Date } = {}) {
  const list = createStatusList();
  for (const [i, v] of Object.entries(statuses)) list.setStatus(Number(i), v);
  return createStatusListToken({ list, uri: o.uri ?? DID_STATUS.uri, signer: o.signer ?? issuerSigner, now: o.at ?? NOW });
}

/**
 * A verifier with the DID path on: the real resolver and trust registry over one scripted gateway
 * (routes may be replaced later), and the real status checker over the same fetch unless `status` is given.
 */
export async function dpkiWorld(o: { routes?: Record<string, Route | (() => Route | Promise<Route>)>; status?: StatusChecker; clock?: ReturnType<typeof fakeClock> } = {}) {
  const gwClock = o.clock ?? fakeClock();
  const served = scriptedFetch({
    [didUrl(DID)]: json(didBody()),
    [tirUrl(DID)]: json(tirBody()),
    [DID_STATUS.uri]: ok(await didStatusToken()),
    ...o.routes,
  });
  const resolver = createCertNetDidResolver({ gatewayUrl: GATEWAY, network: 'local', fetch: served.fetch, clock: gwClock });
  const trustRegistry = createCertNetTrustRegistry({ gatewayUrl: GATEWAY, network: 'local', fetch: served.fetch });
  const x509Trust = fakeTrust();
  const statusChecker = o.status ?? createStatusListChecker({ fetch: served.fetch, verifier: webCryptoVerifier, chainValidator: validator, trustRegistry: x509Trust, clock: gwClock, didResolver: resolver });
  const options = verifyOptions({ dpki: { resolver, trustRegistry }, trustRegistry: x509Trust, statusChecker });
  const callsTo = (url: string) => served.calls.filter((c) => c.url === url).length;
  return { ...served, resolver, trustRegistry, statusChecker, options, x509Trust, callsTo, clock: gwClock };
}

export const didIssuerContext = (signer: Signer = issuerSigner) => ({ signer, hasher: webCryptoHasher, random: webCryptoRandom, clock });
export { fakeStatus };

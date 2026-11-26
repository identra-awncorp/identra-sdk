// A freshly generated DEMO PKI (scripts/pki/make-demo-pki.sh) in a temporary directory, removed
// after the test file, plus the pieces every server test needs.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { after } from 'node:test';
import { base64Decode, createCertificateChainValidator, createCertNetDidResolver, createCertNetTrustRegistry, VCT, type Clock, type HttpFetch, type Signer } from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair, webCryptoHasher, webCryptoVerifier } from '@identra/sdk-core/webcrypto';

export const REPO = fileURLToPath(new URL('../../../', import.meta.url));
export const ISSUERS = 'https://api-identra.awncorp.vn/issuers';
export const issuerUri = (name: string) => `${ISSUERS}/${name}`;

/** Generates the demo PKI once per test file; returns its directory. */
export function freshDemoPki(): string {
  const parent = mkdtempSync(join(tmpdir(), 'identra-demo-pki-'));
  after(() => rmSync(parent, { recursive: true, force: true }));
  const dir = join(parent, 'pki');
  execFileSync('bash', [join(REPO, 'scripts/pki/make-demo-pki.sh'), dir], { stdio: 'pipe' });
  return dir;
}

export const pemCerts = (path: string) =>
  [...readFileSync(path, 'utf8').matchAll(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g)].map((m) => base64Decode(m[1]!.replace(/\s+/g, '')));

export const validatorFor = (dir: string) =>
  createCertificateChainValidator({ trustedRoots: pemCerts(join(dir, 'root.cert.pem')), verifier: webCryptoVerifier, hasher: webCryptoHasher });

export function fakeClock(start = new Date()) {
  let t = start.getTime();
  return { now: () => new Date(t), advance: (seconds: number) => void (t += seconds * 1000) };
}

/** Runs make-trust-list-source.mjs on `dir` and returns its JSON output. */
export const trustListSource = (dir: string): unknown =>
  JSON.parse(execFileSync('node', [join(REPO, 'scripts/pki/make-trust-list-source.mjs'), dir], { encoding: 'utf8' }));

/**
 * A FAKE CertNet gateway (no gateway exists here): the two read routes of the spec of 25/11
 * (4-openapi.yaml), `GET /v1/dids/{did}` -> DidResolutionResult and `GET /v1/trust-registry/issuers/{did}`
 * -> TrustLookupResult, as an injected HttpFetch. `down` answers 503 to every request, `tirDown` to the
 * trust registry only; `recognition` and `vcTypes` script the TIR answer.
 */
export function fakeGateway(base = 'https://gateway.certnet.test') {
  const keys = new Map<string, { kid: string; jwk: object }>();
  const state = { down: false, tirDown: false, recognition: 'recognized', vcTypes: [VCT.diploma] as string[], calls: [] as string[] };
  const answer = (status: number, body: unknown) => ({ status, headers: { get: () => null }, text: async () => JSON.stringify(body) });
  const fetch: HttpFetch = async (url) => {
    state.calls.push(url);
    if (state.down) return answer(503, { error: 'unavailable' });
    const u = new URL(url);
    if (u.origin !== base) throw new Error('host unreachable');
    const did = decodeURIComponent(u.pathname.split('/').pop()!);
    const key = keys.get(did);
    if (u.pathname.startsWith('/v1/dids/')) {
      if (!key) return answer(404, { error: 'not found' });
      return answer(200, {
        did,
        document: {
          '@context': ['https://www.w3.org/ns/did/v1'], id: did,
          verificationMethod: [{ id: key.kid, type: 'JsonWebKey2020', controller: did, publicKeyJwk: key.jwk }],
          authentication: [key.kid], assertionMethod: [key.kid],
        },
        metadata: { deactivated: false },
        chain: { blockHeight: 12, txHash: null, proof: null },
      });
    }
    if (u.pathname.startsWith('/v1/trust-registry/issuers/')) {
      if (state.tirDown) return answer(503, { error: 'unavailable' });
      if (!key) return answer(404, { error: 'not found' });
      return answer(200, { issuerDid: did, recognition: state.recognition, scopes: ['education'], vcTypes: state.vcTypes, validFrom: null, validUntil: null, chain: { blockHeight: 12, txHash: null, proof: null } });
    }
    return answer(404, { error: 'not found' });
  };
  return {
    base, fetch, state,
    /** Registers `signer`'s key as the one verification method of the DID of its kid. */
    register(signer: Signer) {
      keys.set(signer.kid!.split('#')[0]!, { kid: signer.kid!, jwk: signer.publicJwk });
    },
    dpki(clock: Clock) {
      return {
        resolver: createCertNetDidResolver({ gatewayUrl: base, network: 'local', fetch, clock }),
        trustRegistry: createCertNetTrustRegistry({ gatewayUrl: base, network: 'local', fetch }),
      };
    },
  };
}

export const DID = 'did:certnet:local:truongdid0001';
/** A P-256 DID signer generated at run time: `kid` `<did>#key-1`, no x5c. */
export async function newDidSigner(did = DID): Promise<Signer> {
  return Object.assign(await createWebCryptoSigner(await generateWebCryptoKeyPair()), { kid: `${did}#key-1` });
}

// did:jwk (https://github.com/quartzjer/did-jwk) for EC P-256 keys, resolved locally.
// Kept for tests and a later did:certnet; credential verification does not resolve DIDs (ADR-0015).
import { base64UrlDecode, utf8Decode } from './encoding.js';
import type { DidResolutionResult, DidResolver, EcPublicJwk } from './interfaces.js';
import { normalizeEcPublicJwk } from './jwk.js';
import { ErrorCodes } from './results.js';

const PREFIX = 'did:jwk:';

function failure(error: string, message: string): DidResolutionResult {
  return { didDocument: null, didDocumentMetadata: {}, didResolutionMetadata: { error, message } };
}

/** Resolves `did:jwk:<base64url(JSON JWK)>` holding an EC P-256 public key. Never throws. */
export const didJwkResolver: DidResolver = {
  async resolve(did) {
    if (typeof did !== 'string' || !did.startsWith(PREFIX)) return failure('methodNotSupported', 'only did:jwk is supported');
    let jwk: EcPublicJwk | null;
    try {
      jwk = normalizeEcPublicJwk(JSON.parse(utf8Decode(base64UrlDecode(did.slice(PREFIX.length)))));
    } catch {
      jwk = null;
    }
    if (!jwk) return failure('invalidDid', 'not an EC P-256 public JWK');
    const vm = `${did}#0`;
    return {
      didDocument: {
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
        id: did,
        verificationMethod: [{ id: vm, type: 'JsonWebKey2020', controller: did, publicKeyJwk: { ...jwk } }],
        authentication: [vm],
        assertionMethod: [vm],
        capabilityInvocation: [vm],
        capabilityDelegation: [vm],
      },
      didDocumentMetadata: {},
      didResolutionMetadata: { contentType: 'application/did+ld+json' },
    };
  },
};

export type DidKeyResult =
  | { ok: true; publicJwk: EcPublicJwk }
  | { ok: false; code: typeof ErrorCodes.DID_RESOLUTION_FAILED | typeof ErrorCodes.KEY_NOT_FOUND; detail: string };

/**
 * Resolves a DID URL `kid` (`did:...#fragment`) to the EC P-256 key of an `assertionMethod`
 * verification method. Never throws: resolver errors are DID_RESOLUTION_FAILED, a missing or
 * unusable key is KEY_NOT_FOUND.
 */
export async function resolveDidVerificationKey(kid: unknown, resolver: DidResolver): Promise<DidKeyResult> {
  if (typeof kid !== 'string' || !kid.includes('#')) return { ok: false, code: ErrorCodes.KEY_NOT_FOUND, detail: 'kid is not a DID URL with a fragment' };
  const did = kid.slice(0, kid.indexOf('#'));
  let result: DidResolutionResult;
  try {
    result = await resolver.resolve(did);
  } catch {
    return { ok: false, code: ErrorCodes.DID_RESOLUTION_FAILED, detail: 'resolver failed' };
  }
  const doc = result.didDocument;
  if (!doc || result.didResolutionMetadata.error || doc.id !== did) {
    return { ok: false, code: ErrorCodes.DID_RESOLUTION_FAILED, detail: result.didResolutionMetadata.error ?? 'no DID document' };
  }
  const asserted = (doc.assertionMethod ?? []).includes(kid);
  const method = doc.verificationMethod?.find((m) => m.id === kid);
  const jwk = asserted && method?.controller === did ? normalizeEcPublicJwk(method.publicKeyJwk) : null;
  if (!jwk) return { ok: false, code: ErrorCodes.KEY_NOT_FOUND, detail: 'no EC P-256 assertionMethod key for kid' };
  return { ok: true, publicJwk: jwk };
}

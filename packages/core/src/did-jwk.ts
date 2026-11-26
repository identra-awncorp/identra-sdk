// did:jwk (https://github.com/quartzjer/did-jwk) for EC P-256 keys, resolved locally (tests), and
// resolveDidVerificationKey, which the DID trust path uses with the did:certnet resolver (ADR-0020).
import { base64UrlDecode, utf8Decode } from './encoding.js';
import type { DidResolutionResult, DidResolver, EcPublicJwk } from './interfaces.js';
import { normalizeEcPublicJwk } from './jwk.js';
import { ErrorCodes } from './results.js';

/** `didResolutionMetadata.error` of a resolver that got no usable answer: retry later, the DID is not known to be bad. */
export const DID_RESOLUTION_UNAVAILABLE_ERROR = 'temporarilyUnavailable';

/** The DID and fragment of a DID URL `did:<...>#<fragment>` (one `#`, both parts non-empty), else null. */
export function splitDidUrl(kid: unknown): { did: string; fragment: string } | null {
  if (typeof kid !== 'string' || !kid.startsWith('did:')) return null;
  const parts = kid.split('#');
  return parts.length === 2 && parts[0]!.length > 4 && parts[1] !== '' ? { did: parts[0]!, fragment: parts[1]! } : null;
}

const PREFIX = 'did:jwk:';

function failure(error: string, message: string): DidResolutionResult {
  return { didDocument: null, didDocumentMetadata: {}, didResolutionMetadata: { error, message } };
}

/** Resolves `did:jwk:<base64url(JSON JWK)>` holding an EC P-256 public key. Never throws. */
export const didJwkResolver: DidResolver = {
  async resolve(did) {
    if (typeof did !== 'string' || !did.startsWith(PREFIX)) return failure('methodNotSupported', 'only did:jwk is supported');
    let raw: unknown;
    try {
      raw = JSON.parse(utf8Decode(base64UrlDecode(did.slice(PREFIX.length))));
    } catch {
      return failure('invalidDid', 'not base64url JSON');
    }
    const jwk = normalizeEcPublicJwk(raw);
    const use = (raw as { use?: unknown } | null)?.use;
    if (!jwk || (use !== undefined && use !== 'sig' && use !== 'enc')) return failure('invalidDid', 'not an EC P-256 public JWK');
    const vm = `${did}#0`;
    // did:jwk: "use": "enc" keys are offered for keyAgreement only, "use": "sig" keys never for it.
    const relations = use === 'enc' ? { keyAgreement: [vm] } : {
      authentication: [vm],
      assertionMethod: [vm],
      capabilityInvocation: [vm],
      capabilityDelegation: [vm],
      ...(use === undefined ? { keyAgreement: [vm] } : {}),
    };
    return {
      didDocument: {
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
        id: did,
        verificationMethod: [{ id: vm, type: 'JsonWebKey2020', controller: did, publicKeyJwk: { ...jwk } }],
        ...relations,
      },
      didDocumentMetadata: {},
      didResolutionMetadata: { contentType: 'application/did+ld+json' },
    };
  },
};

export type DidKeyResult =
  | { ok: true; publicJwk: EcPublicJwk }
  | {
      ok: false;
      code: typeof ErrorCodes.DID_RESOLUTION_FAILED | typeof ErrorCodes.DID_RESOLUTION_UNAVAILABLE | typeof ErrorCodes.KEY_NOT_FOUND | typeof ErrorCodes.ALG_NOT_ALLOWED;
      detail: string;
    };

/**
 * Resolves a DID URL `kid` (`did:...#fragment`) to the EC P-256 key of an `assertionMethod`
 * verification method controlled by that DID. Never throws: a resolver answering
 * DID_RESOLUTION_UNAVAILABLE_ERROR is DID_RESOLUTION_UNAVAILABLE, any other resolver error, a
 * deactivated DID or a document of another DID is DID_RESOLUTION_FAILED, no such `assertionMethod`
 * method is KEY_NOT_FOUND, and a method whose key is not a valid EC P-256 key is ALG_NOT_ALLOWED.
 */
export async function resolveDidVerificationKey(kid: unknown, resolver: DidResolver): Promise<DidKeyResult> {
  try {
    return await resolveKey(kid, resolver);
  } catch {
    return { ok: false, code: ErrorCodes.DID_RESOLUTION_FAILED, detail: 'unusable resolver output' };
  }
}

async function resolveKey(kid: unknown, resolver: DidResolver): Promise<DidKeyResult> {
  const notFound = (detail: string): DidKeyResult => ({ ok: false, code: ErrorCodes.KEY_NOT_FOUND, detail });
  const failed = (detail: string): DidKeyResult => ({ ok: false, code: ErrorCodes.DID_RESOLUTION_FAILED, detail });
  const parts = splitDidUrl(kid);
  if (!parts) return notFound('kid is not a DID URL with a fragment');
  const { did } = parts;
  let result: DidResolutionResult;
  try {
    result = await resolver.resolve(did);
  } catch {
    return failed('resolver failed');
  }
  const doc = result?.didDocument;
  const meta = result?.didResolutionMetadata;
  if (typeof meta === 'object' && meta !== null && meta.error === DID_RESOLUTION_UNAVAILABLE_ERROR) {
    return { ok: false, code: ErrorCodes.DID_RESOLUTION_UNAVAILABLE, detail: 'the DID could not be resolved now' };
  }
  if (!doc || typeof doc !== 'object' || typeof meta !== 'object' || meta === null || meta.error !== undefined || doc.id !== did) {
    return failed('no DID document for this DID');
  }
  if ((result.didDocumentMetadata as { deactivated?: unknown } | undefined)?.deactivated === true) return failed('the DID is deactivated');
  const asserted = Array.isArray(doc.assertionMethod) && doc.assertionMethod.includes(kid as string);
  const method = Array.isArray(doc.verificationMethod) ? doc.verificationMethod.find((m) => m?.id === kid) : undefined;
  if (!asserted || method?.controller !== did) return notFound('no assertionMethod verification method of this DID for kid');
  const jwk = normalizeEcPublicJwk(method.publicKeyJwk);
  if (!jwk) return { ok: false, code: ErrorCodes.ALG_NOT_ALLOWED, detail: 'the key of kid is not a valid EC P-256 public key' };
  return { ok: true, publicJwk: jwk };
}

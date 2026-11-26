// Status List Token in JWT form (Token Status List section 5.1, ADR-0013 section 3, ADR-0015
// sections 4 and 6): typ statuslist+jwt, x5c [leaf, issuing CA] of a `status` certificate of the
// organisation that issued the credential; for a DID issuer (ADR-0020 section 6) instead `kid`, a
// DID URL of an assertionMethod key of the issuer's own DID, and no x5c.
import { isCertNetDid } from '../did-certnet.js';
import { splitDidUrl } from '../did-jwk.js';
import { utf8Encode } from '../encoding.js';
import type { CertificateChainValidator, DidResolver, EcPublicJwk, Signer, TrustRegistry, Verifier } from '../interfaces.js';
import { signJws } from '../jws.js';
import { TrustListUnavailableError } from '../results.js';
import { fail, tokenTimes, verifyDidSignedToken, verifySignedToken, type TokenFailure, type VerifiedDidSignedToken, type VerifiedSignedToken } from '../signed-token.js';
import { decodeStatusList, type StatusList } from './list.js';

export const STATUS_LIST_TOKEN_TYP = 'statuslist+jwt';
export const STATUS_LIST_TOKEN_MAX_BYTES = 128 * 1024;

export interface VerifiedStatusListToken {
  ok: true;
  list: StatusList;
  token: string;
  iat: number;
  exp: number;
  ttl?: number;
  /** The signer certificate: its fingerprint and its organizationIdentifier (checked against the trust list). */
  signer: { fingerprint: string; maToChuc: string };
}

export async function createStatusListToken(options: {
  list: StatusList;
  uri: string;
  signer: Signer;
  now: Date;
  ttlSeconds?: number;
  lifetimeSeconds?: number;
}): Promise<string> {
  const { list, uri, signer, now, ttlSeconds = 900, lifetimeSeconds = 86_400 } = options;
  if (typeof list?.encode !== 'function') throw new TypeError('list is required');
  if (typeof uri !== 'string' || !uri.startsWith('https://')) throw new TypeError('uri must be an https URL');
  const didKid = typeof signer?.kid === 'string' && signer.kid.startsWith('did:');
  if (didKid ? signer.x5c !== undefined || !isCertNetDid(splitDidUrl(signer.kid)?.did) : !Array.isArray(signer?.x5c) || signer.x5c.length !== 2) {
    throw new TypeError('the signer needs x5c [leaf, issuing CA] of a status certificate, or a did:certnet kid and no x5c');
  }
  const { iat, exp, ttl } = tokenTimes(now, ttlSeconds, lifetimeSeconds);
  const payload = { sub: uri, iat, exp, ttl, status_list: list.encode() };
  return signJws({ typ: STATUS_LIST_TOKEN_TYP }, utf8Encode(JSON.stringify(payload)), signer);
}

/**
 * ADR-0015 section 6: the signer certificate must be in the trust list with purpose `status`, its
 * organizationIdentifier must equal that entry's maToChuc, and (unless `issuerMaToChuc` is null)
 * that maToChuc must be the one of the organisation that issued the credential. Null when all hold.
 */
export async function checkStatusListSigner(
  trustRegistry: TrustRegistry,
  signer: { fingerprint: string; maToChuc: string },
  issuerMaToChuc: string | null,
  now: Date,
): Promise<TokenFailure | null> {
  let entry;
  try {
    entry = await trustRegistry.lookup(signer.fingerprint, now);
  } catch (e) {
    if (e instanceof TrustListUnavailableError) return fail('trust_list_unavailable', 'no valid trust list');
    return fail('not_trusted', 'trust registry failed');
  }
  if (!entry) return fail('not_trusted', 'signer certificate is not in the trust list');
  if (entry.mucDich !== 'status') return fail('not_trusted', 'signer certificate purpose is not status');
  if (entry.maToChuc !== signer.maToChuc) return fail('not_trusted', 'signer organizationIdentifier differs from the trust list entry');
  if (issuerMaToChuc !== null && entry.maToChuc !== issuerMaToChuc) return fail('not_trusted', 'status list is signed by another organisation');
  return null;
}

/**
 * Every rule of docs/architecture.md section 7 except the comparison with the credential issuer's
 * organisation (`issuerMaToChuc` null): what the checker caches per URI before each caller compares.
 */
export async function verifyStatusListTokenSigned(
  token: unknown,
  o: { uri: string; issuerMaToChuc: string | null; chainValidator: CertificateChainValidator; trustRegistry: TrustRegistry; verifier: Verifier; now: Date },
): Promise<VerifiedStatusListToken | TokenFailure> {
  const { chainValidator, verifier, now } = o;
  const r = await verifySignedToken(token, { typ: STATUS_LIST_TOKEN_TYP, profile: 'status', maxBytes: STATUS_LIST_TOKEN_MAX_BYTES, chainValidator, verifier, now });
  if (!r.ok) return r;
  if (r.payload['sub'] !== o.uri) return fail('claims', 'sub is not the status list uri');
  const signer = { fingerprint: r.fingerprint, maToChuc: r.leaf.subject.organizationIdentifier ?? '' };
  const untrusted = await checkStatusListSigner(o.trustRegistry, signer, o.issuerMaToChuc, now);
  if (untrusted) return untrusted;
  return withList(r, token as string, signer);
}

/** The decoded list of a verified token. */
function withList<S>(r: VerifiedSignedToken | VerifiedDidSignedToken, token: string, signer: S): ({ ok: true; list: StatusList; token: string; iat: number; exp: number; ttl?: number; signer: S }) | TokenFailure {
  let list: StatusList;
  try {
    list = decodeStatusList(r.payload['status_list']);
  } catch (e) {
    return fail('claims', (e as Error).message);
  }
  return { ok: true, list, token, iat: r.iat, exp: r.exp, ...(r.ttl !== undefined ? { ttl: r.ttl } : {}), signer };
}

export interface VerifiedDidStatusListToken extends Omit<VerifiedStatusListToken, 'signer'> {
  /** The DID URL of the signing key and that key. */
  signer: { kid: string; publicJwk: EcPublicJwk };
}

/**
 * The status list of a DID issuer (ADR-0020 section 6): every rule of docs/architecture.md section
 * 7 for the token and `sub`, with `kid` = `<did>#<fragment>` of the issuer's own DID (`not_trusted`
 * for another DID) and the key an assertionMethod EC P-256 key of it (`key`), and no x5c.
 */
export async function verifyDidStatusListToken(
  token: unknown,
  o: { uri: string; did: string; didResolver: DidResolver; verifier: Verifier; now: Date },
): Promise<VerifiedDidStatusListToken | TokenFailure> {
  const { did, didResolver, verifier, now } = o;
  const r = await verifyDidSignedToken(token, { typ: STATUS_LIST_TOKEN_TYP, maxBytes: STATUS_LIST_TOKEN_MAX_BYTES, did, didResolver, verifier, now });
  if (!r.ok) return r;
  if (r.payload['sub'] !== o.uri) return fail('claims', 'sub is not the status list uri');
  return withList(r, token as string, { kid: r.kid, publicJwk: r.publicJwk });
}

/** Every rule of docs/architecture.md section 7; never throws for bad input. */
export async function verifyStatusListToken(
  token: unknown,
  o: {
    uri: string;
    issuer: { maToChuc: string };
    chainValidator: CertificateChainValidator;
    trustRegistry: TrustRegistry;
    verifier: Verifier;
    now: Date;
  },
): Promise<VerifiedStatusListToken | TokenFailure> {
  if (typeof o.uri !== 'string' || typeof o.issuer?.maToChuc !== 'string' || o.issuer.maToChuc === '') {
    throw new TypeError('uri and issuer.maToChuc are required');
  }
  if (typeof o.trustRegistry?.lookup !== 'function') throw new TypeError('trustRegistry is required');
  const { uri, chainValidator, trustRegistry, verifier, now } = o;
  return verifyStatusListTokenSigned(token, { uri, issuerMaToChuc: o.issuer.maToChuc, chainValidator, trustRegistry, verifier, now });
}

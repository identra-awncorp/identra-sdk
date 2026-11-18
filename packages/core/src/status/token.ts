// Status List Token in JWT form (Token Status List section 5.1, ADR-0013 section 3, ADR-0015
// sections 4 and 6): typ statuslist+jwt, x5c [leaf, issuing CA] of a `status` certificate of the
// organisation that issued the credential.
import { utf8Encode } from '../encoding.js';
import type { CertificateChainValidator, Signer, TrustRegistry, Verifier } from '../interfaces.js';
import { signJws } from '../jws.js';
import { TrustListUnavailableError } from '../results.js';
import { fail, tokenTimes, verifySignedToken, type TokenFailure } from '../signed-token.js';
import { decodeStatusList, type StatusList } from './list.js';

export const STATUS_LIST_TOKEN_TYP = 'statuslist+jwt';
export const STATUS_LIST_TOKEN_MAX_BYTES = 128 * 1024;

export interface VerifiedStatusListToken {
  ok: true;
  list: StatusList;
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
  if (!Array.isArray(signer?.x5c) || signer.x5c.length !== 2) throw new TypeError('the signer needs x5c [leaf, issuing CA] of a status certificate');
  const { iat, exp, ttl } = tokenTimes(now, ttlSeconds, lifetimeSeconds);
  const payload = { sub: uri, iat, exp, ttl, status_list: list.encode() };
  return signJws({ typ: STATUS_LIST_TOKEN_TYP }, utf8Encode(JSON.stringify(payload)), signer);
}

/**
 * ADR-0015 section 6: the signer certificate must be in the trust list with purpose `status`, its
 * organizationIdentifier must equal that entry's maToChuc, and that maToChuc must be the one of the
 * organisation that issued the credential. Null when all hold.
 */
export async function checkStatusListSigner(
  trustRegistry: TrustRegistry,
  signer: { fingerprint: string; maToChuc: string },
  issuerMaToChuc: string,
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
  if (entry.maToChuc !== issuerMaToChuc) return fail('not_trusted', 'status list is signed by another organisation');
  return null;
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
  const { chainValidator, verifier, now } = o;
  const r = await verifySignedToken(token, { typ: STATUS_LIST_TOKEN_TYP, profile: 'status', maxBytes: STATUS_LIST_TOKEN_MAX_BYTES, chainValidator, verifier, now });
  if (!r.ok) return r;
  if (r.payload['sub'] !== o.uri) return fail('claims', 'sub is not the status list uri');
  const signer = { fingerprint: r.fingerprint, maToChuc: r.leaf.subject.organizationIdentifier ?? '' };
  const untrusted = await checkStatusListSigner(o.trustRegistry, signer, o.issuer.maToChuc, o.now);
  if (untrusted) return untrusted;
  let list: StatusList;
  try {
    list = decodeStatusList(r.payload['status_list']);
  } catch (e) {
    return fail('claims', (e as Error).message);
  }
  const result: VerifiedStatusListToken = { ok: true, list, iat: r.iat, exp: r.exp, signer };
  if (r.ttl !== undefined) result.ttl = r.ttl;
  return result;
}

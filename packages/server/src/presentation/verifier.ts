// OpenID4VP 1.0 verifier, cross-device, direct_post.jwt (ADR-0011 as amended by ADR-0015 sections 5
// and 6, vc-api.md section 6, docs/architecture.md section 9). Protocol operations return a ready HTTP
// response and never throw for bad input from the network; they throw only when a dependency fails.
import {
  base64UrlEncode, signJws, utf8Encode, verifyPresentation,
  type Check, type Clock, type RandomSource, type Signer, type VerifyCredentialOptions,
} from '@identra/sdk-core';
import type { JWK } from 'jose';
import { jsonResponse, oauthError, type HttpRequest, type HttpResponse } from '../issuance/http.js';
import type { ProtocolStateStore } from '../state-store.js';
import { CREDENTIAL_QUERY_ID, dcqlQueryOf, generateSessionKey, parseResponse, RESPONSE_ENC_VALUES, satisfiedClaimSet, type Scenario } from './library.js';

export const SESSION_SECONDS = 300;
export const SESSION_KEEP_SECONDS = 1800;
const ID = /^[A-Za-z0-9_-]{22}$/;
const MAX_RESPONSE_BYTES = 65536;

export type SessionStatus = 'pending' | 'request_retrieved' | 'verified' | 'failed' | 'expired';

export interface SessionResult {
  ok: boolean;
  /** Each check of the policy (architecture section 3) and `query`, without details. */
  checks: Pick<Check, 'id' | 'ok' | 'code'>[];
  /** Only when ok: the claims of the satisfied claim set, all strings. */
  claims?: Record<string, string>;
  issuer?: { maToChuc: string; ten: string };
  verifiedAt: string;
}

export interface SessionResource {
  id: string;
  status: SessionStatus;
  verifier: { name: string };
  expiresAt: string;
  serverTime: string;
  /** Absent until the session is final. */
  result?: SessionResult;
}

export interface PresentationVerifierConfig {
  /** Canonical API origin, e.g. `https://api-identra.awncorp.vn`; request and response URIs live under `/oid4vp/`. */
  apiOrigin: string;
  /** The `request` signer: x5c [leaf, issuing CA]. Its fingerprint is the client_id. */
  signer: Signer;
  /** How presentations are verified (verifyPresentation); the server's own lists. */
  verification: Omit<VerifyCredentialOptions, 'now'>;
  random: RandomSource;
  clock: Clock;
  store: ProtocolStateStore;
  scenarios: Record<string, Scenario>;
}

export interface PresentationVerifier {
  clientId: string;
  /** Display name of this verifier in the trust list. */
  name: string;
  /** Null for an unknown scenario. */
  createSession(input: { scenario: string }): Promise<{ id: string; requestId: string; qr: string; expiresAt: string; serverTime: string } | null>;
  requestObject(requestId: string): Promise<HttpResponse>;
  handleResponse(requestId: string, request: HttpRequest): Promise<HttpResponse>;
  /** Null when unknown or deleted (30 minutes after creation or verification). */
  session(id: string): Promise<SessionResource | null>;
}

interface SessionRecord { requestId: string; createdAt: number; expiresAt: number }
interface RequestRecord { id: string; scenario: string; jwt: string; payload: Record<string, unknown>; expiresAt: number }

/**
 * Validates the request certificate (profile `request`) and looks it up in the trust list once:
 * it must be there with purpose `request` and the organisation of the certificate, or this throws.
 */
export async function createPresentationVerifier(config: PresentationVerifierConfig): Promise<PresentationVerifier> {
  const { apiOrigin, signer, verification, random, clock, store } = config;
  if (!/^https:\/\/[A-Za-z0-9.-]+(:[0-9]{1,5})?$/.test(apiOrigin)) throw new TypeError('apiOrigin must be https://host[:port]');
  if (signer?.alg !== 'ES256' || !Array.isArray(signer.x5c) || signer.x5c.length !== 2) throw new TypeError('signer must be an ES256 signer with x5c [leaf, issuing CA]');
  const chain = await verification.chainValidator.validate({ x5c: signer.x5c, profile: 'request', now: clock.now() });
  if (!chain.ok || !chain.fingerprint || !chain.leaf) throw new Error(`the request certificate does not validate: ${chain.code}`);
  const entry = await verification.trustRegistry.lookup(chain.fingerprint, clock.now());
  if (!entry || entry.mucDich !== 'request' || entry.maToChuc !== chain.leaf.subject.organizationIdentifier) {
    throw new Error('the request certificate is not in the trust list with purpose request');
  }
  const queries = Object.fromEntries(Object.entries(config.scenarios).map(([name, s]) => [name, dcqlQueryOf(s)]));
  const clientId = `x509_hash:${chain.fingerprint}`;
  const name = entry.ten;
  const key = (kind: string, id: string) => `vp:${clientId}:${kind}:${id}`;
  const newId = () => base64UrlEncode(random.bytes(16));
  const read = async <T>(k: string): Promise<T | null> => {
    const v = await store.get(k);
    return v === null ? null : (JSON.parse(v) as T);
  };
  const invalid = () => oauthError(400, 'invalid_request', 'the response is not acceptable');

  /** verifyPresentation, then the query on the verified claims; the result to store. */
  async function evaluate(presentation: unknown, request: RequestRecord, now: Date): Promise<SessionResult> {
    const verifiedAt = now.toISOString();
    const checks = (cs: Check[]) => cs.map(({ id, ok, code }) => ({ id, ok, code }));
    if (typeof presentation !== 'string') return { ok: false, checks: [{ id: 'structure', ok: false, code: 'MALFORMED' }], verifiedAt };
    const r = await verifyPresentation(presentation, {
      ...verification, now, presentation: { nonce: request.payload['nonce'] as string, audience: clientId },
    });
    const claims = r.credential?.claims;
    if (!r.ok || !claims) return { ok: false, checks: [...checks(r.checks), { id: 'query', ok: false, code: 'SKIPPED' }], verifiedAt };
    const index = satisfiedClaimSet(queries[request.scenario]!, { vct: r.credential!.vct, claims });
    if (index === null) return { ok: false, checks: [...checks(r.checks), { id: 'query', ok: false, code: 'QUERY_NOT_SATISFIED' }], verifiedAt };
    // Only the claims of the satisfied claim set are kept; any other disclosed claim is dropped.
    const kept = Object.fromEntries(config.scenarios[request.scenario]!.claimSets[index]!.filter((n) => typeof claims[n] === 'string').map((n) => [n, claims[n] as string]));
    return { ok: true, checks: [...checks(r.checks), { id: 'query', ok: true, code: null }], claims: kept, issuer: { ...r.credential!.issuer! }, verifiedAt };
  }

  return {
    clientId,
    name,

    async createSession({ scenario }) {
      if (typeof scenario !== 'string' || !Object.hasOwn(queries, scenario)) return null;
      const id = newId();
      const requestId = newId();
      const now = clock.now();
      const iat = Math.floor(now.getTime() / 1000);
      const expiresAt = now.getTime() + SESSION_SECONDS * 1000;
      const sessionKey = await generateSessionKey(newId());
      const requestUri = `${apiOrigin}/oid4vp/request/${requestId}`;
      const payload = {
        response_type: 'vp_token',
        client_id: clientId,
        response_mode: 'direct_post.jwt',
        response_uri: `${apiOrigin}/oid4vp/response/${requestId}`,
        nonce: base64UrlEncode(random.bytes(32)),
        state: base64UrlEncode(random.bytes(32)),
        dcql_query: queries[scenario],
        client_metadata: {
          jwks: { keys: [sessionKey.publicJwk] },
          encrypted_response_enc_values_supported: RESPONSE_ENC_VALUES,
          vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] } },
        },
        aud: 'https://self-issued.me/v2',
        iat,
        exp: iat + SESSION_SECONDS,
      };
      // The one signing path: core signJws with the request signer (x5c from the signer).
      const jwt = await signJws({ typ: 'oauth-authz-req+jwt' }, utf8Encode(JSON.stringify(payload)), signer);
      const request: RequestRecord = { id, scenario, jwt, payload, expiresAt };
      await store.put(key('session', id), JSON.stringify({ requestId, createdAt: now.getTime(), expiresAt } satisfies SessionRecord), SESSION_KEEP_SECONDS);
      await store.put(key('key', requestId), JSON.stringify(sessionKey.privateJwk), SESSION_SECONDS);
      await store.put(key('request', requestId), JSON.stringify(request), SESSION_SECONDS);
      await store.put(key('open', requestId), '1', SESSION_SECONDS);
      const qr = `openid4vp://?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(requestUri)}`;
      return { id, requestId, qr, expiresAt: new Date(expiresAt).toISOString(), serverTime: now.toISOString() };
    },

    async requestObject(requestId) {
      const request = ID.test(requestId) ? await read<RequestRecord>(key('request', requestId)) : null;
      // Served until the session is final: the open marker is gone once a response was processed.
      if (!request || request.expiresAt <= clock.now().getTime() || (await store.get(key('open', requestId))) === null) return jsonResponse(404, { error: 'not_found' });
      await store.put(key('retrieved', request.id), '1', SESSION_KEEP_SECONDS);
      return { status: 200, headers: { 'Content-Type': 'application/oauth-authz-req+jwt', 'Cache-Control': 'no-store' }, body: request.jwt };
    },

    async handleResponse(requestId, req) {
      const now = clock.now();
      const request = ID.test(requestId) ? await read<RequestRecord>(key('request', requestId)) : null;
      if (!request || request.expiresAt <= now.getTime()) return invalid();
      if (!(req.headers['content-type'] ?? '').toLowerCase().startsWith('application/x-www-form-urlencoded') || req.body.length > MAX_RESPONSE_BYTES) return invalid();
      const params = new URLSearchParams(req.body);
      const names = [...params.keys()];
      // direct_post.jwt only: exactly one `response` parameter holding a compact JWE (no downgrade to direct_post).
      const response = params.get('response');
      if (names.length !== 1 || response === null || response.split('.').length !== 5) return invalid();
      const privateJwk = await read<JWK>(key('key', requestId));
      if (!privateJwk) return invalid();
      const presentations = await parseResponse({ form: { response }, requestPayload: request.payload, privateJwk, hasher: verification.hasher });
      if (!presentations) return invalid();
      // Exactly once: of concurrent responses only the one that takes the open marker is processed.
      if ((await store.take(key('open', requestId))) === null) return invalid();

      const ids = Object.keys(presentations);
      const list = presentations[CREDENTIAL_QUERY_ID];
      const presentation = ids.length === 1 && Array.isArray(list) && list.length === 1 ? list[0] : undefined;
      const result = await evaluate(presentation, request, now);
      const session = await read<SessionRecord>(key('session', request.id));
      await store.put(key('result', request.id), JSON.stringify(result), SESSION_KEEP_SECONDS);
      if (session) await store.put(key('session', request.id), JSON.stringify(session), SESSION_KEEP_SECONDS);
      await store.take(key('key', requestId));
      return jsonResponse(200, {});
    },

    async session(id) {
      const s = ID.test(id) ? await read<SessionRecord>(key('session', id)) : null;
      if (!s) return null;
      const now = clock.now();
      const result = await read<SessionResult>(key('result', id));
      const status: SessionStatus = result
        ? result.ok ? 'verified' : 'failed'
        : s.expiresAt <= now.getTime() ? 'expired' : (await store.get(key('retrieved', id))) !== null ? 'request_retrieved' : 'pending';
      return { id, status, verifier: { name }, expiresAt: new Date(s.expiresAt).toISOString(), serverTime: now.toISOString(), ...(result ? { result } : {}) };
    },
  };
}

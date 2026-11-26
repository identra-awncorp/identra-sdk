// OpenID4VP 1.0 verifier, cross-device, direct_post.jwt (ADR-0011 as amended by ADR-0015 sections 5
// and 6, vc-api.md section 6, docs/architecture.md section 9). Protocol operations return a ready HTTP
// response and never throw for bad input from the network; they throw only when a dependency fails.
import {
  base64UrlEncode, claimSetsNested, MAX_CLAIM_SETS, signJws, utf8Encode, verifyPresentation,
  type Check, type Clock, type ErrorCode, type RandomSource, type Signer, type VerifyCredentialOptions,
} from '@identra/sdk-core';
import type { JWK } from 'jose';
import { jsonResponse, oauthError, type HttpRequest, type HttpResponse } from '../issuance/http.js';
import type { ProtocolStateStore } from '../state-store.js';
import { CREDENTIAL_QUERY_ID, dcqlQueryOf, generateSessionKey, parseResponse, RESPONSE_ENC_VALUES, satisfiedClaimSet, type Scenario } from './library.js';

export const SESSION_SECONDS = 300;
export const SESSION_KEEP_SECONDS = 1800;
/** Responses that do not finalise a session (refused before or at holder binding) allowed per request. */
export const MAX_RESPONSE_ATTEMPTS = 10;
/** How often createSession re-checks that this verifier is still in the trust list. */
export const TRUST_RECHECK_SECONDS = 3600;
const ID = /^[A-Za-z0-9_-]{22}$/;
const MAX_RESPONSE_BYTES = 65536;

export type SessionStatus = 'pending' | 'request_retrieved' | 'verified' | 'failed' | 'expired';

export interface SessionResult {
  ok: boolean;
  /** Each check of the policy (architecture section 3) and `query`, without details. */
  checks: Pick<Check, 'id' | 'ok' | 'code'>[];
  /** Only when ok: the claims of the satisfied claim set, all strings. */
  claims?: Record<string, string>;
  /** Only when ok: how the issuer was recognised (ADR-0020); `issuer` on the X.509 path, `issuerDid` on the DID path. */
  trustPath?: 'x509' | 'did';
  /** Only when ok on the X.509 path: the trust-list entry. */
  issuer?: { maToChuc: string; ten: string };
  /** Only when ok on the DID path: the issuer's did:certnet DID; this path has no display name. */
  issuerDid?: string;
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
  /**
   * How presentations are verified (verifyPresentation); the server's own lists. With `dpki` the DID
   * trust path is on, and `statusChecker` must then have a `didResolver` (createStatusListChecker).
   */
  verification: Omit<VerifyCredentialOptions, 'now'>;
  random: RandomSource;
  clock: Clock;
  store: ProtocolStateStore;
  scenarios: Record<string, Scenario>;
}

export interface CreatedSession { id: string; requestId: string; qr: string; expiresAt: string; serverTime: string }

/**
 * `unknown_scenario`: the caller named a scenario that is not configured (HTTP 400/404).
 * `verifier_not_listed`: this verifier's request certificate is no longer in the trust list with
 * purpose `request` (HTTP 503 until the list is fixed).
 */
export type CreateSessionResult = { ok: true; session: CreatedSession } | { ok: false; reason: 'unknown_scenario' | 'verifier_not_listed' };

/**
 * What happened, for the server's log (ids and codes only). `final`: this response made the
 * session final (`ok` and `code` of its result: the first failing check, absent when ok). A refused
 * response (`final: false`) carries why: `MALFORMED` for transport, encryption, `state` or shape,
 * the holder-binding code (KB_INVALID, NONCE_MISMATCH, AUD_MISMATCH, …), or the code of the
 * gating step that failed before holder binding could run (MALFORMED, CERT_*, …); none when another
 * response finalised the session first. Log `sessionId` as a prefix only: it reads the result.
 */
export interface ResponseOutcome { sessionId: string; final: boolean; ok?: boolean; code?: ErrorCode }
export interface HandledResponse { response: HttpResponse; outcome: ResponseOutcome }

export interface PresentationVerifier {
  readonly clientId: string;
  /** Display name of this verifier in the trust list, refreshed at most hourly. */
  readonly name: string;
  createSession(input: { scenario: string }): Promise<CreateSessionResult>;
  /** Null when this verifier holds no such request (unknown, expired or final): a server with several verifiers tries the next; with none left, 404. */
  requestObject(requestId: string): Promise<HttpResponse | null>;
  /** Null when this verifier holds no such request (unknown, expired or final): a server with several verifiers tries the next; with none left, 400 invalid_request. */
  handleResponse(requestId: string, request: HttpRequest): Promise<HandledResponse | null>;
  /** Null when unknown or deleted (30 minutes after creation or verification). */
  session(id: string): Promise<SessionResource | null>;
}

interface SessionRecord { requestId: string; createdAt: number; expiresAt: number }
interface RequestRecord { id: string; scenario: string; jwt: string; payload: Record<string, unknown>; expiresAt: number }

/** The one presentation of a vp_token of exactly `{ "credential": ["<presentation>"] }`, or null. */
function onlyPresentation(vpToken: unknown): string | null {
  if (typeof vpToken !== 'object' || vpToken === null || Array.isArray(vpToken) || Object.keys(vpToken).length !== 1) return null;
  const list = (vpToken as Record<string, unknown>)[CREDENTIAL_QUERY_ID];
  return Array.isArray(list) && list.length === 1 && typeof list[0] === 'string' ? list[0] : null;
}

/**
 * Validates the request certificate (profile `request`) and looks it up in the trust list: it must
 * be there with purpose `request` and the organisation of the certificate, or this throws.
 * createSession repeats the lookup at most once an hour.
 */
export async function createPresentationVerifier(config: PresentationVerifierConfig): Promise<PresentationVerifier> {
  const { apiOrigin, signer, verification, random, clock, store } = config;
  if (!/^https:\/\/[A-Za-z0-9.-]+(:[0-9]{1,5})?$/.test(apiOrigin)) throw new TypeError('apiOrigin must be https://host[:port]');
  if (signer?.alg !== 'ES256' || !Array.isArray(signer.x5c) || signer.x5c.length !== 2) throw new TypeError('signer must be an ES256 signer with x5c [leaf, issuing CA]');
  const chain = await verification.chainValidator.validate({ x5c: signer.x5c, profile: 'request', now: clock.now() });
  if (!chain.ok || !chain.fingerprint || !chain.leaf) throw new Error(`the request certificate does not validate: ${chain.code}`);
  const fingerprint = chain.fingerprint;
  const organisation = chain.leaf.subject.organizationIdentifier;
  /** The trust-list name of this verifier, or null when it is not listed with purpose `request`. */
  const listedName = async (): Promise<string | null> => {
    const entry = await verification.trustRegistry.lookup(fingerprint, clock.now());
    return entry && entry.mucDich === 'request' && entry.maToChuc === organisation ? entry.ten : null;
  };
  const first = await listedName();
  if (first === null) throw new Error('the request certificate is not in the trust list with purpose request');
  let listing = { name: first, listed: true, checkedAt: clock.now().getTime() };
  /** Re-checked at most once per TRUST_RECHECK_SECONDS; an unreadable trust list keeps the last answer and is tried again next time. */
  async function currentListing() {
    if (clock.now().getTime() - listing.checkedAt < TRUST_RECHECK_SECONDS * 1000 && clock.now().getTime() >= listing.checkedAt) return listing;
    try {
      const n = await listedName();
      listing = { name: n ?? listing.name, listed: n !== null, checkedAt: clock.now().getTime() };
    } catch {
      // keep the last answer
    }
    return listing;
  }
  const queries = Object.fromEntries(Object.entries(config.scenarios).map(([name, s]) => {
    // The wallet refuses claim sets that are not a strictly shrinking chain (ADR-0008 section 5).
    if (!claimSetsNested(s.claimSets)) throw new TypeError(`scenario ${name}: claim sets must each be a proper subset of the one before, at most ${MAX_CLAIM_SETS}`);
    return [name, dcqlQueryOf(s)];
  }));
  const clientId = `x509_hash:${fingerprint}`;
  const key = (kind: string, id: string) => `vp:${clientId}:${kind}:${id}`;
  const newId = () => base64UrlEncode(random.bytes(16));
  const read = async <T>(k: string): Promise<T | null> => {
    const v = await store.get(k);
    return v === null ? null : (JSON.parse(v) as T);
  };
  const invalid = () => oauthError(400, 'invalid_request', 'the response is not acceptable');

  /**
   * verifyPresentation, then the query on the verified claims; the result to store, or the
   * holder-binding code when that check did not pass (the sender did not prove possession of the
   * presented credential's key for this nonce and audience: such a response must not finalise).
   */
  async function evaluate(presentation: string, request: RequestRecord, now: Date): Promise<SessionResult | { refused: ErrorCode }> {
    const verifiedAt = now.toISOString();
    const checks = (cs: Check[]) => cs.map(({ id, ok, code }) => ({ id, ok, code }));
    const r = await verifyPresentation(presentation, {
      ...verification, now, presentation: { nonce: request.payload['nonce'] as string, audience: clientId },
    });
    const binding = r.checks.find((c) => c.id === 'holder_binding');
    // When holder binding was skipped (an earlier step failed), report that step's code instead.
    if (binding?.ok !== true) return { refused: (binding?.skipped ? r.checks.find((c) => !c.ok)?.code : binding?.code) ?? 'KB_INVALID' };
    const claims = r.credential?.claims;
    if (!r.ok || !claims) return { ok: false, checks: [...checks(r.checks), { id: 'query', ok: false, code: 'SKIPPED' }], verifiedAt };
    const index = satisfiedClaimSet(queries[request.scenario]!, { vct: r.credential!.vct, claims });
    if (index === null) return { ok: false, checks: [...checks(r.checks), { id: 'query', ok: false, code: 'QUERY_NOT_SATISFIED' }], verifiedAt };
    // Only the claims of the satisfied claim set are kept; any other disclosed claim is dropped. Each
    // of them must be a non-empty string: a set that would be stored with a claim missing is not satisfied.
    const names = config.scenarios[request.scenario]!.claimSets[index]!;
    if (!names.every((n) => typeof claims[n] === 'string' && claims[n] !== '')) {
      return { ok: false, checks: [...checks(r.checks), { id: 'query', ok: false, code: 'QUERY_NOT_SATISFIED' }], verifiedAt };
    }
    const kept = Object.fromEntries(names.map((n) => [n, claims[n] as string]));
    const c = r.credential!;
    const issuer = c.trustPath === 'did' ? { trustPath: 'did' as const, issuerDid: c.issuerDid } : { trustPath: 'x509' as const, issuer: { ...c.issuer! } };
    return { ok: true, checks: [...checks(r.checks), { id: 'query', ok: true, code: null }], claims: kept, ...issuer, verifiedAt };
  }

  /**
   * Makes `result` the session's final result: the open marker is taken (exactly once under
   * concurrency) and the result written; if the write fails the marker is put back, so the session
   * can still complete. Then the session key and the request record are deleted. False when another
   * response finalised it first.
   */
  async function finalise(requestId: string, request: RequestRecord, result: SessionResult): Promise<boolean> {
    if ((await store.take(key('open', requestId))) === null) return false;
    try {
      await store.put(key('result', request.id), JSON.stringify(result), SESSION_KEEP_SECONDS);
    } catch (e) {
      const left = Math.ceil((request.expiresAt - clock.now().getTime()) / 1000);
      if (left > 0) await store.put(key('open', requestId), '1', left).catch(() => {});
      throw e;
    }
    // The result is written: a failing cleanup must not turn it into an error for the wallet. The
    // records it would have removed expire by their TTL (the session 30 minutes after creation).
    try {
      const session = await read<SessionRecord>(key('session', request.id));
      if (session) await store.put(key('session', request.id), JSON.stringify(session), SESSION_KEEP_SECONDS);
      await store.take(key('key', requestId));
      await store.take(key('request', requestId));
    } catch {
      // swallowed, see above
    }
    return true;
  }

  /** A response that did not finalise: 400; the tenth such response finalises the session as TOO_MANY_ATTEMPTS. */
  async function refused(requestId: string, request: RequestRecord, now: Date, code: ErrorCode): Promise<HandledResponse> {
    const attempts = await store.increment(key('attempts', requestId), SESSION_SECONDS);
    if (attempts >= MAX_RESPONSE_ATTEMPTS) {
      const ended = await finalise(requestId, request, { ok: false, checks: [{ id: 'holder_binding', ok: false, code: 'TOO_MANY_ATTEMPTS' }], verifiedAt: now.toISOString() });
      if (ended) return { response: invalid(), outcome: { sessionId: request.id, final: true, ok: false, code: 'TOO_MANY_ATTEMPTS' } };
    }
    return { response: invalid(), outcome: { sessionId: request.id, final: false, code } };
  }

  return {
    clientId,
    get name() {
      return listing.name;
    },

    async createSession({ scenario }) {
      if (typeof scenario !== 'string' || !Object.hasOwn(queries, scenario)) return { ok: false, reason: 'unknown_scenario' };
      if (!(await currentListing()).listed) return { ok: false, reason: 'verifier_not_listed' };
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
      return { ok: true, session: { id, requestId, qr, expiresAt: new Date(expiresAt).toISOString(), serverTime: now.toISOString() } };
    },

    async requestObject(requestId) {
      const request = ID.test(requestId) ? await read<RequestRecord>(key('request', requestId)) : null;
      // Served until the session is final: the open marker is gone once a response was processed.
      if (!request || request.expiresAt <= clock.now().getTime() || (await store.get(key('open', requestId))) === null) return null;
      await store.put(key('retrieved', request.id), '1', SESSION_KEEP_SECONDS);
      return { status: 200, headers: { 'Content-Type': 'application/oauth-authz-req+jwt', 'Cache-Control': 'no-store' }, body: request.jwt };
    },

    async handleResponse(requestId, req) {
      const now = clock.now();
      const request = ID.test(requestId) ? await read<RequestRecord>(key('request', requestId)) : null;
      if (!request || request.expiresAt <= now.getTime() || (await store.get(key('open', requestId))) === null) return null;
      // From here every refusal counts against the request (refused): a flood ends the session.
      if (!(req.headers['content-type'] ?? '').toLowerCase().startsWith('application/x-www-form-urlencoded') || req.body.length > MAX_RESPONSE_BYTES) return refused(requestId, request, now, 'MALFORMED');
      const params = new URLSearchParams(req.body);
      const names = [...params.keys()];
      // direct_post.jwt only: exactly one `response` parameter holding a compact JWE (no downgrade to direct_post).
      const response = params.get('response');
      if (names.length !== 1 || response === null || response.split('.').length !== 5) return refused(requestId, request, now, 'MALFORMED');
      const privateJwk = await read<JWK>(key('key', requestId));
      if (!privateJwk) return null;
      const presentation = onlyPresentation(await parseResponse({ form: { response }, requestPayload: request.payload, privateJwk, hasher: verification.hasher }));
      if (presentation === null) return refused(requestId, request, now, 'MALFORMED');
      // The request object is public: only a response proving possession of the presented
      // credential's key for this nonce and audience may finalise the session.
      const result = await evaluate(presentation, request, now);
      if ('refused' in result) return refused(requestId, request, now, result.refused);
      // Exactly once: of concurrent responses only the one that takes the open marker is stored.
      if (!(await finalise(requestId, request, result))) return { response: invalid(), outcome: { sessionId: request.id, final: false } };
      const code = result.checks.find((c) => !c.ok)?.code ?? undefined;
      return { response: jsonResponse(200, {}), outcome: { sessionId: request.id, final: true, ok: result.ok, ...(code ? { code } : {}) } };
    },

    async session(id) {
      const s = ID.test(id) ? await read<SessionRecord>(key('session', id)) : null;
      if (!s) return null;
      const now = clock.now();
      const result = await read<SessionResult>(key('result', id));
      const status: SessionStatus = result
        ? result.ok ? 'verified' : 'failed'
        : s.expiresAt <= now.getTime() ? 'expired' : (await store.get(key('retrieved', id))) !== null ? 'request_retrieved' : 'pending';
      return { id, status, verifier: { name: listing.name }, expiresAt: new Date(s.expiresAt).toISOString(), serverTime: now.toISOString(), ...(result ? { result } : {}) };
    },
  };
}

// Verifier-session client for web pages (identra-server docs/vc-api.md sections 2 and 6).
// Every response is validated before use; error messages never carry response text or claims.
// Time decisions (expiry) use the server's clock: each response carries `serverTime` (section 2).
import type { Check, CheckId, ErrorCode } from '@identra/sdk-core';

export type { Check, CheckId, ErrorCode };

export type SessionStatus = 'pending' | 'request_retrieved' | 'verified' | 'failed' | 'expired';
/** Every claim value is a string (section 6). */
export type ClaimValue = string;
export interface SessionIssuer { maToChuc: string; ten: string }
export interface SessionResult {
  ok: boolean;
  checks: Check[];
  /** Present only when `ok`. */
  claims?: Record<string, ClaimValue>;
  /** Present only when `ok`. */
  issuer?: SessionIssuer;
  verifiedAt: string;
}
export interface VerificationSession {
  id: string;
  status: SessionStatus;
  verifier: { name: string };
  expiresAt: string;
  serverTime: string;
  /** Present only when the session is final (`verified` or `failed`). */
  result?: SessionResult;
}
export interface CreatedSession { id: string; qr: string; expiresAt: string; serverTime: string }

/** The closed list of `code` values of section 2. */
export const API_ERROR_CODES = [
  'INVALID_CREDENTIALS',
  'SESSION_EXPIRED',
  'FORBIDDEN',
  'NOT_FOUND',
  'CONFLICT',
  'VALIDATION_FAILED',
  'RATE_LIMITED',
  'INTERNAL_ERROR',
  'UNAVAILABLE',
] as const;
export type ApiErrorCode = (typeof API_ERROR_CODES)[number];

/** The checks a presentation of a credential always lists (SDK architecture section 3, steps 1-9). */
export const PRESENTATION_CHECK_IDS = [
  'structure',
  'algorithm',
  'certificate_chain',
  'signature',
  'validity_time',
  'credential_type',
  'issuer_trust',
  'status',
  'holder_binding',
] as const satisfies readonly CheckId[];

export type VerifierClientErrorKind = 'network' | 'timeout' | 'http' | 'rate_limited' | 'not_found' | 'malformed';

export class VerifierClientError extends Error {
  readonly kind: VerifierClientErrorKind;
  readonly status?: number;
  /** A code from `API_ERROR_CODES` when the server sent the section 2 error body. */
  readonly code?: ApiErrorCode;
  /** From a 429's `Retry-After` header. */
  readonly retryAfterSeconds?: number;
  constructor(
    kind: VerifierClientErrorKind,
    message: string,
    details: { status?: number; code?: ApiErrorCode; retryAfterSeconds?: number } = {},
  ) {
    super(message);
    this.name = 'VerifierClientError';
    this.kind = kind;
    if (details.status !== undefined) this.status = details.status;
    if (details.code !== undefined) this.code = details.code;
    if (details.retryAfterSeconds !== undefined) this.retryAfterSeconds = details.retryAfterSeconds;
  }
}

export interface WatchSessionOptions {
  intervalMs?: number;
  maxBackoffMs?: number;
  signal?: AbortSignal;
  /**
   * The session's `expiresAt` and `serverTime` from `createSession`, so the watch stops at expiry even
   * when its very first request hangs.
   */
  expiresAt?: string;
  serverTime?: string;
  /** Called with the first session and on every status change. */
  onUpdate?: (session: VerificationSession) => void;
  /** Called on a retryable failure, before waiting `retryInMs`. `attempt` counts consecutive failures from 1. */
  onError?: (error: VerifierClientError, info: { attempt: number; retryInMs: number }) => void;
  /** Called on the first successful response after one or more failures. */
  onRecover?: () => void;
}

export interface VerifierClient {
  createSession(input: { verifier: string; scenario: string }, options?: { signal?: AbortSignal }): Promise<CreatedSession>;
  getSession(id: string, options?: { signal?: AbortSignal }): Promise<VerificationSession>;
  watchSession(id: string, options?: WatchSessionOptions): Promise<VerificationSession>;
}

export interface VerifierClientOptions {
  /** Where requests go (the canonical API origin, or what stands in for it in development). */
  baseUrl: string;
  /** The canonical API origin that `request_uri` in a QR must point at (section 1). */
  apiOrigin?: string;
  fetch?: typeof fetch;
  /** The local clock; the client corrects it with each response's `serverTime`. */
  now?: () => number;
  /** Per-request limit; default 10 s. */
  requestTimeoutMs?: number;
}

export const DEFAULT_API_ORIGIN = 'https://api-identra.awncorp.vn';
export const MAX_QR_LENGTH = 2048;

const STATUSES: readonly string[] = ['pending', 'request_retrieved', 'verified', 'failed', 'expired'];
const CHECK_CODE = /^[A-Z0-9_]{1,64}$/;
const CHECK_ID = /^[a-z_]{1,64}$/;
const CLAIM_KEY = /^[A-Za-z0-9_]{1,64}$/;
// ma_to_chuc of the trust list: VATVN-<10-digit tax code>[-<3-digit branch>] (ADR-0015 section 9).
const ORG_ID = /^VATVN-[0-9]{10}(-[0-9]{3})?$/;
const SESSION_ID = /^[A-Za-z0-9_-]{16,256}$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
/** C0/C1 controls, bidirectional overrides and isolates, zero-width characters and the BOM. */
const UNSAFE_TEXT = /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/;

export function isTerminalStatus(s: SessionStatus): boolean {
  return s === 'verified' || s === 'failed' || s === 'expired';
}

/** Milliseconds to add to the local clock to read the server's (`serverTime` − local time at receipt). */
export function serverClockOffset(serverTime: string, localNow: number): number {
  const server = Date.parse(serverTime);
  return Number.isNaN(server) ? 0 : server - localNow;
}

/** True when `qr` is exactly `openid4vp://?client_id=x509_hash:…&request_uri=<apiOrigin>/oid4vp/request/<id>`. */
export function isValidVerifierQr(qr: string, apiOrigin = DEFAULT_API_ORIGIN): boolean {
  const prefix = 'openid4vp://?';
  if (qr.length > MAX_QR_LENGTH || !qr.startsWith(prefix)) return false;
  const params = new URLSearchParams(qr.slice(prefix.length));
  const names: string[] = [];
  params.forEach((_, name) => names.push(name));
  if (names.length !== 2 || !names.includes('client_id') || !names.includes('request_uri')) return false;
  if (!/^x509_hash:[A-Za-z0-9_-]{43}$/.test(params.get('client_id') ?? '')) return false;
  const requestBase = `${apiOrigin.replace(/\/+$/, '')}/oid4vp/request/`;
  const requestUri = params.get('request_uri') ?? '';
  return requestUri.startsWith(requestBase) && /^[A-Za-z0-9_-]{16,256}$/.test(requestUri.slice(requestBase.length));
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const isDate = (v: unknown): v is string => typeof v === 'string' && v.length <= 64 && !Number.isNaN(Date.parse(v));
const has = (o: Obj, k: string) => Object.prototype.hasOwnProperty.call(o, k);
const isText = (v: unknown, max: number): v is string =>
  typeof v === 'string' && v.length > 0 && v.length <= max && !UNSAFE_TEXT.test(v);

function malformed(path: string): never {
  throw new VerifierClientError('malformed', `malformed session response: ${path}`);
}

function parseCreated(raw: unknown, apiOrigin: string): CreatedSession {
  if (!isObj(raw)) malformed('body');
  const { id, qr, expiresAt, serverTime } = raw;
  if (typeof id !== 'string' || !SESSION_ID.test(id)) malformed('id');
  if (typeof qr !== 'string' || !isValidVerifierQr(qr, apiOrigin)) malformed('qr');
  if (!isDate(expiresAt)) malformed('expiresAt');
  if (!isDate(serverTime)) malformed('serverTime');
  return { id, qr, expiresAt, serverTime };
}

function parseCheck(raw: unknown, path: string): Check {
  if (!isObj(raw)) malformed(path);
  const { id, ok, code, skipped } = raw;
  if (typeof id !== 'string' || !CHECK_ID.test(id)) malformed(`${path}.id`);
  if (typeof ok !== 'boolean') malformed(`${path}.ok`);
  if (code !== null && (typeof code !== 'string' || !CHECK_CODE.test(code))) malformed(`${path}.code`);
  if (ok && code !== null) malformed(`${path}.code`);
  if (skipped !== undefined && skipped !== true) malformed(`${path}.skipped`);
  // Unknown but well-formed ids and codes are kept; `detail` is dropped.
  const check: Check = { id: id as CheckId, ok, code: code as ErrorCode | null };
  if (skipped) check.skipped = true;
  return check;
}

function parseClaims(raw: unknown): Record<string, ClaimValue> {
  if (!isObj(raw)) malformed('result.claims');
  const keys = Object.keys(raw);
  if (keys.length === 0 || keys.length > 50) malformed('result.claims');
  const out: Record<string, ClaimValue> = {};
  for (const k of keys) {
    // Key names and values come from the server, so they stay out of the message.
    if (!CLAIM_KEY.test(k) || FORBIDDEN_KEYS.has(k)) malformed('result.claims');
    const v = raw[k];
    if (!isText(v, 10_000)) malformed('result.claims');
    out[k] = v;
  }
  return out;
}

function parseResult(raw: unknown): SessionResult {
  if (!isObj(raw)) malformed('result');
  const { ok, checks, claims, issuer, verifiedAt } = raw;
  if (typeof ok !== 'boolean') malformed('result.ok');
  if (!Array.isArray(checks) || checks.length === 0 || checks.length > 32) malformed('result.checks');
  const parsed = checks.map((c, i) => parseCheck(c, `result.checks[${i}]`));
  if (new Set(parsed.map((c) => c.id)).size !== parsed.length) malformed('result.checks');
  if (!isDate(verifiedAt)) malformed('result.verifiedAt');

  if (!ok) {
    // A failure lists at least one failing check and never carries claims or an issuer.
    if (parsed.every((c) => c.ok)) malformed('result.ok');
    if (has(raw, 'claims')) malformed('result.claims');
    if (has(raw, 'issuer')) malformed('result.issuer');
    return { ok, checks: parsed, verifiedAt };
  }

  // A success must list every presentation check, each passed.
  if (parsed.some((c) => !c.ok)) malformed('result.ok');
  for (const id of PRESENTATION_CHECK_IDS) if (!parsed.some((c) => c.id === id)) malformed('result.checks');
  if (!isObj(issuer) || typeof issuer['maToChuc'] !== 'string' || !ORG_ID.test(issuer['maToChuc']) || !isText(issuer['ten'], 500)) {
    malformed('result.issuer');
  }
  return {
    ok,
    checks: parsed,
    claims: parseClaims(claims),
    issuer: { maToChuc: issuer['maToChuc'], ten: issuer['ten'] as string },
    verifiedAt,
  };
}

function parseSession(raw: unknown): VerificationSession {
  if (!isObj(raw)) malformed('body');
  const { id, status, verifier, expiresAt, serverTime } = raw;
  if (typeof id !== 'string' || !SESSION_ID.test(id)) malformed('id');
  if (typeof status !== 'string' || !STATUSES.includes(status)) malformed('status');
  if (!isObj(verifier) || !isText(verifier['name'], 500)) malformed('verifier');
  if (!isDate(expiresAt)) malformed('expiresAt');
  if (!isDate(serverTime)) malformed('serverTime');
  const session: VerificationSession = {
    id,
    status: status as SessionStatus,
    verifier: { name: verifier['name'] as string },
    expiresAt,
    serverTime,
  };
  const isFinal = status === 'verified' || status === 'failed';
  if (isFinal !== has(raw, 'result')) malformed('result');
  if (isFinal) {
    session.result = parseResult(raw['result']);
    // `verified` means ok, `failed` means not ok.
    if (session.result.ok !== (status === 'verified')) malformed('status');
  }
  return session;
}

function retryAfter(header: string | null): number | undefined {
  const seconds = Number(header);
  return header !== null && Number.isInteger(seconds) && seconds >= 0 && seconds <= 3600 ? seconds : undefined;
}

function httpError(status: number, text: string, retryAfterHeader: string | null): VerifierClientError {
  let code: ApiErrorCode | undefined;
  try {
    const body: unknown = JSON.parse(text);
    if (isObj(body) && (API_ERROR_CODES as readonly unknown[]).includes(body['code'])) code = body['code'] as ApiErrorCode;
  } catch {
    // Not the section 2 error JSON: no code.
  }
  const kind = status === 404 ? 'not_found' : status === 429 ? 'rate_limited' : 'http';
  const details: { status: number; code?: ApiErrorCode; retryAfterSeconds?: number } = { status };
  if (code !== undefined) details.code = code;
  const seconds = status === 429 ? retryAfter(retryAfterHeader) : undefined;
  if (seconds !== undefined) details.retryAfterSeconds = seconds;
  return new VerifierClientError(kind, `HTTP ${status}`, details);
}

const isRetryable = (e: VerifierClientError) =>
  e.kind === 'network' || e.kind === 'timeout' || e.kind === 'rate_limited' || (e.kind === 'http' && (e.status ?? 0) >= 500);

/** Resolves after `ms`; rejects with the abort reason and clears the timer on abort. */
function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

export function createVerifierClient(options: VerifierClientOptions): VerifierClient {
  const base = options.baseUrl.replace(/\/+$/, '');
  const apiOrigin = options.apiOrigin ?? DEFAULT_API_ORIGIN;
  const fetchFn = options.fetch ?? ((...a: Parameters<typeof fetch>) => globalThis.fetch(...a));
  const now = options.now ?? Date.now;
  const requestTimeoutMs = options.requestTimeoutMs ?? 10_000;

  async function request(
    method: 'GET' | 'POST',
    path: string,
    body: unknown,
    signal: AbortSignal | undefined,
    timeoutMs = requestTimeoutMs,
  ): Promise<unknown> {
    signal?.throwIfAborted();
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    // The request ends on the caller's abort or on its own timeout, whichever comes first.
    const controller = new AbortController();
    const onAbort = () => controller.abort(signal?.reason);
    signal?.addEventListener('abort', onAbort, { once: true });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, Math.max(0, timeoutMs));
    let res: Response;
    let text: string;
    try {
      res = await fetchFn(base + path, {
        method,
        headers,
        body: body === undefined ? null : JSON.stringify(body),
        credentials: 'omit',
        signal: controller.signal,
      });
      text = await res.text();
    } catch {
      signal?.throwIfAborted();
      if (timedOut) throw new VerifierClientError('timeout', 'request timed out');
      throw new VerifierClientError('network', 'network error');
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    }
    signal?.throwIfAborted();
    if (!res.ok) throw httpError(res.status, text, res.headers.get('Retry-After'));
    try {
      return JSON.parse(text);
    } catch {
      return malformed('body is not JSON');
    }
  }

  const sessionPath = (id: string) => `/v1/verification/sessions/${encodeURIComponent(id)}`;
  const getSession: VerifierClient['getSession'] = async (id, opts) =>
    parseSession(await request('GET', sessionPath(id), undefined, opts?.signal));

  return {
    async createSession(input, opts) {
      const body = { verifier: input.verifier, scenario: input.scenario };
      return parseCreated(await request('POST', '/v1/verification/sessions', body, opts?.signal), apiOrigin);
    },

    getSession,

    async watchSession(id, opts = {}) {
      const { intervalMs = 1000, maxBackoffMs = 8000, signal, onUpdate, onError, onRecover } = opts;
      let last: VerificationSession | undefined;
      let expiresAt = opts.expiresAt !== undefined ? Date.parse(opts.expiresAt) : Infinity;
      let offset = opts.serverTime !== undefined ? serverClockOffset(opts.serverTime, now()) : 0;
      const serverNow = () => now() + offset;
      let attempt = 0;
      for (;;) {
        const left = expiresAt - serverNow();
        if (left <= 0) return expire();
        let wait: number;
        let failure: VerifierClientError | undefined;
        try {
          // A request never runs past expiry: its timeout is cut to the time left.
          const session = parseSession(
            await request('GET', sessionPath(id), undefined, signal, Math.min(requestTimeoutMs, left)),
          );
          signal?.throwIfAborted();
          offset = serverClockOffset(session.serverTime, now());
          expiresAt = Date.parse(session.expiresAt);
          if (attempt > 0) onRecover?.();
          const changed = last?.status !== session.status;
          last = session;
          if (changed) onUpdate?.(session);
          if (isTerminalStatus(session.status)) return session;
          attempt = 0;
          wait = intervalMs;
        } catch (e) {
          signal?.throwIfAborted();
          if (!(e instanceof VerifierClientError) || !isRetryable(e)) throw e;
          if (expiresAt - serverNow() <= 0) return expire();
          failure = e;
          attempt++;
          wait = Math.min(intervalMs * 2 ** attempt, maxBackoffMs);
          if (e.retryAfterSeconds !== undefined) wait = Math.max(wait, e.retryAfterSeconds * 1000);
        }
        // Never schedule a request at or after expiry: clamp the wait to it, then synthesize `expired`.
        // A wait cut short by expiry ends the watch even if the timer fires a millisecond early.
        const remaining = expiresAt - serverNow();
        if (remaining <= 0) return expire();
        const waitsUntilExpiry = remaining <= wait;
        wait = Math.min(wait, remaining);
        if (failure) onError?.(failure, { attempt, retryInMs: wait });
        await sleep(wait, signal);
        if (waitsUntilExpiry) return expire();
      }

      // Not final when this runs, so it carries no result. Without any good response yet, the session
      // is described from the creation data only.
      function expire(): VerificationSession {
        const expired: VerificationSession = last
          ? { id: last.id, status: 'expired', verifier: last.verifier, expiresAt: last.expiresAt, serverTime: new Date(serverNow()).toISOString() }
          : {
              id,
              status: 'expired',
              verifier: { name: '' },
              expiresAt: Number.isFinite(expiresAt) ? new Date(expiresAt).toISOString() : '',
              serverTime: new Date(serverNow()).toISOString(),
            };
        onUpdate?.(expired);
        return expired;
      }
    },
  };
}

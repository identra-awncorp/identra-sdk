// Verifier-session client for web pages (identra-server docs/vc-api.md sections 2 and 6).
// Every response is validated before use; error messages never carry response text or claims.
import type { Check, CheckId, ErrorCode } from '@identra/sdk-core';

export type { Check, CheckId, ErrorCode };

export type SessionStatus = 'pending' | 'request_retrieved' | 'verified' | 'failed' | 'expired';
export type ClaimValue = string | number | boolean;
export interface SessionIssuer { maToChuc: string; ten: string }
export interface SessionResult {
  ok: boolean;
  checks: Check[];
  claims?: Record<string, ClaimValue>;
  issuer: SessionIssuer | null;
  verifiedAt: string;
}
export interface VerificationSession {
  id: string;
  status: SessionStatus;
  verifier: { name: string };
  expiresAt: string;
  result?: SessionResult;
}
export interface CreatedSession { id: string; qr: string; expiresAt: string }

export type VerifierClientErrorKind = 'network' | 'http' | 'rate_limited' | 'not_found' | 'malformed';

export class VerifierClientError extends Error {
  readonly kind: VerifierClientErrorKind;
  readonly status?: number;
  readonly code?: string;
  constructor(kind: VerifierClientErrorKind, message: string, status?: number, code?: string) {
    super(message);
    this.name = 'VerifierClientError';
    this.kind = kind;
    if (status !== undefined) this.status = status;
    if (code !== undefined) this.code = code;
  }
}

export interface WatchSessionOptions {
  intervalMs?: number;
  maxBackoffMs?: number;
  signal?: AbortSignal;
  /** Called with the first session and on every status change. */
  onUpdate?: (session: VerificationSession) => void;
  /** Called on a retryable failure, before waiting `retryInMs`. `attempt` counts consecutive failures from 1. */
  onError?: (error: VerifierClientError, info: { attempt: number; retryInMs: number }) => void;
}

export interface VerifierClient {
  createSession(input: { verifier: string; scenario: string }, options?: { signal?: AbortSignal }): Promise<CreatedSession>;
  getSession(id: string, options?: { signal?: AbortSignal }): Promise<VerificationSession>;
  watchSession(id: string, options?: WatchSessionOptions): Promise<VerificationSession>;
}

const STATUSES: readonly string[] = ['pending', 'request_retrieved', 'verified', 'failed', 'expired'];
const CODE = /^[A-Z0-9_]{1,64}$/;
const CHECK_ID = /^[a-z_]{1,64}$/;
const CLAIM_KEY = /^[A-Za-z0-9_]{1,64}$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function isTerminalStatus(s: SessionStatus): boolean {
  return s === 'verified' || s === 'failed' || s === 'expired';
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const isDate = (v: unknown): v is string => typeof v === 'string' && v.length <= 64 && !Number.isNaN(Date.parse(v));
const has = (o: Obj, k: string) => Object.prototype.hasOwnProperty.call(o, k);

function malformed(path: string): never {
  throw new VerifierClientError('malformed', `malformed session response: ${path}`);
}

function parseCreated(raw: unknown): CreatedSession {
  if (!isObj(raw)) malformed('body');
  const { id, qr, expiresAt } = raw;
  if (typeof id !== 'string' || id.length === 0 || id.length > 256) malformed('id');
  if (typeof qr !== 'string' || !qr.startsWith('openid4vp://') || qr.length > 4096) malformed('qr');
  if (!isDate(expiresAt)) malformed('expiresAt');
  return { id, qr, expiresAt };
}

function parseCheck(raw: unknown, path: string): Check {
  if (!isObj(raw)) malformed(path);
  const { id, ok, code, skipped } = raw;
  if (typeof id !== 'string' || !CHECK_ID.test(id)) malformed(`${path}.id`);
  if (typeof ok !== 'boolean') malformed(`${path}.ok`);
  if (code !== null && (typeof code !== 'string' || !CODE.test(code))) malformed(`${path}.code`);
  if (skipped !== undefined && skipped !== true) malformed(`${path}.skipped`);
  // Unknown but well-formed ids and codes are kept; `detail` is dropped.
  const check: Check = { id: id as CheckId, ok, code: code as ErrorCode | null };
  if (skipped) check.skipped = true;
  return check;
}

function parseClaims(raw: unknown): Record<string, ClaimValue> {
  if (!isObj(raw)) malformed('result.claims');
  const keys = Object.keys(raw);
  if (keys.length > 50) malformed('result.claims');
  const out: Record<string, ClaimValue> = {};
  for (const k of keys) {
    // Key names come from the server, so they stay out of the message.
    if (!CLAIM_KEY.test(k) || FORBIDDEN_KEYS.has(k)) malformed('result.claims');
    const v = raw[k];
    const valid =
      (typeof v === 'string' && v.length <= 10_000) || (typeof v === 'number' && Number.isFinite(v)) || typeof v === 'boolean';
    if (!valid) malformed('result.claims');
    out[k] = v as ClaimValue;
  }
  return out;
}

function parseResult(raw: unknown): SessionResult {
  if (!isObj(raw)) malformed('result');
  const { ok, checks, claims, issuer, verifiedAt } = raw;
  if (typeof ok !== 'boolean') malformed('result.ok');
  if (!Array.isArray(checks) || checks.length > 32) malformed('result.checks');
  const parsed = checks.map((c, i) => parseCheck(c, `result.checks[${i}]`));
  if (ok && parsed.some((c) => !c.ok)) malformed('result.ok');
  let iss: SessionIssuer | null = null;
  if (issuer !== undefined && issuer !== null) {
    if (!isObj(issuer) || typeof issuer['maToChuc'] !== 'string' || typeof issuer['ten'] !== 'string') malformed('result.issuer');
    iss = { maToChuc: issuer['maToChuc'], ten: issuer['ten'] };
  }
  if (!isDate(verifiedAt)) malformed('result.verifiedAt');
  const result: SessionResult = { ok, checks: parsed, issuer: iss, verifiedAt };
  if (has(raw, 'claims')) {
    if (!ok) malformed('result.claims');
    result.claims = parseClaims(claims);
  }
  return result;
}

function parseSession(raw: unknown): VerificationSession {
  if (!isObj(raw)) malformed('body');
  const { id, status, verifier, expiresAt } = raw;
  if (typeof id !== 'string') malformed('id');
  if (typeof status !== 'string' || !STATUSES.includes(status)) malformed('status');
  if (!isObj(verifier) || typeof verifier['name'] !== 'string') malformed('verifier');
  if (!isDate(expiresAt)) malformed('expiresAt');
  const session: VerificationSession = { id, status: status as SessionStatus, verifier: { name: verifier['name'] }, expiresAt };
  const needsResult = status === 'verified' || status === 'failed';
  if (needsResult !== has(raw, 'result')) malformed('result');
  if (needsResult) session.result = parseResult(raw['result']);
  return session;
}

function httpError(status: number, text: string): VerifierClientError {
  let code: string | undefined;
  try {
    const body: unknown = JSON.parse(text);
    if (isObj(body) && typeof body['code'] === 'string' && CODE.test(body['code'])) code = body['code'];
  } catch {
    // Not the section 2 error JSON: no code.
  }
  const kind = status === 404 ? 'not_found' : status === 429 ? 'rate_limited' : 'http';
  return new VerifierClientError(kind, `HTTP ${status}`, status, code);
}

const isRetryable = (e: VerifierClientError) =>
  e.kind === 'network' || e.kind === 'rate_limited' || (e.kind === 'http' && (e.status ?? 0) >= 500);

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

export function createVerifierClient(options: { baseUrl: string; fetch?: typeof fetch; now?: () => number }): VerifierClient {
  const base = options.baseUrl.replace(/\/+$/, '');
  const fetchFn = options.fetch ?? ((...a: Parameters<typeof fetch>) => globalThis.fetch(...a));
  const now = options.now ?? Date.now;

  async function request(method: 'GET' | 'POST', path: string, body: unknown, signal: AbortSignal | undefined): Promise<unknown> {
    signal?.throwIfAborted();
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let res: Response;
    let text: string;
    try {
      res = await fetchFn(base + path, {
        method,
        headers,
        body: body === undefined ? null : JSON.stringify(body),
        credentials: 'omit',
        signal: signal ?? null,
      });
      text = await res.text();
    } catch {
      signal?.throwIfAborted();
      throw new VerifierClientError('network', 'network error');
    }
    signal?.throwIfAborted();
    if (!res.ok) throw httpError(res.status, text);
    try {
      return JSON.parse(text);
    } catch {
      return malformed('body is not JSON');
    }
  }

  const getSession: VerifierClient['getSession'] = async (id, opts) =>
    parseSession(await request('GET', `/v1/verification/sessions/${encodeURIComponent(id)}`, undefined, opts?.signal));

  return {
    async createSession(input, opts) {
      const body = { verifier: input.verifier, scenario: input.scenario };
      return parseCreated(await request('POST', '/v1/verification/sessions', body, opts?.signal));
    },

    getSession,

    async watchSession(id, opts = {}) {
      const { intervalMs = 1000, maxBackoffMs = 8000, signal, onUpdate, onError } = opts;
      let last: VerificationSession | undefined;
      let expiresAt = Infinity;
      let attempt = 0;
      for (;;) {
        let wait: number;
        let failure: VerifierClientError | undefined;
        try {
          const session = await getSession(id, signal ? { signal } : {});
          signal?.throwIfAborted();
          const changed = last?.status !== session.status;
          last = session;
          expiresAt = Date.parse(session.expiresAt);
          if (changed) onUpdate?.(session);
          if (isTerminalStatus(session.status)) return session;
          attempt = 0;
          wait = intervalMs;
        } catch (e) {
          signal?.throwIfAborted();
          if (!(e instanceof VerifierClientError) || !isRetryable(e)) throw e;
          failure = e;
          attempt++;
          wait = Math.min(intervalMs * 2 ** attempt, maxBackoffMs);
        }
        // Never schedule a request at or after expiry: clamp the wait to it, then synthesize `expired`.
        // A wait cut short by expiry ends the watch even if the timer fires a millisecond early.
        let waitsUntilExpiry = false;
        if (last) {
          const left = expiresAt - now();
          if (left <= 0) return expire(last);
          waitsUntilExpiry = left <= wait;
          wait = Math.min(wait, left);
        }
        if (failure) onError?.(failure, { attempt, retryInMs: wait });
        await sleep(wait, signal);
        if (last && (waitsUntilExpiry || now() >= expiresAt)) return expire(last);
      }

      // `last` is never terminal here, so it carries no result.
      function expire(s: VerificationSession): VerificationSession {
        const expired: VerificationSession = { ...s, status: 'expired' };
        onUpdate?.(expired);
        return expired;
      }
    },
  };
}

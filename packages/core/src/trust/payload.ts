// The trust list content (ADR-0013 section 7, ADR-0015 sections 6 and 9) and its strict validator.
// Anything unexpected is refused: unknown fields, unknown purposes, a purpose outside its section,
// malformed fingerprints or instants, and one fingerprint listed twice (ambiguous).
import { base64UrlDecode } from '../encoding.js';
import { CONG_DOAN } from '../sd-jwt/credential-types.js';

export interface TrustListCertificate<P extends string> {
  /** base64url (no padding) SHA-256 of the certificate DER: 43 characters. */
  sha256: string;
  muc_dich: P;
}

export interface TrustListIssuer {
  ma_to_chuc: string;
  ten: string;
  chung_thu: TrustListCertificate<'vc' | 'status'>[];
  vct: string[];
  cong_doan?: string[];
  /** ISO 8601 instants in UTC, e.g. 2026-11-19T00:00:00Z. */
  validFrom: string;
  validUntil: string;
}

export interface TrustListVerifier {
  ma_to_chuc: string;
  ten: string;
  chung_thu: TrustListCertificate<'request'>[];
  validFrom?: string;
  validUntil?: string;
}

/** What the trust list operator maintains (the server reads it from a JSON file). */
export interface TrustListContent {
  issuers: TrustListIssuer[];
  verifiers: TrustListVerifier[];
}

export interface TrustListPayload extends TrustListContent {
  iat: number;
  exp: number;
  ttl: number;
}

export const TRUST_LIST_MAX_ENTRIES = 1000;
const MAX_STRING = 500;
const MAX_ARRAY = 100;
const ORG_ID = /^VATVN-[0-9]{10}(-[0-9]{3})?$/;
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

class Invalid extends Error {}
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** A base64url SHA-256 fingerprint: 43 canonical base64url characters decoding to 32 bytes. */
export function isFingerprint(v: unknown): v is string {
  if (typeof v !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(v)) return false;
  try {
    return base64UrlDecode(v).length === 32;
  } catch {
    return false;
  }
}

/** Milliseconds of an ISO 8601 UTC instant; throws Invalid unless it is one (a calendar date that exists). */
function parseInstant(v: unknown, at: string): number {
  if (typeof v !== 'string' || !INSTANT.test(v)) throw new Invalid(`${at} is not an ISO 8601 UTC instant`);
  const d = new Date(v);
  if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 19) !== v.slice(0, 19)) throw new Invalid(`${at} is not a valid instant`);
  return d.getTime();
}

function only(o: Record<string, unknown>, allowed: string[], at: string): void {
  const extra = Object.keys(o).find((k) => !allowed.includes(k));
  if (extra !== undefined) throw new Invalid(`${at} has an unknown field`);
}

function text(v: unknown, at: string): string {
  if (typeof v !== 'string' || v === '' || v.length > MAX_STRING) throw new Invalid(`${at} must be a non-empty string of at most ${MAX_STRING} characters`);
  return v;
}

function list(v: unknown, at: string, max = MAX_ARRAY): unknown[] {
  if (!Array.isArray(v)) throw new Invalid(`${at} must be an array`);
  if (v.length > max) throw new Invalid(`${at} has more than ${max} elements`);
  return v;
}

function certificates(v: unknown, at: string, purposes: readonly string[], seen: Set<string>): void {
  const certs = list(v, at);
  if (certs.length === 0) throw new Invalid(`${at} must not be empty`);
  certs.forEach((c, i) => {
    if (!isObject(c)) throw new Invalid(`${at}[${i}] must be an object`);
    only(c, ['sha256', 'muc_dich'], `${at}[${i}]`);
    if (!isFingerprint(c['sha256'])) throw new Invalid(`${at}[${i}].sha256 is not a base64url SHA-256 fingerprint`);
    if (!['vc', 'status', 'request'].includes(c['muc_dich'] as string)) throw new Invalid(`${at}[${i}].muc_dich is not a known purpose`);
    if (!purposes.includes(c['muc_dich'] as string)) throw new Invalid(`${at}[${i}].muc_dich does not fit this section`);
    if (seen.has(c['sha256'])) throw new Invalid(`${at}[${i}].sha256 is listed more than once in the trust list`);
    seen.add(c['sha256']);
  });
}

function validity(e: Record<string, unknown>, at: string, required: boolean): void {
  if (!required && e['validFrom'] === undefined && e['validUntil'] === undefined) return;
  const from = parseInstant(e['validFrom'], `${at}.validFrom`);
  const until = parseInstant(e['validUntil'], `${at}.validUntil`);
  if (from >= until) throw new Invalid(`${at}.validFrom must be before validUntil`);
}

function checkContent(c: Record<string, unknown>): void {
  const issuers = list(c['issuers'], 'issuers', TRUST_LIST_MAX_ENTRIES);
  const verifiers = list(c['verifiers'], 'verifiers', TRUST_LIST_MAX_ENTRIES);
  if (issuers.length + verifiers.length > TRUST_LIST_MAX_ENTRIES) throw new Invalid(`more than ${TRUST_LIST_MAX_ENTRIES} entries`);
  const seen = new Set<string>();
  issuers.forEach((e, i) => {
    const at = `issuers[${i}]`;
    if (!isObject(e)) throw new Invalid(`${at} must be an object`);
    only(e, ['ma_to_chuc', 'ten', 'chung_thu', 'vct', 'cong_doan', 'validFrom', 'validUntil'], at);
    if (!ORG_ID.test(text(e['ma_to_chuc'], `${at}.ma_to_chuc`))) throw new Invalid(`${at}.ma_to_chuc is not VATVN-<tax code>`);
    text(e['ten'], `${at}.ten`);
    certificates(e['chung_thu'], `${at}.chung_thu`, ['vc', 'status'], seen);
    list(e['vct'], `${at}.vct`).forEach((v, j) => text(v, `${at}.vct[${j}]`));
    if (e['cong_doan'] !== undefined) {
      list(e['cong_doan'], `${at}.cong_doan`).forEach((v, j) => {
        if (!(CONG_DOAN as readonly unknown[]).includes(v)) throw new Invalid(`${at}.cong_doan[${j}] is not a known stage`);
      });
    }
    validity(e, at, true);
  });
  verifiers.forEach((e, i) => {
    const at = `verifiers[${i}]`;
    if (!isObject(e)) throw new Invalid(`${at} must be an object`);
    only(e, ['ma_to_chuc', 'ten', 'chung_thu', 'validFrom', 'validUntil'], at);
    if (!ORG_ID.test(text(e['ma_to_chuc'], `${at}.ma_to_chuc`))) throw new Invalid(`${at}.ma_to_chuc is not VATVN-<tax code>`);
    text(e['ten'], `${at}.ten`);
    certificates(e['chung_thu'], `${at}.chung_thu`, ['request'], seen);
    validity(e, at, false);
  });
}

type Validation<T> = { ok: true; value: T } | { ok: false; detail: string };

function run<T>(v: unknown, check: (o: Record<string, unknown>) => void): Validation<T> {
  try {
    if (!isObject(v)) throw new Invalid('not a JSON object');
    check(v);
    return { ok: true, value: v as T };
  } catch (e) {
    if (e instanceof Invalid) return { ok: false, detail: e.message };
    throw e;
  }
}

/** `{ issuers, verifiers }` exactly. The detail names the offending field, never its value. */
export function validateTrustListContent(v: unknown): Validation<TrustListContent> {
  return run(v, (o) => {
    only(o, ['issuers', 'verifiers'], 'trust list');
    checkContent(o);
  });
}

/** The signed payload: `iat`, `exp`, `ttl` (positive integers) plus the content. */
export function validateTrustListPayload(v: unknown): Validation<TrustListPayload> {
  return run(v, (o) => {
    only(o, ['iat', 'exp', 'ttl', 'issuers', 'verifiers'], 'payload');
    for (const k of ['iat', 'exp', 'ttl']) {
      if (!Number.isSafeInteger(o[k]) || (o[k] as number) <= 0) throw new Invalid(`${k} must be a positive integer`);
    }
    checkContent(o);
  });
}

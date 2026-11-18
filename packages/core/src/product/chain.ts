// Product lifecycle chain, step 10 `product_chain` (docs/architecture.md section 10, ADR-0012
// section 4, ADR-0007 step 10). Never throws for bad input; TypeError only for a wrong gtin /
// serial (parse the URL with parseDigitalLinkPath first) or wrong options.
import { base64UrlEncode, utf8Encode } from '../encoding.js';
import type { Hasher } from '../interfaces.js';
import { ErrorCodes, type Check, type ErrorCode } from '../results.js';
import { parseSdJwt } from '../sd-jwt/compact.js';
import { CONG_DOAN, SD_JWT_LIMITS, VCT } from '../sd-jwt/credential-types.js';
import { verifyStoredCredential, type VerifyCredentialOptions } from '../sd-jwt/verify.js';
import { formatProductCode } from './gs1.js';

export const PRODUCT_CHAIN_LIMITS = Object.freeze({
  /** ADR-0012 security requirement 4. */
  maxEvents: 20,
  /** All events together, in characters (= bytes for the ASCII compacts that can pass). */
  maxTotalBytes: 20 * SD_JWT_LIMITS.maxCompactBytes,
});

/** Same dependencies as verifyStoredCredential; the only supported vct is the product event. */
export type VerifyProductChainOptions = Omit<VerifyCredentialOptions, 'supportedVcts'>;

/** The claims of an event whose steps 1-4 passed; every value a string of at most 500 characters. */
export interface ProductEventView {
  congDoan: string;
  thoiDiem: string;
  diaDiem: string;
  moTa: string;
  maSanPham: string;
  /** From the trust list; null unless the issuer_trust check passed. */
  issuer: { maToChuc: string; ten: string } | null;
}

export interface ProductChainEvent {
  index: number;
  ok: boolean;
  /** The checks of verifyStoredCredential, then `product_chain`. */
  checks: Check[];
  event?: ProductEventView;
}

export interface ProductChainResult {
  /** Complete (all three stages, in order) and every event ok. */
  ok: boolean;
  /** TOO_LARGE / MALFORMED for the list itself (no event verified); CHAIN_BROKEN when an event's product_chain check failed; else null. */
  code: ErrorCode | null;
  complete: boolean;
  events: ProductChainEvent[];
}

/**
 * The `prev` the next event carries: base64url(SHA-256(the exact compact, trailing "~" included)).
 * The compact is hashed as UTF-8, which equals its ASCII bytes for any compact that can verify.
 */
export async function productEventHash(compact: string, hasher: Hasher): Promise<string> {
  if (typeof compact !== 'string') throw new TypeError('compact must be a string');
  return base64UrlEncode(await hasher.sha256(utf8Encode(compact)));
}

const ISO_INSTANT = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{1,3})?Z$/;
/** Milliseconds of an ISO 8601 UTC instant `YYYY-MM-DDTHH:MM:SS[.sss]Z` that names a real date, else null. */
export function parseUtcInstant(s: unknown): number | null {
  const m = typeof s === 'string' ? ISO_INSTANT.exec(s) : null;
  if (!m) return null;
  const ms = Date.parse(s as string);
  // The round trip refuses 2026-02-30 and 24:00:00, which Date.parse would roll over or accept.
  return Number.isFinite(ms) && new Date(ms).toISOString().startsWith(m[1]!) ? ms : null;
}

const VIEW_CLAIMS = ['ma_san_pham', 'cong_doan', 'thoi_diem', 'dia_diem', 'mo_ta'] as const;
const isProductString = (v: unknown): v is string => typeof v === 'string' && v !== '' && v.length <= SD_JWT_LIMITS.maxProductStringLength;
const broken = (detail: string): Check => ({ id: 'product_chain', ok: false, code: ErrorCodes.CHAIN_BROKEN, detail });

/**
 * Step 10 for the event at `index`, whose steps 1-4 passed (its payload is authenticated).
 * `prevHash` is the hash of the event before it in the list as received (any validity);
 * `prevTime` that event's thoi_diem when its own steps 1-4 passed and the value is valid.
 */
function chainCheck(p: Record<string, unknown>, index: number, code: string, prevHash: string | null, prevTime: number | null): Check {
  if (p['vct'] !== VCT.productEvent) return broken('not a product event');
  if (!VIEW_CLAIMS.every((k) => isProductString(p[k]))) {
    return { id: 'product_chain', ok: false, code: ErrorCodes.MALFORMED, detail: 'product event claims are missing, not strings or longer than 500 characters' };
  }
  if (p['ma_san_pham'] !== code) return broken('event of another product');
  if (p['cong_doan'] !== CONG_DOAN[index]) return broken('stage out of order, repeated or missing');
  if (prevHash === null ? Object.hasOwn(p, 'prev') : p['prev'] !== prevHash) return broken(prevHash === null ? 'the first event carries prev' : 'prev does not match the event before');
  const time = parseUtcInstant(p['thoi_diem']);
  if (time === null) return broken('thoi_diem is not an ISO 8601 UTC instant');
  if (prevTime !== null && time < prevTime) return broken('thoi_diem is earlier than the event before');
  return { id: 'product_chain', ok: true, code: null };
}

function listProblem(events: unknown): ErrorCode | null {
  if (!Array.isArray(events) || events.length === 0) return ErrorCodes.MALFORMED;
  if (events.length > PRODUCT_CHAIN_LIMITS.maxEvents) return ErrorCodes.TOO_LARGE;
  if (![...events].every((e) => typeof e === 'string')) return ErrorCodes.MALFORMED; // spread: holes count as undefined
  const total = (events as string[]).reduce((n, e) => n + e.length, 0);
  return total > PRODUCT_CHAIN_LIMITS.maxTotalBytes ? ErrorCodes.TOO_LARGE : null;
}

/**
 * Verifies the events of one product, in the order received, against the product being viewed.
 * Events are verified one after another, so each status list and the trust list are fetched at
 * most once (the checker and registry caches answer the later events).
 */
export async function verifyProductChain(
  input: { gtin: string; serial: string; events: unknown },
  options: VerifyProductChainOptions,
): Promise<ProductChainResult> {
  const code = formatProductCode(input?.gtin, input?.serial);
  const problem = listProblem(input.events);
  if (problem) return { ok: false, code: problem, complete: false, events: [] };
  const compacts = input.events as string[];
  const verifyOptions: VerifyCredentialOptions = { ...options, supportedVcts: [VCT.productEvent] };

  const events: ProductChainEvent[] = [];
  let prevHash: string | null = null;
  let prevTime: number | null = null;
  for (const [index, compact] of compacts.entries()) {
    const r = await verifyStoredCredential(compact, verifyOptions);
    const checks = [...r.checks];
    const out: ProductChainEvent = { index, ok: false, checks };
    let time: number | null = null;
    // `credential` is present exactly when steps 1-4 passed (structure through signature).
    const parsed = r.credential ? parseSdJwt(compact) : null;
    if (parsed?.ok) {
      const p = parsed.sdJwt.payload;
      checks.push(chainCheck(p, index, code, prevHash, prevTime));
      // Only well-formed values reach the page: never an over-long or non-string claim.
      if (VIEW_CLAIMS.every((k) => isProductString(p[k]))) {
        const s = (k: string) => p[k] as string;
        out.event = { congDoan: s('cong_doan'), thoiDiem: s('thoi_diem'), diaDiem: s('dia_diem'), moTa: s('mo_ta'), maSanPham: s('ma_san_pham'), issuer: r.credential!.issuer };
        time = parseUtcInstant(p['thoi_diem']);
      }
    } else {
      checks.push({ id: 'product_chain', ok: false, code: ErrorCodes.SKIPPED, skipped: true });
    }
    out.ok = checks.every((c) => c.ok);
    events.push(out);
    prevHash = await productEventHash(compact, options.hasher);
    prevTime = time;
  }

  const chainFailed = events.some((e) => e.checks.some((c) => c.id === 'product_chain' && !c.ok && !c.skipped));
  const complete = events.length === CONG_DOAN.length && events.every((e) => e.checks.at(-1)!.ok);
  return { ok: complete && events.every((e) => e.ok), code: chainFailed ? ErrorCodes.CHAIN_BROKEN : null, complete, events };
}

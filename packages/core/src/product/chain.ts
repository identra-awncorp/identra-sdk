// Product lifecycle chain, step 10 `product_chain` (docs/architecture.md section 10, ADR-0012
// section 4, ADR-0007 step 10). Never throws for bad input; TypeError only for a wrong gtin /
// serial (parse the URL with parseDigitalLinkPath first) or wrong options.
import { base64UrlEncode, utf8Encode } from '../encoding.js';
import type { Hasher } from '../interfaces.js';
import { ErrorCodes, type Check, type ErrorCode } from '../results.js';
import { parseSdJwt } from '../sd-jwt/compact.js';
import { CONG_DOAN, parseUtcInstant, SD_JWT_LIMITS, VCT, type CongDoan } from '../sd-jwt/credential-types.js';
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

/** The claims of a shown event; every value a string of 1 to 500 characters. */
export interface ProductEventView {
  congDoan: string;
  thoiDiem: string;
  diaDiem: string;
  moTa: string;
  maSanPham: string;
  /** From the trust list: who signed it. */
  issuer: { maToChuc: string; ten: string };
}

export interface ProductChainEvent {
  index: number;
  /** Every check ok. */
  ok: boolean;
  /** The checks of verifyStoredCredential, then `product_chain`; only `product_chain` at index 3 and later. */
  checks: Check[];
  /** Only when every check but `status` passed: a revoked, suspended or unverifiable step is shown in red. */
  event?: ProductEventView;
}

/** The one verdict for the page. */
export type ProductChainState = 'verified' | 'in_progress' | 'failed';

export interface ProductChainResult {
  /** verified: three stages, every event ok; in_progress: one or two stages, every event ok; failed: anything else. */
  state: ProductChainState;
  /** state === 'verified'. */
  ok: boolean;
  /** state === 'verified'. */
  complete: boolean;
  /** null unless failed: TOO_LARGE / MALFORMED for the list itself, else the first failing event's first failing code. */
  code: ErrorCode | null;
  /** The stages still to come when in_progress; [] otherwise. */
  missingStages: CongDoan[];
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

const VIEW_CLAIMS = ['ma_san_pham', 'cong_doan', 'thoi_diem', 'dia_diem', 'mo_ta'] as const;
const isProductString = (v: unknown): v is string => typeof v === 'string' && v !== '' && v.length <= SD_JWT_LIMITS.maxProductStringLength;
const broken = (detail: string): Check => ({ id: 'product_chain', ok: false, code: ErrorCodes.CHAIN_BROKEN, detail });
const SKEW_MS = SD_JWT_LIMITS.clockSkewSeconds * 1000;

/**
 * Step 10 for the event at `index` (0-2), whose steps 1-4 passed (its payload is authenticated).
 * `prevHash` is the hash of the event before it in the list as received (any validity);
 * `prevTime` that event's thoi_diem when its own product_chain check passed.
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
  // A stage dated in the future would block every later stage for good (events are never reissued).
  if (time > (p['iat'] as number) * 1000 + SKEW_MS) return broken('thoi_diem is later than the event was signed');
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

const failed = (code: ErrorCode, events: ProductChainEvent[] = []): ProductChainResult => ({ state: 'failed', ok: false, complete: false, code, missingStages: [], events });

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
  if (problem) return failed(problem);
  const compacts = input.events as string[];
  const verifyOptions: VerifyCredentialOptions = { ...options, supportedVcts: [VCT.productEvent] };

  const events: ProductChainEvent[] = [];
  let prevHash: string | null = null;
  let prevTime: number | null = null;
  for (const [index, compact] of compacts.entries()) {
    // No stage exists after phan_phoi: not parsed, no crypto, no request.
    if (index >= CONG_DOAN.length) {
      events.push({ index, ok: false, checks: [broken('no stage after phan_phoi')] });
      continue;
    }
    const r = await verifyStoredCredential(compact, verifyOptions);
    const checks = [...r.checks];
    const out: ProductChainEvent = { index, ok: false, checks };
    let time: number | null = null;
    // `credential` is present exactly when steps 1-4 passed (structure through signature).
    const parsed = r.credential ? parseSdJwt(compact) : null;
    if (parsed?.ok) {
      const p = parsed.sdJwt.payload;
      const link = chainCheck(p, index, code, prevHash, prevTime);
      checks.push(link);
      // Only a step whose own link holds dates the next one (a future-dated step cannot block it).
      if (link.ok) time = parseUtcInstant(p['thoi_diem']);
      // Shown only for a step whose issuer is trusted and whose link holds (then the claims are
      // well-formed strings): free text of anyone else never reaches the page.
      if (checks.every((c) => c.ok || c.id === 'status')) {
        const s = (k: string) => p[k] as string;
        out.event = { congDoan: s('cong_doan'), thoiDiem: s('thoi_diem'), diaDiem: s('dia_diem'), moTa: s('mo_ta'), maSanPham: s('ma_san_pham'), issuer: r.credential!.issuer! };
      }
    } else {
      checks.push({ id: 'product_chain', ok: false, code: ErrorCodes.SKIPPED, skipped: true });
    }
    out.ok = checks.every((c) => c.ok);
    events.push(out);
    prevHash = await productEventHash(compact, options.hasher);
    prevTime = time;
  }

  const firstBad = events.find((e) => !e.ok);
  if (firstBad) return failed(firstBad.checks.find((c) => !c.ok)!.code!, events);
  if (events.length === CONG_DOAN.length) return { state: 'verified', ok: true, complete: true, code: null, missingStages: [], events };
  return { state: 'in_progress', ok: false, complete: false, code: null, missingStages: CONG_DOAN.slice(events.length), events };
}

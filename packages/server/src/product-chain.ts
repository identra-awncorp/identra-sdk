// Product lifecycle events on the server side (ADR-0012 sections 2 and 4, identra-server
// docs/vc-api.md section 7): an organisation appends its event after the stored ones, and the
// store checks a submitted event before keeping it. The store stays "not an authority": the page
// verifies the whole chain again in the browser.
import {
  CONG_DOAN,
  formatProductCode,
  issueProductEvent,
  parseUtcInstant,
  productEventHash,
  verifyProductChain,
  type Check,
  type CongDoan,
  type ErrorCode,
  type IssuerContext,
  type ProductChainResult,
  type VerifyProductChainOptions,
} from '@identra/sdk-core';

/** The stored chain cannot be extended: `index` is the failing event (null for the list itself, e.g. TOO_LARGE). */
export class ProductChainRefusedError extends Error {
  readonly index: number | null;
  readonly code: ErrorCode;
  constructor(index: number | null, code: ErrorCode) {
    super(index === null ? `the stored chain is refused (${code})` : `stored event ${index} is refused (${code})`);
    this.name = 'ProductChainRefusedError';
    this.index = index;
    this.code = code;
  }
}

export interface AppendProductEventInput extends IssuerContext {
  gtin: string;
  serial: string;
  /** The stored events of this product, in order; [] for the first stage. */
  existing: string[];
  iss: string;
  status: { idx: number; uri: string };
  claims: { congDoan: CongDoan; thoiDiem: string; diaDiem: string; moTa: string };
  /** Verification of `existing` (pinned root, trust list, status lists). */
  verify: VerifyProductChainOptions;
}

/** First failing event of a failed result, as [index, code]; [null, code] for a list-level problem. */
function firstFailure(r: ProductChainResult): [number | null, ErrorCode] {
  const bad = r.events.find((e) => !e.ok);
  return bad ? [bad.index, bad.checks.find((c) => !c.ok)!.code!] : [null, r.code!];
}

/**
 * Issues the next event of a product, `prev` computed from the last stored one. `existing` is
 * verified first: every stored event must be fully ok (a revoked, suspended or unverifiable step
 * is not extended), else ProductChainRefusedError; a complete chain is refused with index 3 and
 * CHAIN_BROKEN. TypeError for a stage that is not the next one or a thoiDiem earlier than the last
 * stored one; issueProductEvent checks the rest (ISO instant, not later than now, lengths, GTIN).
 */
export async function appendProductEvent(input: AppendProductEventInput): Promise<string> {
  const { gtin, serial, existing, claims, verify, ...issuer } = input;
  if (!Array.isArray(existing)) throw new TypeError('existing must be an array');
  const maSanPham = formatProductCode(gtin, serial);
  let after: { compact: string; thoiDiem: string } | undefined;
  if (existing.length > 0) {
    const r = await verifyProductChain({ gtin, serial, events: existing }, verify);
    if (r.state === 'verified') throw new ProductChainRefusedError(CONG_DOAN.length, 'CHAIN_BROKEN');
    if (r.state === 'failed') throw new ProductChainRefusedError(...firstFailure(r));
    after = { compact: existing.at(-1)!, thoiDiem: r.events.at(-1)!.event!.thoiDiem };
  }
  const expected = CONG_DOAN[existing.length]!;
  if (claims?.congDoan !== expected) throw new TypeError(`congDoan must be ${expected} here`);
  const time = parseUtcInstant(claims.thoiDiem);
  if (after && time !== null && time < parseUtcInstant(after.thoiDiem)!) throw new TypeError('thoiDiem is earlier than the previous event');
  const prev = after ? { prev: await productEventHash(after.compact, issuer.hasher) } : {};
  return issueProductEvent({
    ...issuer,
    claims: { ma_san_pham: maSanPham, cong_doan: claims.congDoan, thoi_diem: claims.thoiDiem, dia_diem: claims.diaDiem, mo_ta: claims.moTa, ...prev },
  });
}

export type StorageCheck = { ok: true } | { ok: false; code: ErrorCode; index: number | null; checks: Check[] };

/**
 * The store's gatekeeping for `POST /v1/products/:gtin/:serial/events`: `existing` (as stored, in
 * order) must be fully ok and `candidate` must extend it to in_progress or verified. Otherwise the
 * first failing event (a stored one or the candidate) with its first failing code and its checks;
 * index null and no checks for a list-level problem (TOO_LARGE, MALFORMED).
 */
export async function checkProductEventForStorage(
  input: { gtin: string; serial: string; existing: string[]; candidate: string },
  options: VerifyProductChainOptions,
): Promise<StorageCheck> {
  if (!Array.isArray(input?.existing)) throw new TypeError('existing must be an array');
  const r = await verifyProductChain({ gtin: input.gtin, serial: input.serial, events: [...input.existing, input.candidate] }, options);
  if (r.state !== 'failed') return { ok: true };
  const [index, code] = firstFailure(r);
  return { ok: false, code, index, checks: index === null ? [] : r.events[index]!.checks };
}

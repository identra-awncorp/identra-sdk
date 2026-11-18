// Product lifecycle events on the server side (ADR-0012 sections 2 and 4, identra-server
// docs/vc-api.md section 7): an organisation appends its event after the previous one, and the
// store checks a submitted event before keeping it. The store stays "not an authority": the page
// verifies the whole chain again in the browser.
import {
  CONG_DOAN,
  decodeCredentialUnverified,
  issueProductEvent,
  parseUtcInstant,
  productEventHash,
  verifyProductChain,
  VCT,
  type Check,
  type CongDoan,
  type ErrorCode,
  type IssuerContext,
  type VerifyProductChainOptions,
} from '@identra/sdk-core';

export interface AppendProductEventInput extends IssuerContext {
  /** The compact of the last event of this product; absent for the first event. */
  previous?: string;
  iss: string;
  status: { idx: number; uri: string };
  claims: { maSanPham: string; congDoan: CongDoan; thoiDiem: string; diaDiem: string; moTa: string };
}

function fail(message: string): never {
  throw new TypeError(message);
}

/**
 * Issues the next event of a product with `prev` computed from `previous`. Refuses (TypeError) a
 * stage that does not follow the previous event's stage, another product code, a thoi_diem that is
 * not an ISO 8601 UTC instant or is earlier than the previous one. `previous` is read without
 * verification (it is the caller's own stored copy); the store verifies the result with
 * checkProductEventForStorage. Everything else is checked by issueProductEvent.
 */
export async function appendProductEvent(input: AppendProductEventInput): Promise<string> {
  const { previous, claims, ...issuer } = input;
  const time = parseUtcInstant(claims?.thoiDiem);
  if (time === null) fail('thoiDiem must be an ISO 8601 UTC instant');
  let prev: string | undefined;
  let expected: CongDoan = CONG_DOAN[0];
  if (previous !== undefined) {
    let p: Record<string, unknown>;
    try {
      p = decodeCredentialUnverified(previous).payload;
    } catch {
      fail('previous is not a credential compact');
    }
    if (p['vct'] !== VCT.productEvent) fail('previous is not a product event');
    const stage = CONG_DOAN.indexOf(p['cong_doan'] as CongDoan);
    const next = stage < 0 ? undefined : CONG_DOAN[stage + 1];
    if (next === undefined) fail('the previous event is the last stage or has no known stage');
    expected = next;
    if (p['ma_san_pham'] !== claims.maSanPham) fail('maSanPham differs from the previous event');
    const before = parseUtcInstant(p['thoi_diem']);
    if (before !== null && time < before) fail('thoiDiem is earlier than the previous event');
    prev = await productEventHash(previous, issuer.hasher);
  }
  if (claims.congDoan !== expected) fail(`congDoan must be ${expected} here`);
  return issueProductEvent({
    ...issuer,
    claims: {
      ma_san_pham: claims.maSanPham, cong_doan: claims.congDoan, thoi_diem: claims.thoiDiem, dia_diem: claims.diaDiem, mo_ta: claims.moTa,
      ...(prev !== undefined ? { prev } : {}),
    },
  });
}

export type StorageCheck = { ok: true } | { ok: false; code: ErrorCode; checks: Check[] };

/**
 * The store's gatekeeping for `POST /v1/products/:gtin/:serial/events`: `existing` (as stored, in
 * order) plus `candidate` must verify with verifyProductChain, and the candidate's own event must be
 * ok (its signature, trust scope, status and its link to the last stored event). Problems of
 * earlier events (one revoked since) do not block the candidate. `code` is the chain-level code
 * (TOO_LARGE, MALFORMED) or the candidate's first failing check.
 */
export async function checkProductEventForStorage(
  input: { gtin: string; serial: string; existing: string[]; candidate: string },
  options: VerifyProductChainOptions,
): Promise<StorageCheck> {
  if (!Array.isArray(input?.existing)) throw new TypeError('existing must be an array');
  const r = await verifyProductChain({ gtin: input.gtin, serial: input.serial, events: [...input.existing, input.candidate] }, options);
  const mine = r.events[input.existing.length];
  if (!mine) return { ok: false, code: r.code!, checks: [] };
  if (mine.ok) return { ok: true };
  return { ok: false, code: mine.checks.find((c) => !c.ok)!.code!, checks: mine.checks };
}

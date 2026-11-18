// GS1 product identifiers (ADR-0012 section 1): GTIN-14 plus serial, AI (01) + AI (21), as the
// element string `(01)<GTIN>(21)<serial>` (the `ma_san_pham` claim) and as the GS1 Digital Link
// path `/01/<GTIN>/21/<serial>` (the product QR). Strict on purpose: Identra prints and accepts
// exactly `/01/<GTIN-14>/21/<serial>`; lot or other key qualifiers, shorter GTINs, trailing slashes,
// raw sub-delimiters and lower-case percent-escapes are refused, so each product has one path.

/** One parsed product identifier. */
export interface ProductCode {
  gtin: string;
  serial: string;
}

/**
 * GS1 standard check digit (General Specifications 7.9.1) for the digits WITHOUT the check digit:
 * weights 3, 1, 3, … from the rightmost digit; the check digit brings the sum to a multiple of ten.
 */
export function gs1CheckDigit(digits: string): number {
  if (!/^[0-9]{1,17}$/.test(digits)) throw new TypeError('digits must be 1 to 17 decimal digits');
  let sum = 0;
  for (let i = 0; i < digits.length; i++) sum += Number(digits[digits.length - 1 - i]) * (i % 2 === 0 ? 3 : 1);
  return (10 - (sum % 10)) % 10;
}

/** 14 decimal digits whose last one is the GS1 check digit of the first 13. */
export function isGtin14(gtin: unknown): gtin is string {
  return typeof gtin === 'string' && /^[0-9]{14}$/.test(gtin) && gs1CheckDigit(gtin.slice(0, 13)) === Number(gtin[13]);
}

// GS1 AI encodable character set 82 (General Specifications figure 7.11-1).
const CSET82 = /^[A-Za-z0-9!"%&'()*+,\-./:;<=>?_]{1,20}$/;
// A serial that itself looks percent-encoded ("%41") is refused in every form, so that the element
// string and the Digital Link path stay one-to-one and a double-encoded path cannot be accepted.
const LOOKS_ENCODED = /%[0-9A-Fa-f]{2}/;

/**
 * AI (21): 1 to 20 characters of set 82, no `%` followed by two hex digits, and not `.` or `..`
 * (a URL parser resolves those as dot segments, so they can be neither a Digital Link nor an API path).
 */
export function isSerial(serial: unknown): serial is string {
  return typeof serial === 'string' && CSET82.test(serial) && !LOOKS_ENCODED.test(serial) && serial !== '.' && serial !== '..';
}

const ELEMENT_STRING = /^\(01\)([0-9]{14})\(21\)(.{1,20})$/s;

/** `(01)<GTIN-14>(21)<serial>` → `{ gtin, serial }`, or null. */
export function parseProductCode(maSanPham: unknown): ProductCode | null {
  if (typeof maSanPham !== 'string' || maSanPham.length > 42) return null;
  const m = ELEMENT_STRING.exec(maSanPham);
  if (!m || !isGtin14(m[1]) || !isSerial(m[2])) return null;
  return { gtin: m[1], serial: m[2] };
}

function checked(gtin: string, serial: string): void {
  if (!isGtin14(gtin)) throw new TypeError('gtin must be a GTIN-14 with a valid check digit');
  if (!isSerial(serial)) throw new TypeError('serial must be 1 to 20 characters of GS1 character set 82');
}

/** The element string `(01)<GTIN>(21)<serial>`; TypeError on an invalid GTIN or serial. */
export function formatProductCode(gtin: string, serial: string): string {
  checked(gtin, serial);
  return `(01)${gtin}(21)${serial}`;
}

// Characters written as themselves in a Digital Link path; every other set-82 character is
// percent-encoded (GS1 Digital Link URI syntax 4.2 lists them; `"` is not a URI character at all).
const RAW = /^[A-Za-z0-9._-]$/;
const hex = (c: string) => `%${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`;

/** `/01/<GTIN>/21/<serial>` with the serial percent-encoded; TypeError on an invalid GTIN or serial. */
export function formatDigitalLinkPath(gtin: string, serial: string): string {
  checked(gtin, serial);
  return `/01/${gtin}/21/${[...serial].map((c) => (RAW.test(c) ? c : hex(c))).join('')}`;
}

/** "/01/" + 14 digits + "/21/" + at most 20 characters encoded as 3 each. */
const MAX_PATH = 4 + 14 + 4 + 20 * 3;
const PATH = /^\/01\/([0-9]{14})\/21\/((?:[A-Za-z0-9._-]|%[0-9A-F]{2}){1,20})$/;

/**
 * Parses a GS1 Digital Link path `/01/<GTIN-14>/21/<serial>` (e.g. `location.pathname`), or null.
 * Only the exact form formatDigitalLinkPath writes: no other AI or qualifier, no query, fragment,
 * trailing slash or extra segment; `A–Z a–z 0–9 - . _` raw, every other set-82 character as an
 * UPPER-CASE percent-escape, an escape of a raw character (`%41`) refused, so one serial has exactly
 * one accepted path; the decoded serial must pass isSerial, which refuses a double-encoded one.
 */
export function parseDigitalLinkPath(path: unknown): ProductCode | null {
  if (typeof path !== 'string' || path.length > MAX_PATH) return null;
  const m = PATH.exec(path);
  if (!m || !isGtin14(m[1])) return null;
  let serial = '';
  for (const piece of m[2]!.match(/%[0-9A-F]{2}|[^%]/g)!) {
    if (piece.length === 1) {
      serial += piece;
      continue;
    }
    const c = String.fromCharCode(parseInt(piece.slice(1), 16));
    if (RAW.test(c) || !CSET82.test(c)) return null;
    serial += c;
  }
  return isSerial(serial) ? { gtin: m[1], serial } : null;
}

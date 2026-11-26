// The two Identra credential types (docs/architecture.md section 5, ADR-0001, ADR-0008, ADR-0012).

export const VCT = Object.freeze({
  diploma: 'https://identra.awncorp.vn/vct/bang-tot-nghiep/v1',
  productEvent: 'https://identra.awncorp.vn/vct/su-kien-vong-doi/v1',
});

/** Diploma subject claims; each is its own top-level disclosure. */
export const DIPLOMA_CLAIMS = Object.freeze([
  'ho_ten',
  'ngay_sinh',
  'ma_sinh_vien',
  'nganh',
  'hang_tot_nghiep',
  'nam_tot_nghiep',
  'so_hieu_bang',
] as const);

/** A diploma's `_sd` is padded with decoys to exactly this many digests (ADR-0008 section 2). */
export const DIPLOMA_SD_DIGESTS = 10;

/** Product lifecycle event claims; none is disclosable. `prev` is added on every event but the first. */
export const PRODUCT_EVENT_CLAIMS = Object.freeze(['ma_san_pham', 'cong_doan', 'thoi_diem', 'dia_diem', 'mo_ta'] as const);
export const CONG_DOAN = Object.freeze(['san_xuat', 'kiem_dinh', 'phan_phoi'] as const);

/** Metadata claims: always visible, never disclosable (ADR-0001, ADR-0008 section 6). */
export const METADATA_CLAIMS: readonly string[] = Object.freeze(['iss', 'vct', 'iat', 'nbf', 'exp', 'cnf', 'status']);
/** Names that can never be a disclosed claim name. */
export const RESERVED_CLAIM_NAMES: readonly string[] = Object.freeze(['_sd', '...', '_sd_alg']);

export const SD_JWT_LIMITS = Object.freeze({
  /** Compact (including disclosures and KB-JWT) in bytes (ADR-0007). */
  maxCompactBytes: 16_384,
  maxDisclosures: 50,
  /** A KB-JWT alone, in bytes. */
  maxKbJwtBytes: 4096,
  /** Each product event string claim, in characters. */
  maxProductStringLength: 500,
  /** KB-JWT `iat` may be at most this old (ADR-0008 section 4), plus clock skew. */
  kbMaxAgeSeconds: 300,
  clockSkewSeconds: 60,
});

/** At most this many DCQL claim sets (options) per request. */
export const MAX_CLAIM_SETS = 4;

/**
 * ADR-0008 section 5: the first claim set holds every requested name and each later one only
 * shrinks it, so "share less" can never add a field. True when there are 1 to MAX_CLAIM_SETS sets,
 * none empty or with a repeated name, and each is a proper subset of the one before.
 */
export function claimSetsNested(sets: readonly (readonly string[])[]): boolean {
  if (sets.length === 0 || sets.length > MAX_CLAIM_SETS) return false;
  return sets.every((set, i) => {
    if (set.length === 0 || new Set(set).size !== set.length) return false;
    const prev = sets[i - 1];
    return prev === undefined || (set.length < prev.length && set.every((n) => prev.includes(n)));
  });
}

export type DiplomaClaims =Record<(typeof DIPLOMA_CLAIMS)[number], string>;
export type CongDoan = (typeof CONG_DOAN)[number];
export interface ProductEventClaims {
  /** GS1 element string `(01)<GTIN>(21)<serial>`. */
  ma_san_pham: string;
  cong_doan: CongDoan;
  thoi_diem: string;
  dia_diem: string;
  mo_ta: string;
  /** base64url(SHA-256(previous event compact)); absent on the first event. */
  prev?: string;
}

const STATUS_LIST_NUMBER = /^[1-9][0-9]{0,8}$/;
/**
 * The status list URI of an issuer has exactly the form `<iss>/status/<n>` with n a decimal
 * 1..999999999 (ADR-0015 section 11). Compared as strings: no URL parsing, so "..", "%2e",
 * "\\", whitespace, query, fragment, userinfo, port or case variants cannot pass.
 */
export function isStatusListUri(uri: unknown, iss: string): boolean {
  const prefix = `${iss}/status/`;
  return typeof uri === 'string' && uri.startsWith(prefix) && STATUS_LIST_NUMBER.test(uri.slice(prefix.length));
}

// Host: at least two lower-case labels of letters, digits and hyphens joined by dots, the last one
// (captured) starting with a letter, so that no URL parser reads it as an IPv4 address in any
// notation (2130706433, 0x7f000001, 169.254.169.254, 0) and no single-label name (localhost, an
// intranet host) passes; a port of 1-5 digits without a leading 0 (any port: development
// deployments use them); one or more path segments of unreserved characters, a dot only inside a
// segment (so no empty, "." or ".." segment); then /status/<n>. No ambiguous repetition (no ReDoS).
const DID_STATUS_LIST_URI =
  /^https:\/\/(?:[a-z0-9-]+\.)+([a-z][a-z0-9-]*)(?::[1-9][0-9]{0,4})?(?:\/[A-Za-z0-9_~-]+(?:\.[A-Za-z0-9_~-]+)*)+\/status\/[1-9][0-9]{0,8}$/;
/**
 * Last labels that name no public host: the special-use names of RFC 6761 (localhost, test,
 * example, invalid), local of RFC 6762, home.arpa of RFC 8375 (by arpa), onion of RFC 7686, and the
 * common internal suffixes (localdomain, internal, intranet, lan, home, corp, Kubernetes' svc).
 */
const INTERNAL_TLDS = new Set(['localhost', 'local', 'localdomain', 'internal', 'intranet', 'lan', 'home', 'corp', 'svc', 'arpa', 'test', 'example', 'invalid', 'onion']);
/**
 * The status list URI of a DID issuer, which cannot be `<iss>/status/<n>` (ADR-0020 section 6):
 * `https://<host>[:port]/<path>/status/<n>`, n in 1..999999999, matched as a string against a strict
 * pattern, so query, fragment, userinfo, "..", "%", "\\", whitespace, upper-case hosts, IPv4
 * literals, single-label hosts and hosts under a special-use or internal last label (INTERNAL_TLDS:
 * a.localhost, metadata.google.internal, kubernetes.default.svc) cannot pass. A public name that
 * resolves to a private address can: the HttpFetch given to the status checker must refuse those.
 */
export function isDidStatusListUri(uri: unknown): boolean {
  const m = typeof uri === 'string' ? DID_STATUS_LIST_URI.exec(uri) : null;
  return m !== null && !INTERNAL_TLDS.has(m[1]!);
}

const ISO_INSTANT = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{1,3})?Z$/;
/**
 * Milliseconds of an ISO 8601 UTC instant `YYYY-MM-DDTHH:MM:SS[.sss]Z` that names a real date
 * (years 0000-9999), else null. The form of a product event's `thoi_diem`.
 */
export function parseUtcInstant(s: unknown): number | null {
  const m = typeof s === 'string' ? ISO_INSTANT.exec(s) : null;
  if (!m) return null;
  const ms = Date.parse(s as string);
  // The round trip refuses 2026-02-30 and 24:00:00, which Date.parse would roll over or accept.
  return Number.isFinite(ms) && new Date(ms).toISOString().startsWith(m[1]!) ? ms : null;
}

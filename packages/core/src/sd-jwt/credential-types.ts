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
  /** Each product event string claim, in characters. */
  maxProductStringLength: 500,
  /** KB-JWT `iat` may be at most this old (ADR-0008 section 4), plus clock skew. */
  kbMaxAgeSeconds: 300,
  clockSkewSeconds: 60,
});

export type DiplomaClaims = Record<(typeof DIPLOMA_CLAIMS)[number], string>;
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

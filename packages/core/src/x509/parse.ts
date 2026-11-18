// X.509 certificate parsing. This is the only file that imports micro-key-producer (ADR-0004,
// "Bổ sung 2026-11-19"); the library is used to read DER only, never for cryptography.
import { oid, oidName } from 'micro-key-producer/asn1.js';
import { PKCS8 } from 'micro-key-producer/convert.js';
import { CERTUtils, X509 } from 'micro-key-producer/x509.js';
import { derSignatureToRaw } from '../ecdsa-der.js';
import { base64UrlEncode, bytesEqual, hexDecode } from '../encoding.js';
import type { EcPublicJwk } from '../interfaces.js';
import { normalizeEcPublicJwk } from '../jwk.js';

export const OID = Object.freeze({
  ecPublicKey: '1.2.840.10045.2.1',
  p256: '1.2.840.10045.3.1.7',
  ecdsaWithSha256: '1.2.840.10045.4.3.2',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  subjectAltName: '2.5.29.17',
  C: '2.5.4.6',
  O: '2.5.4.10',
  CN: '2.5.4.3',
  organizationIdentifier: '2.5.4.97',
});

export interface ParsedCertificate {
  /** The whole certificate (fingerprint input). */
  der: Uint8Array;
  /** tbsCertificate exactly as signed. */
  tbs: Uint8Array;
  /** Outer signatureAlgorithm OID (equal to the one inside tbsCertificate). */
  signatureAlgorithm: string;
  /** r||s; only set for ecdsa-with-SHA256 without parameters and a well-formed DER signature value. */
  signature?: Uint8Array;
  /** subjectPublicKeyInfo algorithm OID, and the named curve for EC keys. */
  publicKeyAlgorithm: string;
  publicKeyCurve?: string;
  /** Only set for a P-256 key in uncompressed form whose point lies on the curve. */
  publicJwk?: EcPublicJwk;
  notBefore: Date;
  notAfter: Date;
  /** Raw Name DER, for byte-for-byte chaining. */
  issuerName: Uint8Array;
  subjectName: Uint8Array;
  subject: { C?: string; O?: string; organizationIdentifier?: string; CN?: string };
  basicConstraints?: { cA: boolean; pathLenConstraint?: number };
  /** The nine keyUsage bits (RFC 5280 section 4.2.1.3); absent when the extension is absent. */
  keyUsage?: Record<KeyUsageBit, boolean>;
  sanUris: string[];
  criticalExtensions: string[];
}

export const KEY_USAGE_BITS = Object.freeze([
  'digitalSignature',
  'nonRepudiation',
  'keyEncipherment',
  'dataEncipherment',
  'keyAgreement',
  'keyCertSign',
  'cRLSign',
  'encipherOnly',
  'decipherOnly',
] as const);
export type KeyUsageBit = (typeof KEY_USAGE_BITS)[number];

type Cert = ReturnType<typeof X509.decode>;
type Name = Cert['tbs']['subject'];

const SUBJECT_KEYS: Record<string, 'C' | 'O' | 'organizationIdentifier' | 'CN'> = {
  [OID.C]: 'C',
  [OID.O]: 'O',
  [OID.organizationIdentifier]: 'organizationIdentifier',
  [OID.CN]: 'CN',
};

// micro-key-producer reports known OIDs by name ('commonName') and others as dotted strings.
const dotted = (o: string): string => oid.decode(oidName.encode(o));

/** UTCTime YYMMDDHHMMSSZ or GeneralizedTime YYYYMMDDHHMMSSZ (RFC 5280 section 4.1.2.5). */
function parseTime(t: { TAG: 'utc' | 'generalized'; data: string }): Date {
  const m = (t.TAG === 'generalized' ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/ : /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/).exec(t.data);
  if (!m) throw new TypeError('invalid certificate time');
  const [, y, mo, d, h, mi, s] = m.map(Number) as [number, number, number, number, number, number, number];
  // RFC 5280 uses UTCTime through 2049; GeneralizedTime is accepted from 1950 on (a documented leniency).
  const year = t.TAG === 'generalized' ? y : y >= 50 ? 1900 + y : 2000 + y;
  if (year < 1950) throw new TypeError('certificate year before 1950');
  const date = new Date(0);
  date.setUTCFullYear(year, mo - 1, d); // Date.UTC would map years 0-99 to 19xx
  date.setUTCHours(h, mi, s, 0);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== mo - 1 || date.getUTCDate() !== d || h > 23 || mi > 59 || s > 59) {
    throw new TypeError('invalid certificate time');
  }
  return date;
}

function subjectAttributes(name: Name): ParsedCertificate['subject'] {
  const out: ParsedCertificate['subject'] = {};
  for (const rdn of name.rdns) {
    for (const a of rdn) {
      const key = SUBJECT_KEYS[dotted(a.oid)];
      if (!key) continue;
      // Two values for the same attribute would make the organisation identity ambiguous.
      if (key in out) throw new TypeError(`duplicate subject attribute ${key}`);
      if (a.value.TAG !== 'raw') out[key] = a.value.data;
    }
  }
  return out;
}

/**
 * Parses a DER certificate. Accepts strict DER only: re-encoding must reproduce the input byte
 * for byte, so `tbs` and the names are the bytes that were signed. Throws TypeError (never any
 * other error) on anything malformed, on a version other than v3, on mismatching inner/outer
 * signature algorithms, on duplicate or undecodable basicConstraints / keyUsage / SAN extensions
 * and on duplicate C / O / organizationIdentifier / CN attributes.
 */
export function parseCertificate(der: Uint8Array): ParsedCertificate {
  try {
    return parse(der);
  } catch (e) {
    throw e instanceof TypeError ? e : new TypeError(`not a valid certificate (${(e as Error)?.message})`);
  }
}

function parse(der: Uint8Array): ParsedCertificate {
  const c = X509.decode(der);
  if (!bytesEqual(X509.encode(c), der)) throw new TypeError('not a strict DER certificate (re-encoding differs)');
  const t = c.tbs;
  if (t.version !== 2n) throw new TypeError('not an X.509 v3 certificate');
  const signatureAlgorithm = dotted(c.sigAlg.algorithm);
  if (dotted(t.signature.algorithm) !== signatureAlgorithm) throw new TypeError('signature algorithm mismatch');

  const out: ParsedCertificate = {
    der,
    tbs: CERTUtils.TBSCertificate.encode(t),
    signatureAlgorithm,
    publicKeyAlgorithm: dotted(t.spki.algorithm.algorithm),
    notBefore: parseTime(t.validity.notBefore),
    notAfter: parseTime(t.validity.notAfter),
    issuerName: CERTUtils.Name.encode(t.issuer),
    subjectName: CERTUtils.Name.encode(t.subject),
    subject: subjectAttributes(t.subject),
    sanUris: [],
    criticalExtensions: [],
  };

  if (signatureAlgorithm === OID.ecdsaWithSha256 && c.sigAlg.params === undefined) {
    try {
      out.signature = derSignatureToRaw(c.sig);
    } catch {
      // Left unset: the chain validator reports a signature that cannot verify.
    }
  }

  const params = t.spki.algorithm.params;
  if (out.publicKeyAlgorithm === OID.ecPublicKey && params?.tag === 0x06 && params.valueHex !== undefined) {
    out.publicKeyCurve = oid.decode(hexDecode(params.valueHex));
    const jwk = out.publicKeyCurve === OID.p256 ? p256PointToJwk(t.spki.publicKey) : null;
    if (jwk) out.publicJwk = jwk;
  }

  const seen = new Set<string>();
  for (const e of X509.extensions(c)) {
    const id = dotted(e.oid);
    if (seen.has(id)) throw new TypeError(`duplicate extension ${id}`);
    seen.add(id);
    if (e.critical) out.criticalExtensions.push(id);
    if (id === OID.basicConstraints) {
      if (!e.basic) throw new TypeError('undecodable basicConstraints');
      out.basicConstraints = { cA: e.basic.ca === true };
      if (e.basic.pathLen !== undefined) out.basicConstraints.pathLenConstraint = Number(e.basic.pathLen);
    }
    if (id === OID.keyUsage) {
      if (!e.keyUsage) throw new TypeError('undecodable keyUsage');
      const bytes = e.keyUsage.bytes;
      // Bit n is bit (7 - n % 8) of byte n / 8: digitalSignature is the most significant bit.
      const bit = (n: number) => (((bytes[n >> 3] ?? 0) >> (7 - (n & 7))) & 1) === 1;
      out.keyUsage = Object.fromEntries(KEY_USAGE_BITS.map((name, n) => [name, bit(n)])) as Record<KeyUsageBit, boolean>;
    }
    if (id === OID.subjectAltName) {
      if (!e.san) throw new TypeError('undecodable subjectAltName');
      for (const g of e.san.list) {
        if (g.TAG !== 'uniformResourceIdentifier') continue;
        if (typeof g.data !== 'string') throw new TypeError('undecodable SAN URI');
        out.sanUris.push(g.data);
      }
    }
  }
  return out;
}

/** Uncompressed SEC1 point (04 || x || y) -> JWK, or null when not that or not on P-256. */
function p256PointToJwk(point: Uint8Array): EcPublicJwk | null {
  if (point.length !== 65 || point[0] !== 0x04) return null;
  return normalizeEcPublicJwk({ kty: 'EC', crv: 'P-256', x: base64UrlEncode(point.subarray(1, 33)), y: base64UrlEncode(point.subarray(33)) });
}

/**
 * The P-256 public key carried inside a PKCS#8 EC private key (the optional `publicKey` of
 * RFC 5915), or null when the key is not P-256 or carries no public key. Reads the structure
 * only; the private scalar is not used.
 */
export function publicJwkFromPkcs8(der: Uint8Array): EcPublicJwk | null {
  try {
    const k = PKCS8.decode(der);
    const info = k.algorithm.info as { TAG: string; data?: { TAG?: string; data?: unknown } };
    if (info.TAG !== 'EC' || info.data?.TAG !== 'namedCurve' || info.data.data !== 'P-256') return null;
    const point = k.privateKey.TAG === 'struct' ? k.privateKey.data.publicKey : undefined;
    return point ? p256PointToJwk(point) : null;
  } catch {
    return null;
  }
}

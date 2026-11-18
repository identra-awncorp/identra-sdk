// Certificate forging for negative tests: decode a test-PKI certificate with micro-key-producer,
// edit its TBS, re-sign with a test CA key (node:crypto). Approach of the GĐ1 review harness.
import { createPrivateKey, sign, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { CERTUtils, X509 } from 'micro-key-producer/x509.js';
import { REPO } from './pki.js';

type Cert = ReturnType<typeof X509.decode>;
export type Tbs = Cert['tbs'];

const keyAt = (path: string): KeyObject => createPrivateKey(readFileSync(new URL(`.pki/test/${path}`, REPO), 'utf8'));
export const caKey = (name: string) => keyAt(`ca/${name}/ca.key.pem`);
export const leafKey = (name: string) => keyAt(`leaf/${name}.key.pem`);

/** Re-signs `base` after `edit(tbs)`; `sigAlg` relabels both signature algorithm fields. */
export function forge(base: Uint8Array, edit: ((tbs: Tbs) => void) | null, key: KeyObject, options: { sigAlg?: string; hash?: string } = {}): Uint8Array {
  const c = X509.decode(base);
  const tbs = structuredClone(c.tbs);
  const sigAlg = options.sigAlg ? { ...c.sigAlg, algorithm: options.sigAlg } : c.sigAlg;
  if (options.sigAlg) tbs.signature = { ...tbs.signature, algorithm: options.sigAlg };
  edit?.(tbs);
  const der = CERTUtils.TBSCertificate.encode(tbs);
  const sig = new Uint8Array(sign(options.hash ?? 'sha256', der, { key, dsaEncoding: 'der' }));
  return X509.encode({ tbs, sigAlg, sig });
}

const len = (n: number) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
/** Extension body ("rest"): [critical BOOLEAN TRUE] OCTET STRING(value). */
export function extRest(critical: boolean, value: number[]): Uint8Array {
  const octets = [0x04, ...len(value.length), ...value];
  return Uint8Array.from(critical ? [0x01, 0x01, 0xff, ...octets] : octets);
}
/** keyUsage extension body from a DER BIT STRING. */
export const keyUsageRest = (bitString: number[]) => extRest(true, bitString);
export const withExtension = (tbs: Tbs, oid: string, rest: Uint8Array) => {
  for (const e of tbs.extensions!.list) if (e.oid === oid) e.rest = rest;
};
export const withoutExtension = (tbs: Tbs, oid: string) => {
  tbs.extensions!.list = tbs.extensions!.list.filter((e) => e.oid !== oid);
};

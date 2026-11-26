// File key store (ADR-0015 section 2, ADR-0016 section 6): the keys of the demo organisations and
// of the trust-list signer, in the layout written by scripts/pki/make-demo-pki.sh:
//   <dir>/orgs/<name>/<purpose>.key.pem + <purpose>.chain.pem   (purpose vc | vc-product | status | request)
//   <dir>/orgs/<name>/did.key.pem + did.json                    (a DID issuer, ADR-0020; instead of vc and status)
//   <dir>/trust-list-signer/trust-list.key.pem + trust-list.cert.pem
//   <dir>/root.cert.pem [+ <dir>/root2.cert.pem]
// Private keys are imported non-extractable and leave this module only as the Signer interface
// (ADR-0006 section 3). Nothing is logged; error messages name files, never their content.
import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  base64Decode, createCertificateChainValidator, isCertNetDid, normalizeEcPublicJwk, parseCertificate, splitDidUrl,
  type CertificateChainValidator, type CertificateProfile, type EcPublicJwk, type Signer,
} from '@identra/sdk-core';
import { webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';

export type OrganisationPurpose = 'vc' | 'status' | 'request';

export interface IssuerKeyStore {
  /** The signer of an organisation for one purpose; x5c is [leaf, issuing CA]. */
  signer(organisation: string, purpose: OrganisationPurpose): Promise<Signer>;
  /**
   * The DID signer of an organisation that issues on the DID trust path (ADR-0020): `kid` is its
   * `did:certnet` DID URL, no x5c. Null when the organisation has no DID files (an X.509 issuer).
   * Optional: a key store without it hosts X.509 issuers only.
   */
  didSigner?(organisation: string): Promise<Signer | null>;
  /** The trust-list signer; x5c is exactly its own certificate. */
  trustListSigner(): Promise<Signer>;
  /** The pinned root certificate(s), DER. */
  trustedRoots(): Uint8Array[];
}

/** Lower-case words joined by single hyphens: no dots, no path separators, nothing else. */
const NAME = /^[a-z0-9]+(-[a-z0-9]+)*$/;
// A `vc` certificate is written as vc.* for personal credentials and vc-product.* for product records.
const FILES: Record<OrganisationPurpose, string[]> = { vc: ['vc', 'vc-product'], status: ['status'], request: ['request'] };
const KEY_ALG = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN_ALG = { name: 'ECDSA', hash: 'SHA-256' } as const;

/**
 * Opened without following a symlink and without blocking (a FIFO would otherwise wait for a writer
 * and hang start-up); type and mode are checked on the open descriptor, which is then read (no TOCTOU).
 */
function readKeyFile(path: string): string {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ELOOP') throw new Error(`key store: ${path} is not a regular file`);
    throw e;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error(`key store: ${path} is not a regular file`);
    if ((st.mode & 0o077) !== 0) {
      throw new Error(`key store: ${path} is accessible by group or others (mode ${(st.mode & 0o777).toString(8)}); run chmod 600 on it`);
    }
    return readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }
}

/**
 * The chain must pass the core validator for the purpose's profile against this store's own pinned
 * roots now, so a wrong CA or another profile's certificate is refused at startup. For `vc` the
 * expected issuer URI is the leaf's only SAN URI.
 */
async function checkChain(validator: CertificateChainValidator, x5c: string[], profile: CertificateProfile, path: string): Promise<void> {
  let expectedIssuerUri: string | undefined;
  if (profile === 'vc') {
    const sans = parseCertificate(base64Decode(x5c[0]!)).sanUris;
    if (sans.length !== 1) throw new Error(`key store: ${path} must carry exactly one SAN URI (the issuer URL)`);
    expectedIssuerUri = sans[0];
  }
  const r = await validator.validate({ x5c, profile, now: new Date(), ...(expectedIssuerUri !== undefined ? { expectedIssuerUri } : {}) });
  if (!r.ok) throw new Error(`key store: ${path} does not validate for profile ${profile}: ${r.code}`);
}

function pkcs8Of(pem: string, path: string): Uint8Array {
  const m = /^-----BEGIN PRIVATE KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END PRIVATE KEY-----\s*$/.exec(pem);
  if (!m) throw new Error(`key store: ${path} is not a single PKCS#8 PRIVATE KEY block`);
  return base64Decode(m[1]!.replace(/\r?\n/g, ''));
}

/** Every certificate of a PEM file as standard base64 DER (an x5c entry), parsed once to be sure it is one. */
function certificatesOf(path: string, count: number): string[] {
  const pem = readFileSync(path, 'utf8');
  const certs = [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g)].map((m) => m[1]!.replace(/\s+/g, ''));
  if (certs.length !== count) throw new Error(`key store: ${path} must hold exactly ${count} certificate(s)`);
  for (const c of certs) parseCertificate(base64Decode(c));
  return certs;
}

/**
 * `did.json` is `{ "did": "did:certnet:<network>:<id>", "kid": "<did>#<fragment>" }` (other members
 * are ignored); `did.key.pem` the PKCS#8 P-256 key of that verification method. The public key is
 * derived from the private key: the DID document on CertNet is the only place it is published.
 */
async function loadDidSigner(jsonPath: string, keyPath: string): Promise<Signer> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(jsonPath, 'utf8'));
  } catch {
    throw new Error(`key store: ${jsonPath} is not readable JSON`);
  }
  const { did, kid } = (typeof parsed === 'object' && parsed !== null ? parsed : {}) as { did?: unknown; kid?: unknown };
  if (!isCertNetDid(did)) throw new Error(`key store: ${jsonPath}: did is not a did:certnet DID`);
  if (splitDidUrl(kid)?.did !== did) throw new Error(`key store: ${jsonPath}: kid is not <did>#<fragment> of its did`);
  const pkcs8 = pkcs8Of(readKeyFile(keyPath), keyPath);
  let key: CryptoKey;
  let publicJwk: EcPublicJwk | null;
  try {
    // Imported once extractable only to read the public point; the signing key is not extractable.
    const { kty, crv, x, y } = await globalThis.crypto.subtle.exportKey('jwk', await globalThis.crypto.subtle.importKey('pkcs8', pkcs8, KEY_ALG, true, ['sign']));
    publicJwk = normalizeEcPublicJwk({ kty, crv, x, y });
    key = await globalThis.crypto.subtle.importKey('pkcs8', pkcs8, KEY_ALG, false, ['sign']);
  } catch {
    throw new Error(`key store: ${keyPath} is not an EC P-256 private key`);
  } finally {
    pkcs8.fill(0);
  }
  if (!publicJwk) throw new Error(`key store: ${keyPath} is not an EC P-256 private key`);
  return Object.freeze({
    alg: 'ES256' as const,
    publicJwk,
    kid: kid as string,
    async sign(data: Uint8Array) {
      return new Uint8Array(await globalThis.crypto.subtle.sign(SIGN_ALG, key, data));
    },
  });
}

async function loadSigner(keyPath: string, x5c: string[]): Promise<Signer> {
  const publicJwk: EcPublicJwk | undefined = parseCertificate(base64Decode(x5c[0]!)).publicJwk;
  if (!publicJwk) throw new Error(`key store: the certificate for ${keyPath} does not hold a P-256 key`);
  const pkcs8 = pkcs8Of(readKeyFile(keyPath), keyPath);
  let key: CryptoKey;
  try {
    key = await globalThis.crypto.subtle.importKey('pkcs8', pkcs8, KEY_ALG, false, ['sign']);
  } catch {
    throw new Error(`key store: ${keyPath} is not an EC P-256 private key`);
  } finally {
    pkcs8.fill(0);
  }
  const signer: Signer = {
    alg: 'ES256',
    publicJwk,
    x5c: [...x5c],
    async sign(data) {
      return new Uint8Array(await globalThis.crypto.subtle.sign(SIGN_ALG, key, data));
    },
  };
  // The key must belong to the certificate: sign a random challenge and verify it with the certificate key.
  const challenge = webCryptoRandom.bytes(32);
  if (!(await webCryptoVerifier.verify(publicJwk, challenge, await signer.sign(challenge)))) {
    throw new Error(`key store: ${keyPath} does not match the public key of its certificate`);
  }
  return Object.freeze(signer);
}

export function createFileKeyStore(dir: string): IssuerKeyStore {
  if (typeof dir !== 'string' || dir === '') throw new TypeError('dir is required');
  const root = resolve(dir);
  const trustedRoots = () => {
    const files = ['root.cert.pem', 'root2.cert.pem'].filter((f, i) => i === 0 || existsSync(join(root, f)));
    return files.map((f) => base64Decode(certificatesOf(join(root, f), 1)[0]!));
  };
  let validator: CertificateChainValidator | undefined;
  const chainValidator = () => (validator ??= createCertificateChainValidator({ trustedRoots: trustedRoots(), verifier: webCryptoVerifier, hasher: webCryptoHasher }));
  const cache = new Map<string, Promise<Signer | null>>();
  const cached = <T extends Signer | null>(id: string, load: () => Promise<T>): Promise<T> => {
    let p = cache.get(id);
    if (!p) {
      p = load();
      cache.set(id, p);
      p.catch(() => cache.delete(id));
    }
    return p as Promise<T>;
  };
  const checkName = (organisation: string) => {
    if (typeof organisation !== 'string' || !NAME.test(organisation)) throw new TypeError('organisation must be lower-case words joined by hyphens');
  };
  /** The organisation directory itself, not a link to another organisation's (or anyone's) keys. */
  const orgDir = (organisation: string) => {
    const base = join(root, 'orgs', organisation);
    if (lstatSync(base, { throwIfNoEntry: false })?.isSymbolicLink()) throw new Error(`key store: ${base} is a symbolic link`);
    return base;
  };
  const DID_FILES = ['did.json', 'did.key.pem'];
  const ISSUING_KEYS = ['vc', 'vc-product', 'status'].map((f) => `${f}.key.pem`);
  /** One issuing path per organisation (ADR-0020 decision 1): DID files and X.509 issuing keys never together. */
  const checkOnePath = (base: string, organisation: string) => {
    if (DID_FILES.some((f) => existsSync(join(base, f))) && ISSUING_KEYS.some((f) => existsSync(join(base, f)))) {
      throw new Error(`key store: ${organisation} has both DID files and X.509 issuing keys; an organisation issues on one path only`);
    }
  };

  return {
    async signer(organisation, purpose) {
      checkName(organisation);
      if (!Object.hasOwn(FILES, purpose)) throw new TypeError('purpose must be vc, status or request');
      return cached(`${organisation}/${purpose}`, async () => {
        const base = orgDir(organisation);
        if (purpose !== 'request') checkOnePath(base, organisation);
        const found = FILES[purpose].filter((f) => existsSync(join(base, `${f}.key.pem`)));
        if (found.length !== 1) throw new Error(`key store: expected exactly one ${FILES[purpose].join(' or ')} key for ${organisation}, found ${found.length}`);
        const chainPath = join(base, `${found[0]}.chain.pem`);
        const x5c = certificatesOf(chainPath, 2);
        await checkChain(chainValidator(), x5c, purpose, chainPath);
        return loadSigner(join(base, `${found[0]}.key.pem`), x5c);
      });
    },
    async didSigner(organisation) {
      checkName(organisation);
      return cached(`${organisation}/did`, async () => {
        const base = orgDir(organisation);
        const present = DID_FILES.filter((f) => existsSync(join(base, f)));
        if (present.length === 0) return null;
        if (present.length !== 2) throw new Error(`key store: ${organisation} needs both did.json and did.key.pem, found only ${present[0]}`);
        checkOnePath(base, organisation);
        return loadDidSigner(join(base, 'did.json'), join(base, 'did.key.pem'));
      });
    },
    async trustListSigner() {
      const base = join(root, 'trust-list-signer');
      return cached('trust-list-signer', async () => {
        const certPath = join(base, 'trust-list.cert.pem');
        const x5c = certificatesOf(certPath, 1);
        await checkChain(chainValidator(), x5c, 'trust-list', certPath);
        return loadSigner(join(base, 'trust-list.key.pem'), x5c);
      });
    },
    trustedRoots,
  };
}

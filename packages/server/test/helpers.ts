// A freshly generated DEMO PKI (scripts/pki/make-demo-pki.sh) in a temporary directory, removed
// after the test file, plus the pieces every server test needs.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { after } from 'node:test';
import { base64Decode, createCertificateChainValidator } from '@identra/sdk-core';
import { webCryptoHasher, webCryptoVerifier } from '@identra/sdk-core/webcrypto';

export const REPO = fileURLToPath(new URL('../../../', import.meta.url));
export const ISSUERS = 'https://api-identra.awncorp.vn/issuers';
export const issuerUri = (name: string) => `${ISSUERS}/${name}`;

/** Generates the demo PKI once per test file; returns its directory. */
export function freshDemoPki(): string {
  const parent = mkdtempSync(join(tmpdir(), 'identra-demo-pki-'));
  after(() => rmSync(parent, { recursive: true, force: true }));
  const dir = join(parent, 'pki');
  execFileSync('bash', [join(REPO, 'scripts/pki/make-demo-pki.sh'), dir], { stdio: 'pipe' });
  return dir;
}

export const pemCerts = (path: string) =>
  [...readFileSync(path, 'utf8').matchAll(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g)].map((m) => base64Decode(m[1]!.replace(/\s+/g, '')));

export const validatorFor = (dir: string) =>
  createCertificateChainValidator({ trustedRoots: pemCerts(join(dir, 'root.cert.pem')), verifier: webCryptoVerifier, hasher: webCryptoHasher });

export function fakeClock(start = new Date()) {
  let t = start.getTime();
  return { now: () => new Date(t), advance: (seconds: number) => void (t += seconds * 1000) };
}

/** Runs make-trust-list-source.mjs on `dir` and returns its JSON output. */
export const trustListSource = (dir: string): unknown =>
  JSON.parse(execFileSync('node', [join(REPO, 'scripts/pki/make-trust-list-source.mjs'), dir], { encoding: 'utf8' }));

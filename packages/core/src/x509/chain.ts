// Certificate chain validation for x5c (docs/architecture.md section 4, ADR-0015 sections 7, 8, 14, 15).
// Signatures are checked only through the injected Verifier; hashing only through the Hasher.
import { base64Decode, base64UrlEncode, bytesEqual } from '../encoding.js';
import type { CertificateChainValidator, CertificateProfile, ChainValidationResult, Hasher, Verifier } from '../interfaces.js';
import { ErrorCodes, type Check, type CheckId, type ErrorCode } from '../results.js';
import { OID, parseCertificate, type ParsedCertificate } from './parse.js';

export const MAX_CERTIFICATE_BYTES = 4096;
export const CLOCK_SKEW_MS = 60_000;

const PROFILES: readonly CertificateProfile[] = ['vc', 'status', 'request', 'trust-list'];
// Critical extensions this validator understands; any other critical extension is rejected.
const KNOWN_CRITICAL = new Set<string>([OID.basicConstraints, OID.keyUsage, OID.subjectAltName]);
// Cheap bound on the string before decoding; the 4 KB rule itself applies to the decoded DER.
const MAX_BASE64_LENGTH = 2 * MAX_CERTIFICATE_BYTES;

class StepFailure {
  constructor(
    readonly code: ErrorCode,
    readonly detail: string,
  ) {}
}

export function createCertificateChainValidator(options: {
  trustedRoots: Uint8Array[];
  verifier: Verifier;
  hasher: Hasher;
}): CertificateChainValidator {
  const { trustedRoots, verifier, hasher } = options;
  if (!Array.isArray(trustedRoots) || trustedRoots.length < 1 || trustedRoots.length > 2) {
    throw new TypeError('trustedRoots must hold one or two root certificates (DER)');
  }
  if (typeof verifier?.verify !== 'function' || typeof hasher?.sha256 !== 'function') {
    throw new TypeError('verifier and hasher are required');
  }
  const roots = trustedRoots.map((der) => parseCertificate(der));

  async function signedBy(cert: ParsedCertificate, issuer: ParsedCertificate): Promise<boolean> {
    if (cert.signatureAlgorithm !== OID.ecdsaWithSha256 || !cert.signature || !issuer.publicJwk) return false;
    return verifier.verify(issuer.publicJwk, cert.tbs, cert.signature);
  }

  // Step 1: shape of x5c. Returns the parsed certificates, leaf first.
  function parseChain(x5c: unknown, profile: CertificateProfile): ParsedCertificate[] {
    const fail = (detail: string) => new StepFailure(ErrorCodes.CERT_CHAIN_MALFORMED, detail);
    const expected = profile === 'trust-list' ? 1 : 2;
    if (!Array.isArray(x5c) || x5c.length !== expected) throw fail(`x5c must hold exactly ${expected} certificate(s)`);
    return x5c.map((entry: unknown, i) => {
      if (typeof entry !== 'string' || entry.length === 0 || entry.length > MAX_BASE64_LENGTH) throw fail(`x5c[${i}] is not a non-empty string of bounded length`);
      let der: Uint8Array;
      let cert: ParsedCertificate;
      try {
        der = base64Decode(entry);
      } catch {
        throw fail(`x5c[${i}] is not valid base64`);
      }
      if (der.length > MAX_CERTIFICATE_BYTES) throw fail(`x5c[${i}] is larger than 4 KB`);
      try {
        cert = parseCertificate(der);
      } catch {
        throw fail(`x5c[${i}] is not a DER certificate`);
      }
      if (roots.some((r) => bytesEqual(r.der, der))) throw fail(`x5c[${i}] is a pinned root`);
      if (bytesEqual(cert.issuerName, cert.subjectName)) throw fail(`x5c[${i}] is self-issued`);
      return cert;
    });
  }

  // Step 2: names chain byte for byte and every signature verifies, the last one with a pinned root.
  async function findRoot(chain: ParsedCertificate[]): Promise<ParsedCertificate> {
    const fail = (detail: string) => new StepFailure(ErrorCodes.CERT_CHAIN_UNTRUSTED, detail);
    for (let i = 0; i + 1 < chain.length; i++) {
      if (!bytesEqual(chain[i]!.issuerName, chain[i + 1]!.subjectName)) throw fail(`x5c[${i}] issuer name does not match x5c[${i + 1}] subject`);
    }
    const last = chain[chain.length - 1]!;
    // Two pinned roots may share a name during a root change, so every name match is tried.
    const candidates = roots.filter((r) => bytesEqual(r.subjectName, last.issuerName));
    if (candidates.length === 0) throw fail('last certificate is not issued by a pinned root');
    for (let i = 0; i + 1 < chain.length; i++) {
      if (!(await signedBy(chain[i]!, chain[i + 1]!))) throw fail(`x5c[${i}] signature does not verify`);
    }
    for (const root of candidates) if (await signedBy(last, root)) return root;
    throw fail(`x5c[${chain.length - 1}] signature does not verify with a pinned root`);
  }

  // Step 3: validity of every certificate including the root, with clock skew.
  function checkValidity(certs: { cert: ParsedCertificate; label: string }[], now: Date): void {
    const t = now.getTime();
    for (const { cert, label } of certs) {
      if (t < cert.notBefore.getTime() - CLOCK_SKEW_MS) throw new StepFailure(ErrorCodes.CERT_NOT_YET_VALID, `${label} is not yet valid`);
      if (t > cert.notAfter.getTime() + CLOCK_SKEW_MS) throw new StepFailure(ErrorCodes.CERT_EXPIRED, `${label} has expired`);
    }
  }

  // Step 4: basicConstraints, keyUsage, subject and critical extensions (ADR-0015 section 15).
  function checkConstraints(chain: ParsedCertificate[], root: ParsedCertificate, profile: CertificateProfile): void {
    const fail = (detail: string) => new StepFailure(ErrorCodes.CERT_CONSTRAINT_INVALID, detail);
    const leaf = chain[0]!;
    if (!leaf.basicConstraints || leaf.basicConstraints.cA) throw fail('leaf must have basicConstraints CA:FALSE');
    if (!leaf.keyUsage?.digitalSignature) throw fail('leaf keyUsage must include digitalSignature');
    if (profile !== 'trust-list') {
      const s = leaf.subject;
      if (!s.O || !s.C || !s.organizationIdentifier) throw fail('leaf subject must carry O, C and organizationIdentifier');
      const ca = chain[1]!;
      if (!ca.basicConstraints?.cA || ca.basicConstraints.pathLenConstraint !== 0) throw fail('issuing CA must have CA:TRUE and pathLenConstraint 0');
      if (!ca.keyUsage?.keyCertSign) throw fail('issuing CA keyUsage must include keyCertSign');
    }
    if (!root.basicConstraints?.cA) throw fail('root must have CA:TRUE');
    if (!root.keyUsage?.keyCertSign) throw fail('root keyUsage must include keyCertSign');
    for (const cert of [...chain, root]) {
      const unknown = cert.criticalExtensions.find((o) => !KNOWN_CRITICAL.has(o));
      if (unknown) throw fail(`unknown critical extension ${unknown}`);
    }
  }

  return {
    async validate(input) {
      const { x5c, profile, now, expectedIssuerUri } = input;
      if (!PROFILES.includes(profile)) throw new TypeError(`unknown profile ${String(profile)}`);
      if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('now must be a valid Date');
      if (expectedIssuerUri !== undefined && (profile !== 'vc' || typeof expectedIssuerUri !== 'string')) {
        throw new TypeError('expectedIssuerUri is a string and only applies to profile vc');
      }

      // One check per step, in order; the first failure stops the run and later steps are SKIPPED.
      const ids: CheckId[] = ['chain_format', 'chain_signatures', 'chain_validity', 'chain_constraints', 'leaf_key'];
      if (expectedIssuerUri !== undefined) ids.push('issuer_uri');
      const checks: Check[] = [];
      const pass = () => void checks.push({ id: ids[checks.length]!, ok: true, code: null });
      try {
        const chain = parseChain(x5c, profile);
        pass();
        const root = await findRoot(chain);
        pass();
        const labelled = chain.map((cert, i) => ({ cert, label: i === 0 ? 'leaf' : 'issuing CA' }));
        checkValidity([...labelled, { cert: root, label: 'root' }], now);
        pass();
        checkConstraints(chain, root, profile);
        pass();
        const leaf = chain[0]!;
        if (!leaf.publicJwk) throw new StepFailure(ErrorCodes.CERT_KEY_NOT_ALLOWED, 'leaf key is not EC P-256');
        pass();
        if (expectedIssuerUri !== undefined) {
          if (!leaf.sanUris.includes(expectedIssuerUri)) {
            throw new StepFailure(ErrorCodes.ISSUER_MISMATCH, 'expected issuer URI is not a SAN URI of the leaf');
          }
          pass();
        }
        const fingerprint = base64UrlEncode(await hasher.sha256(leaf.der));
        return { ok: true, code: null, checks, leaf, fingerprint } satisfies ChainValidationResult;
      } catch (e) {
        if (!(e instanceof StepFailure)) throw e;
        checks.push({ id: ids[checks.length]!, ok: false, code: e.code, detail: e.detail });
        for (const id of ids.slice(checks.length)) checks.push({ id, ok: false, code: ErrorCodes.SKIPPED, skipped: true });
        return { ok: false, code: e.code, checks };
      }
    },
  };
}

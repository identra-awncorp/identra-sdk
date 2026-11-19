// Adapters from the Identra interfaces to the callbacks of @sd-jwt/sd-jwt-vc. This is the only
// file that imports @sd-jwt/*. The library is used to issue and to present (ADR-0004,
// "Bổ sung 2026-11-19" point 3); verification never calls it.
import '../zod-config.js'; // before the library: see zod-config.ts
import { SdJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { base64UrlEncode, utf8Encode } from '../encoding.js';
import type { Hasher, RandomSource, Signer } from '../interfaces.js';

type LibSigner = (data: string) => Promise<string>;

function libSigner(signer: Signer): LibSigner {
  return async (data) => {
    const signature = await signer.sign(utf8Encode(data));
    if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new TypeError('signer must return a 64-byte r||s signature');
    return base64UrlEncode(signature);
  };
}

function libHasher(hasher: Hasher) {
  return (data: string | ArrayBuffer, alg: string): Promise<Uint8Array> => {
    if (alg !== 'sha-256') throw new TypeError(`hash algorithm ${alg} is not allowed`);
    return hasher.sha256(typeof data === 'string' ? utf8Encode(data) : new Uint8Array(data));
  };
}

/** Issues `payload` with the given top-level claims disclosable and `decoys` decoy digests. */
export async function libIssue(options: {
  signer: Signer & { x5c: string[] };
  hasher: Hasher;
  random: RandomSource;
  payload: Record<string, unknown>;
  disclosable: string[];
  decoys: number;
}): Promise<string> {
  const { signer, hasher, random, payload, disclosable, decoys } = options;
  const instance = new SdJwtVcInstance({
    signer: libSigner(signer),
    signAlg: 'ES256',
    hasher: libHasher(hasher),
    hashAlg: 'sha-256',
    // The library asks for 16 bytes: 128-bit salts from our RandomSource (ADR-0001).
    saltGenerator: (length: number) => base64UrlEncode(random.bytes(length)),
  });
  const frame = disclosable.length > 0 ? { _sd: disclosable, _sd_decoy: decoys } : undefined;
  // Header becomes { typ: 'dc+sd-jwt', x5c, alg: 'ES256' }.
  return instance.issue(payload as { vct: string; iss: string }, frame as never, { header: { x5c: [...signer.x5c] } });
}

/** Keeps the named top-level disclosures and appends a KB-JWT signed by `holderSigner`. */
export async function libPresent(options: {
  compact: string;
  disclose: string[];
  holderSigner: Signer;
  hasher: Hasher;
  kbPayload: { iat: number; aud: string; nonce: string };
}): Promise<string> {
  const { compact, disclose, holderSigner, hasher, kbPayload } = options;
  const instance = new SdJwtVcInstance({ hasher: libHasher(hasher), kbSigner: libSigner(holderSigner), kbSignAlg: 'ES256' });
  const frame = Object.fromEntries(disclose.map((name) => [name, true]));
  return instance.present(compact, frame as never, { kb: { payload: kbPayload } });
}

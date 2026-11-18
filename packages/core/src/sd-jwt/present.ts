// Holder side: selective disclosure plus a KB-JWT (ADR-0008 sections 4 and 5).
import type { Hasher, Signer } from '../interfaces.js';
import { normalizeEcPublicJwk } from '../jwk.js';
import { parseSdJwt } from './compact.js';
import { libPresent } from './library.js';

/**
 * Returns a presentation of a stored credential that carries only the disclosures named in
 * `disclose` and a KB-JWT (`typ: kb+jwt`, `alg: ES256`, payload `iat`, `aud`, `nonce`, `sd_hash`)
 * signed by `holderSigner`, whose key must be the credential's `cnf.jwk`. Throws TypeError on
 * programmer error (unknown claim name, credential without `cnf`, wrong key, KB-JWT already present).
 */
export async function createPresentation(input: {
  compact: string;
  disclose: string[];
  holderSigner: Signer;
  audience: string;
  nonce: string;
  now: Date;
  hasher: Hasher;
}): Promise<string> {
  const { compact, disclose, holderSigner, audience, nonce, now, hasher } = input;
  const parsed = parseSdJwt(compact);
  if (!parsed.ok) throw new TypeError(`not an SD-JWT compact (${parsed.detail})`);
  const { payload, disclosures, kbJwt } = parsed.sdJwt;
  if (kbJwt !== null) throw new TypeError('the credential already carries a KB-JWT');
  const cnf = payload['cnf'] as { jwk?: unknown } | undefined;
  const cnfJwk = normalizeEcPublicJwk(cnf?.jwk);
  if (!cnfJwk) throw new TypeError('the credential has no holder binding (cnf.jwk)');
  if (holderSigner?.alg !== 'ES256' || holderSigner.publicJwk?.x !== cnfJwk.x || holderSigner.publicJwk?.y !== cnfJwk.y) {
    throw new TypeError('holderSigner must be the ES256 key of cnf.jwk');
  }
  const available = disclosures.filter((d) => d.array.length === 3).map((d) => d.array[1]);
  if (!Array.isArray(disclose) || new Set(disclose).size !== disclose.length) throw new TypeError('disclose must list distinct names');
  for (const name of disclose) if (!available.includes(name)) throw new TypeError(`the credential has no disclosure named ${name}`);
  if (typeof audience !== 'string' || audience === '' || typeof nonce !== 'string' || nonce === '') {
    throw new TypeError('audience and nonce must be non-empty strings');
  }
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('now must be a valid Date');
  try {
    return await libPresent({
      compact,
      disclose,
      holderSigner,
      hasher,
      kbPayload: { iat: Math.floor(now.getTime() / 1000), aud: audience, nonce },
    });
  } catch {
    throw new TypeError('the SD-JWT library refused to present the credential'); // its message may quote claim values
  }
}

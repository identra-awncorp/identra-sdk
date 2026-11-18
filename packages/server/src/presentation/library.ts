// Adapter to @openid4vc/openid4vp, dcql and jose for the verifier: the only file of the verifier
// that imports them. The library parses the direct_post.jwt response (after our jose decryption)
// and dcql builds and evaluates the query; every decision is taken by the caller.
import { Openid4vpVerifier } from '@openid4vc/openid4vp';
import { DcqlPresentationResult, DcqlQuery } from 'dcql';
import { compactDecrypt, decodeProtectedHeader, importJWK, type JWK } from 'jose';
import { normalizeEcPublicJwk, utf8Decode, utf8Encode, type EcPublicJwk, type Hasher } from '@identra/sdk-core';

export const CREDENTIAL_QUERY_ID = 'credential';
export const RESPONSE_ENC_VALUES = ['A256GCM', 'A128GCM'];

export interface Scenario {
  vct: string;
  /** Claim sets in order of preference; each a list of top-level claim names. */
  claimSets: string[][];
  purpose: { vi: string; en: string };
}

/** The DCQL query of a scenario: one dc+sd-jwt credential of `vct`, its claim sets, the purpose. Validated by dcql. */
export function dcqlQueryOf(s: Scenario): Record<string, unknown> {
  const names = [...new Set(s.claimSets.flat())];
  const query = {
    credentials: [{
      id: CREDENTIAL_QUERY_ID,
      format: 'dc+sd-jwt' as const,
      meta: { vct_values: [s.vct] },
      claims: names.map((n) => ({ id: n, path: [n] })),
      claim_sets: s.claimSets,
    }],
    credential_sets: [{ options: [[CREDENTIAL_QUERY_ID]], purpose: { ...s.purpose } }],
  };
  DcqlQuery.validate(DcqlQuery.parse(query));
  return query;
}

/** A fresh ECDH P-256 key for one session: its public JWK and its private JWK (kept only in the session state). */
export async function generateSessionKey(kid: string): Promise<{ publicJwk: EcPublicJwk & { kid: string; alg: 'ECDH-ES'; use: 'enc' }; privateJwk: JWK }> {
  const pair = await globalThis.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const privateJwk = (await globalThis.crypto.subtle.exportKey('jwk', pair.privateKey)) as JWK;
  const publicJwk = normalizeEcPublicJwk(await globalThis.crypto.subtle.exportKey('jwk', pair.publicKey));
  if (!publicJwk) throw new Error('generated ECDH key is not P-256');
  return { publicJwk: { ...publicJwk, kid, alg: 'ECDH-ES', use: 'enc' }, privateJwk: { kty: 'EC', crv: 'P-256', x: privateJwk.x!, y: privateJwk.y!, d: privateJwk.d! } };
}

const notUsed = () => {
  throw new Error('the verifier never asks the OpenID4VP library to sign or verify');
};

/** Decrypts a compact JWE with ECDH-ES and A128GCM / A256GCM only; a compressed (`zip`) JWE is refused before any work. Null on failure. */
export async function decryptCompact(jwe: string, privateJwk: JWK): Promise<string | null> {
  try {
    if ('zip' in decodeProtectedHeader(jwe)) return null;
    const { plaintext } = await compactDecrypt(jwe, await importJWK(privateJwk, 'ECDH-ES'), { keyManagementAlgorithms: ['ECDH-ES'], contentEncryptionAlgorithms: RESPONSE_ENC_VALUES });
    return utf8Decode(plaintext);
  } catch {
    return null;
  }
}

/**
 * Decrypts (decryptCompact, the session key only) and parses a direct_post.jwt response form; the
 * library checks `state` against the request. Returns the `vp_token` exactly as decrypted (not as
 * the library normalises it), or null for anything refused. Never throws for bad input.
 */
export async function parseResponse(o: { form: Record<string, string>; requestPayload: Record<string, unknown>; privateJwk: JWK; hasher: Hasher }): Promise<unknown> {
  let decrypted: string | null = null;
  const callbacks = {
    hash: (data: string | ArrayBuffer) => o.hasher.sha256(typeof data === 'string' ? utf8Encode(data) : new Uint8Array(data)),
    generateRandom: notUsed,
    signJws: notUsed,
    verifyJws: notUsed,
    encryptJwe: notUsed,
    clientAuthentication: () => {},
    decryptJwe: async (jwe: string, options?: { jwk?: unknown }) => {
      decrypted = await decryptCompact(jwe, o.privateJwk);
      return decrypted === null ? { decrypted: false } : { decrypted: true, decryptionJwk: (options?.jwk ?? {}) as never, payload: decrypted };
    },
  } as never;
  try {
    const parsed = await new Openid4vpVerifier({ callbacks }).parseOpenid4vpAuthorizationResponse({ authorizationResponse: o.form, authorizationRequestPayload: o.requestPayload as never, callbacks });
    if (parsed.type !== 'dcql' || parsed.jarm?.type !== 'Encrypted' || decrypted === null) return null;
    return (JSON.parse(decrypted) as { vp_token?: unknown }).vp_token ?? null;
  } catch {
    return null;
  }
}

/**
 * The index of the first claim set of `query` (the verifier's order of preference) that the
 * verified claims of a presentation satisfy, or null.
 */
export function satisfiedClaimSet(query: Record<string, unknown>, presented: { vct: string; claims: Record<string, unknown> }): number | null {
  try {
    const result = DcqlPresentationResult.fromDcqlPresentation(
      { [CREDENTIAL_QUERY_ID]: [{ credential_format: 'dc+sd-jwt', vct: presented.vct, claims: presented.claims as never, cryptographic_holder_binding: true }] },
      { dcqlQuery: DcqlQuery.parse(query as never) },
    );
    const match = result.credential_matches[CREDENTIAL_QUERY_ID];
    if (!result.can_be_satisfied || !match?.success) return null;
    const indexes = match.valid_credentials[0]?.claims.valid_claim_sets.map((c) => c.claim_set_index ?? 0) ?? [];
    return indexes.length > 0 ? Math.min(...indexes) : null;
  } catch {
    return null;
  }
}

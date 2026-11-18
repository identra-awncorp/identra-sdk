// Adapter to @openid4vc/openid4vci, @openid4vc/openid4vp and dcql for the wallet: the only file of
// sdk-app that imports them, so a library upgrade touches one place. The libraries parse (zod) and
// send; every decision is taken by the caller on the plain JSON this file hands back. Crypto goes
// through the callbacks below: the noble JWE, the injected Hasher and RandomSource, the wallet key's
// Signer, and for request objects the caller's own JWS check.
import { Openid4vciClient, type CredentialOfferObject, type IssuerMetadataResult } from '@openid4vc/openid4vci';
import { Openid4vpClient } from '@openid4vc/openid4vp';
import { DcqlQuery } from 'dcql';
import { base64UrlEncode, normalizeEcPublicJwk, utf8Decode, utf8Encode, type EcPublicJwk, type Hasher, type HttpFetch, type RandomSource, type Signer } from '@identra/sdk-core';
import { decryptJwe, encryptJwe, JweError } from '../jwe.js';
import { WalletFetchError, type WalletFetchErrorCode } from './fetch.js';

export interface LibraryDeps {
  /** Already guarded (fetch.ts). */
  fetch: HttpFetch;
  hasher: Hasher;
  random: RandomSource;
}

/** The resolved offer and metadata as the library parsed them. Read-only for the caller. */
export interface IssuerSession {
  offer: Record<string, unknown>;
  credentialIssuer: Record<string, unknown>;
  authorizationServers: Record<string, unknown>[];
  /** 'V1' for OpenID4VCI 1.0 metadata. */
  version: string;
}

// Header names copied into the library's Response; HttpFetch cannot enumerate headers.
const RESPONSE_HEADERS = ['content-type', 'www-authenticate', 'dpop-nonce', 'cache-control'];

/** The library's fetch (RequestInit in, Response out) over an HttpFetch. Needs the globals Headers and Response. */
function libraryFetch(fetch: HttpFetch) {
  return async (input: string, init: RequestInit): Promise<Response> => {
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((value, name) => (headers[name] = value));
    if (init.body !== undefined && init.body !== null && typeof init.body !== 'string') throw new TypeError('only string request bodies are supported');
    const res = await fetch(input, { method: (init.method ?? 'GET').toUpperCase(), headers, ...(typeof init.body === 'string' ? { body: init.body } : {}) });
    const bytes = utf8Encode(await res.text());
    return {
      status: res.status,
      statusText: '',
      ok: res.status >= 200 && res.status < 300,
      url: input,
      redirected: false,
      body: null,
      headers: {
        get: (name: string) => res.headers.get(name),
        forEach: (cb: (value: string, name: string) => void) => {
          for (const name of RESPONSE_HEADERS) {
            const v = res.headers.get(name);
            if (v !== null) cb(v, name);
          }
        },
      },
      arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    } as unknown as Response;
  };
}

function callbacks(deps: LibraryDeps, keys: { signer?: Signer; responseKey?: { secretKey: Uint8Array; publicJwk: EcPublicJwk } } = {}) {
  return {
    fetch: libraryFetch(deps.fetch),
    hash: (data: string | ArrayBuffer, alg: string) => {
      if (alg !== 'sha-256' && alg !== 'SHA-256') throw new TypeError('only SHA-256');
      return deps.hasher.sha256(typeof data === 'string' ? utf8Encode(data) : new Uint8Array(data));
    },
    generateRandom: (n: number) => deps.random.bytes(n),
    clientAuthentication: () => {},
    signJws: async (signer: { method: string; alg: string; publicJwk?: unknown }, { signingInputBytes }: { signingInputBytes: Uint8Array }) => {
      const own = keys.signer;
      const jwk = normalizeEcPublicJwk(signer.publicJwk);
      if (!own || signer.method !== 'jwk' || signer.alg !== 'ES256' || jwk?.x !== own.publicJwk.x || jwk.y !== own.publicJwk.y) throw new TypeError('no wallet key for this signer');
      return { signature: base64UrlEncode(await own.sign(signingInputBytes)), signerJwk: { ...own.publicJwk } };
    },
    encryptJwe: (encryptor: { method: string; alg?: string; enc: string; publicJwk?: unknown; kid?: string }, data: string) => {
      const recipient = normalizeEcPublicJwk(encryptor.publicJwk);
      if (encryptor.method !== 'jwk' || encryptor.alg !== 'ECDH-ES' || !recipient || (encryptor.enc !== 'A128GCM' && encryptor.enc !== 'A256GCM')) {
        throw new TypeError('unsupported request encryption');
      }
      const header = encryptor.kid !== undefined ? { kid: encryptor.kid } : {};
      const jwe = encryptJwe({ recipientPublicJwk: recipient, enc: encryptor.enc, plaintext: utf8Encode(data), random: deps.random, header });
      return { jwe, encryptionJwk: { ...recipient } };
    },
    decryptJwe: (jwe: string, options?: { jwk?: unknown }) => {
      const key = keys.responseKey;
      const asked = normalizeEcPublicJwk(options?.jwk);
      if (!key || asked?.x !== key.publicJwk.x || asked.y !== key.publicJwk.y) return { decrypted: false as const };
      try {
        const { plaintext } = decryptJwe({ jwe, recipientSecretKey: key.secretKey });
        return { decrypted: true as const, decryptionJwk: { ...key.publicJwk }, payload: utf8Decode(plaintext) };
      } catch (e) {
        if (e instanceof JweError) return { decrypted: false as const };
        throw e;
      }
    },
  };
}

const client = (deps: LibraryDeps, keys?: Parameters<typeof callbacks>[1]) => new Openid4vciClient({ callbacks: callbacks(deps, keys) as never });
const internal = new WeakMap<IssuerSession, { offer: CredentialOfferObject; metadata: IssuerMetadataResult }>();
const libraryState = (s: IssuerSession) => {
  const state = internal.get(s);
  if (!state) throw new TypeError('not a session created by resolveMetadata');
  return state;
};

/** Fetches the offer by reference (`credential_offer_uri` of the QR text). */
export async function resolveOffer(qrText: string, deps: LibraryDeps): Promise<Record<string, unknown>> {
  return (await client(deps).resolveCredentialOffer(qrText)) as Record<string, unknown>;
}

/** Fetches the credential issuer and authorization server metadata for an offer from resolveOffer. */
export async function resolveMetadata(offer: Record<string, unknown>, deps: LibraryDeps): Promise<IssuerSession> {
  const credentialOffer = offer as CredentialOfferObject;
  const metadata = await client(deps).resolveIssuerMetadata(credentialOffer.credential_issuer);
  const session: IssuerSession = {
    offer,
    credentialIssuer: metadata.credentialIssuer as Record<string, unknown>,
    authorizationServers: metadata.authorizationServers as Record<string, unknown>[],
    version: metadata.originalDraftVersion,
  };
  internal.set(session, { offer: credentialOffer, metadata });
  return session;
}

export async function requestAccessToken(session: IssuerSession, txCode: string | undefined, deps: LibraryDeps): Promise<string> {
  const { offer, metadata } = libraryState(session);
  const r = await client(deps).retrievePreAuthorizedCodeAccessTokenFromOffer({ credentialOffer: offer, issuerMetadata: metadata, ...(txCode !== undefined ? { txCode } : {}) });
  return r.accessTokenResponse.access_token;
}

export async function requestNonce(session: IssuerSession, deps: LibraryDeps): Promise<string> {
  return (await client(deps).requestNonce({ issuerMetadata: libraryState(session).metadata })).c_nonce;
}

/** Proof JWT `typ: openid4vci-proof+jwt`, header `jwk`, `aud` = credential issuer, `nonce`, `iat` = now. */
export async function createProof(session: IssuerSession, o: { configurationId: string; nonce: string; signer: Signer; now: Date }, deps: LibraryDeps): Promise<string> {
  const r = await client(deps, { signer: o.signer }).createCredentialRequestJwtProof({
    issuerMetadata: libraryState(session).metadata,
    credentialConfigurationId: o.configurationId,
    nonce: o.nonce,
    issuedAt: o.now,
    signer: { method: 'jwk', publicJwk: { ...o.signer.publicJwk }, alg: 'ES256' },
  });
  return r.jwt;
}

/**
 * Credential request with one jwt proof, asking for a response encrypted to `responseKey`
 * (ECDH-ES, A256GCM); the library then encrypts the request to the issuer's advertised key and
 * refuses a response that is not encrypted. Returns the `credentials` value of the response as is.
 */
export async function requestCredential(
  session: IssuerSession,
  o: { configurationId: string; accessToken: string; proof: string; responseKey: { secretKey: Uint8Array; publicJwk: EcPublicJwk } },
  deps: LibraryDeps,
): Promise<unknown> {
  const r = await client(deps, { responseKey: o.responseKey }).retrieveCredentials({
    issuerMetadata: libraryState(session).metadata,
    accessToken: o.accessToken,
    credentialConfigurationId: o.configurationId,
    proofs: { jwt: [o.proof] },
    credentialResponseEncryption: { jwk: { ...o.responseKey.publicJwk, alg: 'ECDH-ES', use: 'enc' }, enc: 'A256GCM' },
  });
  return (r.credentialResponse as Record<string, unknown>)['credentials'];
}

/**
 * What went wrong in a library call: the code of a WalletFetchError anywhere in the cause chain
 * (the library wraps fetch errors), else ISSUER_ERROR; plus the OAuth `error` and the HTTP status
 * of an unsuccessful response, when the library reports them.
 */
export function failureOf(e: unknown): { code: WalletFetchErrorCode; oauthError: string | null; httpStatus: number | null } {
  let oauthError: string | null = null;
  let httpStatus: number | null = null;
  for (let x: unknown = e, depth = 0; x instanceof Error && depth < 8; x = x.cause, depth++) {
    if (x instanceof WalletFetchError) return { code: x.code, oauthError: null, httpStatus: null };
    const { errorResponse, response } = x as { errorResponse?: { error?: unknown }; response?: { status?: unknown } };
    if (oauthError === null && typeof errorResponse?.error === 'string') oauthError = errorResponse.error;
    if (httpStatus === null && typeof response?.status === 'number') httpStatus = response.status;
  }
  return { code: 'ISSUER_ERROR', oauthError, httpStatus };
}

/** What the caller's request-object check sees: the x5c and the exact signed bytes the library extracted. */
export interface JarToCheck {
  x5c: unknown;
  alg: string;
  header: Record<string, unknown>;
  /** `<header>.<payload>` as received. */
  signingInput: string;
  signature: string;
}

/**
 * Parses an `openid4vp://` QR text and fetches its request object by reference with GET (the
 * library's `request_uri_method=post` body is wrong in 0.10.0; the caller refuses that parameter).
 * The JWS is decided by `checkJar`, called by the library as its `verifyJws`; it returns the
 * signer's public JWK or null. The library then checks the `x509_hash` client identifier itself,
 * for which it insists on a `getX509CertificateMetadata` callback it does not use for that prefix.
 * Time checks of the library use `deps.now` (the injected clock). Returns the request payload, or throws.
 */
export async function resolvePresentationRequest(qrText: string, deps: LibraryDeps & { now: Date }, checkJar: (jar: JarToCheck) => Promise<EcPublicJwk | null>): Promise<Record<string, unknown>> {
  const c = new Openid4vpClient({
    callbacks: {
      ...callbacks(deps),
      verifyJws: async (signer: { method: string; alg: string; x5c?: unknown }, ctx: { signingInput: string; signature: string; protectedHeader: Record<string, unknown> }) => {
        if (signer.method !== 'x5c') return { verified: false as const };
        const jwk = await checkJar({ x5c: signer.x5c, alg: signer.alg, header: ctx.protectedHeader, signingInput: ctx.signingInput, signature: ctx.signature });
        return jwk ? { verified: true as const, signerJwk: { ...jwk } } : { verified: false as const };
      },
      getX509CertificateMetadata: () => ({ sanDnsNames: [], sanUriNames: [] }),
    } as never,
  });
  const parsed = c.parseOpenid4vpAuthorizationRequest({ authorizationRequest: qrText });
  const resolved = await c.resolveOpenid4vpAuthorizationRequest({ authorizationRequestPayload: parsed.params as never, responseMode: { type: 'direct_post' } as never, now: deps.now });
  return resolved.authorizationRequestPayload as Record<string, unknown>;
}

/**
 * dcql over the wallet's credentials (claims = the disclosable claims): per credential, the
 * indexes of the claim sets of `queryId` it satisfies, in the query's order. Null when dcql refuses the query.
 */
export function matchDcql(query: unknown, queryId: string, credentials: { vct: string; claims: Record<string, unknown> }[]): number[][] | null {
  let parsed;
  try {
    parsed = DcqlQuery.parse(query as never);
    DcqlQuery.validate(parsed);
  } catch {
    return null;
  }
  const out: number[][] = credentials.map(() => []);
  if (credentials.length === 0) return out;
  const result = DcqlQuery.query(parsed, credentials.map((c) => ({ credential_format: 'dc+sd-jwt' as const, vct: c.vct, claims: c.claims as never, cryptographic_holder_binding: true })));
  const match = result.credential_matches[queryId];
  for (const v of match?.success ? match.valid_credentials : []) {
    out[v.input_credential_index] = v.claims.valid_claim_sets.map((c) => c.claim_set_index ?? 0).sort((a, b) => a - b);
  }
  return out;
}

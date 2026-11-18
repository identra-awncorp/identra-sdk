// Adapter to @openid4vc/openid4vci for the wallet: the only file of sdk-app that imports an
// @openid4vc package, so a library upgrade touches one place. The library parses (zod) and sends;
// every decision is taken by the caller on the plain JSON this file hands back. Crypto goes through
// the callbacks below: the noble JWE, the injected Hasher and RandomSource, and the wallet key's
// Signer. GĐ6 adds the x5c `verifyJws` path for request objects here.
import { Openid4vciClient, type CredentialOfferObject, type IssuerMetadataResult } from '@openid4vc/openid4vci';
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
    const res = await fetch(input, { method: init.method ?? 'GET', headers, ...(typeof init.body === 'string' ? { body: init.body } : {}) });
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

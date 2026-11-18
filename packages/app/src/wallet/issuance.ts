// The wallet's side of OpenID4VCI 1.0, pre-authorized code (ADR-0010, docs/architecture.md section 8).
// resolve: QR text -> offer by reference -> metadata, all on the QR's origin; nothing is created.
// accept: token (PIN) -> c_nonce -> new wallet key -> proof -> encrypted credential request ->
// the credential is verified as the wallet would verify it to present it -> vault. Any failure after
// the key was created deletes the key again, and nothing is saved.
import { DIPLOMA_CLAIMS, jwkThumbprint, VCT, verifyStoredCredential, type EcPublicJwk, type HttpFetch } from '@identra/sdk-core';
import { generateSecretKey, P256, uncompressedPointToJwk } from '../crypto/noble.js';
import { Fail, WalletErrorCodes as C, type WalletFailure } from './errors.js';
import { guardFetch, httpsOrigin, PROTOCOL_MAX_BYTES, PROTOCOL_TIMEOUT_MS } from './fetch.js';
import { createProof, failureOf, requestAccessToken, requestCredential, requestNonce, resolveMetadata, resolveOffer, type IssuerSession, type LibraryDeps } from './library.js';
import type { WalletContext } from './context.js';

/** Claims a credential type must disclose to the holder; only holder-bound types can be received. */
export const REQUIRED_CLAIMS: Readonly<Record<string, readonly string[]>> = Object.freeze({ [VCT.diploma]: DIPLOMA_CLAIMS });

const PRE_AUTHORIZED_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const OFFER_SCHEME = 'openid-credential-offer://?';

export interface DisplayEntry {
  name: string;
  locale?: string;
}

/** What the consent screen shows. Display names come from the issuer's metadata and are not verified yet. */
export interface ResolvedOffer {
  issuerUri: string;
  issuerDisplay: DisplayEntry[];
  configuration: { id: string; vct: string; display: DisplayEntry[] };
  txCode: { length: number | null; inputMode: 'numeric' | 'text'; description: string | null } | null;
}

export type AcceptResult = { ok: true; credentialId: string; vct: string; issuerName: string } | WalletFailure;

interface OfferState {
  issuerUri: string;
  offerUri: string;
  origin: string;
  session: IssuerSession;
  configurationId: string;
  vct: string;
}
const offers = new WeakMap<ResolvedOffer, OfferState>();

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
function displayOf(v: unknown): DisplayEntry[] {
  if (!Array.isArray(v)) return [];
  return v.filter((d) => isObject(d) && typeof d['name'] === 'string').map((d) => ({ name: d['name'] as string, ...(typeof d['locale'] === 'string' ? { locale: d['locale'] } : {}) }));
}

/** The `credential_offer_uri` of a QR text that is exactly `openid-credential-offer://?credential_offer_uri=<https URL>`. */
function offerUriOf(qrText: unknown): string {
  if (typeof qrText !== 'string' || !qrText.startsWith(OFFER_SCHEME) || qrText.length > 2048) throw new Fail(C.OFFER_INVALID);
  const params = new URLSearchParams(qrText.slice(OFFER_SCHEME.length));
  const uri = params.get('credential_offer_uri');
  let count = 0;
  params.forEach(() => count++);
  if (count !== 1 || uri === null) throw new Fail(C.OFFER_INVALID);
  if (httpsOrigin(uri) === null) throw new Fail(C.URL_NOT_ALLOWED);
  return uri;
}

/** Throws URL_NOT_ALLOWED unless `url` is https on `origin`. */
function sameOrigin(url: unknown, origin: string): void {
  if (httpsOrigin(url) !== origin) throw new Fail(C.URL_NOT_ALLOWED);
}

/** Everything the wallet relies on in the metadata; anything else is OFFER_INVALID. */
function checkMetadata(session: IssuerSession, origin: string, supportedVcts: readonly string[]): { configurationId: string; vct: string; display: DisplayEntry[] } {
  const { offer, credentialIssuer: ci, authorizationServers } = session;
  const grant = isObject(offer['grants']) ? offer['grants'][PRE_AUTHORIZED_GRANT] : undefined;
  const ids = strings(offer['credential_configuration_ids']);
  if (!isObject(grant) || typeof grant['pre-authorized_code'] !== 'string' || ids.length !== 1 || ids.length !== (offer['credential_configuration_ids'] as unknown[]).length) {
    throw new Fail(C.OFFER_INVALID);
  }
  if (session.version !== 'V1' || ci['credential_issuer'] !== offer['credential_issuer']) throw new Fail(C.OFFER_INVALID);
  sameOrigin(ci['credential_endpoint'], origin);
  if (ci['nonce_endpoint'] === undefined) throw new Fail(C.OFFER_INVALID);
  sameOrigin(ci['nonce_endpoint'], origin);
  for (const as of strings(ci['authorization_servers'])) sameOrigin(as, origin);
  if (authorizationServers.length === 0) throw new Fail(C.OFFER_INVALID);
  for (const as of authorizationServers) {
    sameOrigin(as['issuer'], origin);
    sameOrigin(as['token_endpoint'], origin);
  }
  // Response encryption (ADR-0010 point 9) and, per OpenID4VCI 1.0, request encryption.
  const req = ci['credential_request_encryption'];
  const res = ci['credential_response_encryption'];
  const keys = isObject(req) && isObject(req['jwks']) && Array.isArray(req['jwks']['keys']) ? (req['jwks']['keys'] as unknown[]) : [];
  if (!keys.some((k) => isObject(k) && k['alg'] === 'ECDH-ES' && (k['use'] === undefined || k['use'] === 'enc')) || !isObject(req) || !strings(req['enc_values_supported']).some((e) => e === 'A256GCM' || e === 'A128GCM')) {
    throw new Fail(C.OFFER_INVALID);
  }
  if (!isObject(res) || !strings(res['alg_values_supported']).includes('ECDH-ES') || !strings(res['enc_values_supported']).includes('A256GCM')) throw new Fail(C.OFFER_INVALID);
  const configurationId = ids[0]!;
  const supported = isObject(ci['credential_configurations_supported']) ? ci['credential_configurations_supported'][configurationId] : undefined;
  if (!isObject(supported) || supported['format'] !== 'dc+sd-jwt' || typeof supported['vct'] !== 'string' || !supportedVcts.includes(supported['vct'])) throw new Fail(C.OFFER_INVALID);
  const jwtProof = isObject(supported['proof_types_supported']) ? supported['proof_types_supported']['jwt'] : undefined;
  if (!isObject(jwtProof) || !strings(jwtProof['proof_signing_alg_values_supported']).includes('ES256')) throw new Fail(C.OFFER_INVALID);
  const binding = supported['cryptographic_binding_methods_supported'];
  if (binding !== undefined && !strings(binding).includes('jwk')) throw new Fail(C.OFFER_INVALID);
  const meta = supported['credential_metadata'];
  return { configurationId, vct: supported['vct'], display: displayOf(isObject(meta) ? meta['display'] : supported['display']) };
}

function failure(e: unknown): WalletFailure {
  if (e instanceof Fail) return { ok: false, code: e.code, ...(e.checks ? { checks: e.checks } : {}) };
  return { ok: false, code: failureOf(e).code };
}

/** Runs a library call; its failure ends the operation with the code failureOf gives. */
async function library<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (e) {
    throw new Fail(failureOf(e).code);
  }
}
async function storage<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch {
    throw new Fail(C.STORAGE_ERROR);
  }
}

export function createIssuance(ctx: WalletContext) {
  /** Network access of one offer: its origin only. */
  const depsFor = (origin: string): LibraryDeps => ({
    fetch: guardFetch(ctx.fetch, { allow: (_url, o) => o === origin, maxBytes: PROTOCOL_MAX_BYTES, timeoutMs: PROTOCOL_TIMEOUT_MS }),
    hasher: ctx.hasher,
    random: ctx.random,
  });

  /** After invalid_grant: the offer still served means the PIN was wrong; gone means expired, used or destroyed. */
  async function wrongPinOrExpired(state: OfferState, fetch: HttpFetch): Promise<WalletFailure> {
    try {
      const r = await fetch(state.offerUri, { method: 'GET' });
      return { ok: false, code: r.status === 200 ? C.TX_CODE_WRONG : C.OFFER_EXPIRED };
    } catch (e) {
      return failure(e);
    }
  }

  async function resolve(qrText: string): Promise<{ ok: true; offer: ResolvedOffer } | WalletFailure> {
    try {
      const offerUri = offerUriOf(qrText);
      const origin = httpsOrigin(offerUri)!;
      const deps = depsFor(origin);
      let offer: Record<string, unknown>;
      try {
        offer = await resolveOffer(qrText, deps);
      } catch (e) {
        const f = failureOf(e);
        throw new Fail(f.httpStatus === 404 ? C.OFFER_EXPIRED : f.code);
      }
      sameOrigin(offer['credential_issuer'], origin);
      const session = await library(() => resolveMetadata(offer, deps));
      const { configurationId, vct, display } = checkMetadata(session, origin, ctx.supportedVcts);
      const grant = (offer['grants'] as Record<string, Record<string, unknown>>)[PRE_AUTHORIZED_GRANT]!;
      const tx = grant['tx_code'];
      const resolved: ResolvedOffer = {
        issuerUri: offer['credential_issuer'] as string,
        issuerDisplay: displayOf(session.credentialIssuer['display']),
        configuration: { id: configurationId, vct, display },
        txCode: isObject(tx)
          ? {
              length: typeof tx['length'] === 'number' ? tx['length'] : null,
              inputMode: tx['input_mode'] === 'text' ? 'text' : 'numeric',
              description: typeof tx['description'] === 'string' ? tx['description'] : null,
            }
          : null,
      };
      offers.set(resolved, { issuerUri: resolved.issuerUri, offerUri, origin, session, configurationId, vct });
      return { ok: true, offer: resolved };
    } catch (e) {
      return failure(e);
    }
  }

  async function accept(offer: ResolvedOffer, input: { txCode?: string } = {}): Promise<AcceptResult> {
    const state = offers.get(offer);
    if (!state) throw new TypeError('offer must come from wallet.offers.resolve');
    const deps = depsFor(state.origin);
    let accessToken: string;
    let nonce: string;
    try {
      accessToken = await requestAccessToken(state.session, input.txCode, deps);
    } catch (e) {
      const f = failureOf(e);
      return f.oauthError === 'invalid_grant' ? wrongPinOrExpired(state, deps.fetch) : { ok: false, code: f.code };
    }
    try {
      nonce = await library(() => requestNonce(state.session, deps));
    } catch (e) {
      return failure(e);
    }
    // One new key per credential (ADR-0009 point 2), created only once the PIN was accepted.
    let keyId: string;
    let publicJwk: EcPublicJwk;
    try {
      ({ keyId, publicJwk } = await storage(() => ctx.keyStore.create()));
    } catch (e) {
      return failure(e);
    }
    let responseSecret: Uint8Array | undefined;
    try {
      responseSecret = generateSecretKey(ctx.random);
      const signer = await storage(() => ctx.keyStore.signer(keyId));
      const proof = await library(() => createProof(state.session, { configurationId: state.configurationId, nonce, signer, now: ctx.clock.now() }, deps));
      const responseKey = { secretKey: responseSecret, publicJwk: uncompressedPointToJwk(P256.getPublicKey(responseSecret, false)) };
      const credentials = await library(() => requestCredential(state.session, { configurationId: state.configurationId, accessToken, proof, responseKey }, deps));
      if (!Array.isArray(credentials) || credentials.length !== 1 || !isObject(credentials[0]) || typeof credentials[0]['credential'] !== 'string') throw new Fail(C.ISSUER_ERROR);
      const compact = credentials[0]['credential'];

      // Exactly what the wallet will rely on when it presents the credential (ADR-0007).
      const result = await verifyStoredCredential(compact, {
        verifier: ctx.verifier, hasher: ctx.hasher, chainValidator: ctx.chainValidator, trustRegistry: ctx.trustRegistry,
        statusChecker: ctx.statusChecker, supportedVcts: ctx.supportedVcts, now: ctx.clock.now(),
      });
      const credential = result.credential;
      if (!result.ok || !credential?.claims || !credential.issuer) throw new Fail(C.CREDENTIAL_INVALID, result.checks);
      if (credential.iss !== state.issuerUri) throw new Fail(C.ISSUER_MISMATCH);
      if (credential.vct !== state.vct) throw new Fail(C.ISSUER_ERROR);
      if (!credential.cnfJwk || (await jwkThumbprint(credential.cnfJwk, ctx.hasher)) !== (await jwkThumbprint(publicJwk, ctx.hasher))) throw new Fail(C.CNF_MISMATCH);
      const claims = credential.claims;
      const required = REQUIRED_CLAIMS[credential.vct];
      if (!required || !required.every((n) => typeof claims[n] === 'string' && claims[n] !== '')) throw new Fail(C.CLAIMS_INCOMPLETE);

      const credentialId = await storage(() => ctx.vault.save({ compact, vct: credential.vct, issuer: credential.iss, keyId }));
      try {
        await ctx.vault.setStatus(credentialId, 'valid', ctx.clock.now());
      } catch {
        await ctx.vault.remove(credentialId).catch(() => {});
        throw new Fail(C.STORAGE_ERROR);
      }
      return { ok: true, credentialId, vct: credential.vct, issuerName: credential.issuer.ten };
    } catch (e) {
      await ctx.keyStore.delete(keyId).catch(() => {});
      return failure(e);
    } finally {
      responseSecret?.fill(0);
    }
  }

  return { resolve, accept };
}

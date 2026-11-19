// The wallet's side of OpenID4VCI 1.0, pre-authorized code (ADR-0010, docs/architecture.md section 8).
// resolve: QR text -> offer by reference -> metadata, all on the QR's origin; nothing is created.
// accept: token (PIN) -> c_nonce -> new wallet key -> proof -> encrypted credential request ->
// the credential is verified as the wallet would verify it to present it -> vault. Any failure after
// the key was created deletes the key again, and nothing is saved.
import { decodeCredentialUnverified, DIPLOMA_CLAIMS, jwkThumbprint, VCT, verifyStoredCredential, type Check, type EcPublicJwk, type HttpFetch } from '@identra/sdk-core';
import { generateSecretKey, P256, uncompressedPointToJwk } from '../crypto/noble.js';
import { Fail, keyFailureCode, WalletErrorCodes as C, type WalletFailure } from './errors.js';
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
  /** The origin every request of this offer went to; the only fact about the issuer verified at this point. */
  issuerOrigin: string;
  issuerDisplay: DisplayEntry[];
  configuration: { id: string; vct: string; display: DisplayEntry[] };
  txCode: { length: number | null; inputMode: 'numeric' | 'text'; description: string | null } | null;
  /**
   * True once the token step succeeded for this offer (the wallet holds or held an access token):
   * the PIN was accepted and is not needed again. False before; then a resume needs the PIN.
   */
  readonly codeRedeemed: boolean;
}

/**
 * `status: 'unknown'` when the credential itself verified but the trust list or its status list
 * could not be read at receipt; refreshStatus settles it later. `issuerName` is then null when the
 * trust list was the one missing.
 */
export type AcceptResult =
  | { ok: true; credentialId: string; vct: string; issuerName: string | null; status: 'valid' | 'unknown' }
  | AcceptFailure;

/**
 * `retryable`: true when `accept` on the SAME resolved offer can still complete (the PIN was wrong
 * and the offer still exists, the PIN was missing, a token request got no answer, the wallet still
 * holds an unexpired, unused access token, or a received credential waits to be stored); false when
 * a new offer is needed.
 * `codeRedeemed`: the offer's `codeRedeemed` at the end of this call. True: a retry needs no PIN.
 * False: a retry must send the PIN again (TX_CODE_REQUIRED without it). After a token request with
 * no answer (NETWORK_ERROR, codeRedeemed false) the wallet cannot know whether the issuer redeemed
 * the code: the next accept with the PIN completes, or is OFFER_EXPIRED when the lost request had
 * consumed it.
 */
export type AcceptFailure = WalletFailure & { retryable: boolean; codeRedeemed: boolean };
/** A failure of one attempt, before `codeRedeemed` is added from the offer state. */
type AttemptFailure = WalletFailure & { retryable: boolean };
type AttemptResult = Exclude<AcceptResult, AcceptFailure> | AttemptFailure;

/** A token without `expires_in` is trusted for this long. */
const DEFAULT_TOKEN_SECONDS = 60;
/** A token this close to its expiry is not used any more. */
const TOKEN_MARGIN_MS = 5_000;

interface Received { compact: string; keyId: string; vct: string; iss: string; issuerName: string | null; listsDown: boolean }

interface OfferState {
  issuerUri: string;
  offerUri: string;
  origin: string;
  session: IssuerSession;
  configurationId: string;
  vct: string;
  /** The pre-authorized code was redeemed: it is never sent again. */
  codeUsed: boolean;
  /** The offer's grant carries `tx_code`: the token request needs a PIN. */
  txCodeRequired: boolean;
  /** The access token, in memory only, until the issuer answered a credential request or it expired. */
  token: { value: string; expiresAt: number } | null;
  /** A c_nonce not yet sent in a proof. */
  nonce: string | null;
  /** A received and verified credential whose storing failed; its wallet key is kept for it. */
  received: Received | null;
  /** Calls of accept on one offer run one after the other. */
  queue: Promise<unknown>;
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

/**
 * True when every failing check is only a list that could not be read: issuer_trust with
 * TRUST_LIST_UNAVAILABLE (and status SKIPPED because of it), or status with STATUS_UNAVAILABLE.
 * Chain, signature, validity, type and disclosures must all have passed.
 */
export function onlyListsUnavailable(checks: Check[]): boolean {
  const trustListDown = checks.some((c) => c.id === 'issuer_trust' && c.code === 'TRUST_LIST_UNAVAILABLE');
  return checks.every(
    (c) => c.ok || (c.id === 'issuer_trust' && c.code === 'TRUST_LIST_UNAVAILABLE') || (c.id === 'status' && (c.code === 'STATUS_UNAVAILABLE' || (c.code === 'SKIPPED' && trustListDown))),
  );
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
async function keyStoreCall<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (e) {
    throw new Fail(keyFailureCode(e));
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
  async function wrongPinOrExpired(state: OfferState, fetch: HttpFetch): Promise<AttemptFailure> {
    try {
      const r = await fetch(state.offerUri, { method: 'GET', maxBytes: 65_536 });
      return r.status === 200 ? { ok: false, code: C.TX_CODE_WRONG, retryable: true } : { ok: false, code: C.OFFER_EXPIRED, retryable: false };
    } catch (e) {
      return { ...failure(e), retryable: true };
    }
  }

  const tokenUsable = (state: OfferState) => state.token !== null && ctx.clock.now().getTime() < state.token.expiresAt - TOKEN_MARGIN_MS;
  const fails = (e: unknown, retryable: boolean): AttemptFailure => ({ ...failure(e), retryable });

  /** Stores a received credential. A failure keeps it (and its key) in the offer state for the next accept. */
  async function storeReceived(state: OfferState, r: Received): Promise<AttemptResult> {
    let savedId: string | undefined;
    try {
      savedId = await storage(() => ctx.vault.save({ compact: r.compact, vct: r.vct, issuer: r.iss, keyId: r.keyId }));
      const id = savedId;
      await storage(() => ctx.vault.setStatus(id, r.listsDown ? 'unavailable' : 'valid', ctx.clock.now()));
      state.received = null;
      return { ok: true, credentialId: id, vct: r.vct, issuerName: r.issuerName, status: r.listsDown ? 'unknown' : 'valid' };
    } catch (e) {
      if (savedId !== undefined) {
        const id = savedId;
        await ctx.vault.remove(id).catch(() => {});
        // A row that cannot be removed keeps its key; it is not saved a second time.
        if (!(await ctx.vault.getMeta(id).then((m) => m === null, () => false))) {
          state.received = null;
          return fails(e, false);
        }
      }
      state.received = r;
      return fails(e, true);
    }
  }

  /**
   * Forgets a resolved offer: a held access token, and a received credential that could not be
   * stored together with its wallet key. Call it when the user abandons an offer after a failure.
   */
  async function discard(offer: ResolvedOffer): Promise<void> {
    const state = offers.get(offer);
    if (!state) return;
    offers.delete(offer);
    await state.queue.catch(() => {});
    if (state.received) await ctx.keyStore.delete(state.received.keyId).catch(() => {});
    state.received = null;
    state.token = null;
  }

  async function resolve(qrText: string): Promise<{ ok: true; offer: ResolvedOffer } | WalletFailure> {
    try {
      const offerUri = offerUriOf(qrText);
      const origin = httpsOrigin(offerUri)!;
      if (ctx.allowedOrigins && !ctx.allowedOrigins.includes(origin)) throw new Fail(C.URL_NOT_ALLOWED);
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
      const state: OfferState = {
        issuerUri: offer['credential_issuer'] as string, offerUri, origin, session, configurationId, vct, codeUsed: false, txCodeRequired: isObject(tx),
        token: null, nonce: null, received: null, queue: Promise.resolve(),
      };
      const resolved: ResolvedOffer = {
        issuerUri: offer['credential_issuer'] as string,
        issuerOrigin: origin,
        issuerDisplay: displayOf(session.credentialIssuer['display']),
        configuration: { id: configurationId, vct, display },
        txCode: isObject(tx)
          ? {
              length: typeof tx['length'] === 'number' ? tx['length'] : null,
              inputMode: tx['input_mode'] === 'text' ? 'text' : 'numeric',
              description: typeof tx['description'] === 'string' ? tx['description'] : null,
            }
          : null,
        get codeRedeemed() {
          return state.codeUsed;
        },
      };
      offers.set(resolved, state);
      return { ok: true, offer: resolved };
    } catch (e) {
      return failure(e);
    }
  }

  /**
   * Token (PIN) -> c_nonce -> new wallet key -> proof -> credential request -> verify -> store.
   * Resumable: after the PIN was accepted, the access token (and an unused c_nonce) stay in the
   * offer's memory, so a later accept on the SAME resolved offer continues from the c_nonce with a
   * new key attempt and ignores `txCode`. Before that (`offer.codeRedeemed` false) an offer with a
   * PIN needs `txCode`: without one it is TX_CODE_REQUIRED and nothing is sent. The token is
   * dropped once the issuer answered a credential request (success or a definitive error) and when
   * it expires; it is never stored or logged.
   */
  async function accept(offer: ResolvedOffer, input: { txCode?: string } = {}): Promise<AcceptResult> {
    const state = offers.get(offer);
    if (!state) throw new TypeError('offer must come from wallet.offers.resolve');
    const run = state.queue.then(() => attempt(state, input.txCode)).then((r): AcceptResult => (r.ok ? r : { ...r, codeRedeemed: state.codeUsed }));
    state.queue = run.catch(() => {});
    return run;
  }

  async function attempt(state: OfferState, txCode: string | undefined): Promise<AttemptResult> {
    if (state.received) return storeReceived(state, state.received);
    const deps = depsFor(state.origin);
    if (!tokenUsable(state)) {
      state.token = null;
      if (state.codeUsed) return { ok: false, code: C.OFFER_EXPIRED, retryable: false };
      // An empty PIN would cost one of the issuer's five attempts: refused here, nothing is sent.
      if (state.txCodeRequired && !txCode) return { ok: false, code: C.TX_CODE_REQUIRED, retryable: true };
      try {
        const t = await requestAccessToken(state.session, txCode, deps);
        state.codeUsed = true;
        state.token = { value: t.accessToken, expiresAt: ctx.clock.now().getTime() + (t.expiresIn ?? DEFAULT_TOKEN_SECONDS) * 1000 };
      } catch (e) {
        const f = failureOf(e);
        // Unanswered: the code may still be unredeemed. Anything else from the issuer is final.
        return f.oauthError === 'invalid_grant' ? wrongPinOrExpired(state, deps.fetch) : { ok: false, code: f.code, retryable: f.code === 'NETWORK_ERROR' };
      }
    }
    const accessToken = state.token!.value;
    try {
      state.nonce ??= await library(() => requestNonce(state.session, deps));
    } catch (e) {
      return fails(e, tokenUsable(state));
    }
    // One new key per credential (ADR-0009 point 2), created only once the PIN was accepted.
    let keyId: string;
    let publicJwk: EcPublicJwk;
    try {
      ({ keyId, publicJwk } = await keyStoreCall(() => ctx.keyStore.create()));
    } catch (e) {
      return fails(e, tokenUsable(state));
    }
    let responseSecret: Uint8Array | undefined;
    try {
      responseSecret = generateSecretKey(ctx.random);
      const signer = await keyStoreCall(() => ctx.keyStore.signer(keyId));
      const proof = await library(() => createProof(state.session, { configurationId: state.configurationId, nonce: state.nonce!, signer, now: ctx.clock.now() }, deps));
      const responseKey = { secretKey: responseSecret, publicJwk: uncompressedPointToJwk(P256.getPublicKey(responseSecret, false)) };
      state.nonce = null; // spent once it leaves in a proof
      let credentials: unknown;
      try {
        credentials = await requestCredential(state.session, { configurationId: state.configurationId, accessToken, proof, responseKey }, deps);
        state.token = null;
      } catch (e) {
        // No answer at all: the same token may be tried again. Any answer from the issuer is definitive.
        if (failureOf(e).code !== 'NETWORK_ERROR') state.token = null;
        throw new Fail(failureOf(e).code);
      }
      if (!Array.isArray(credentials) || credentials.length !== 1 || !isObject(credentials[0]) || typeof credentials[0]['credential'] !== 'string') throw new Fail(C.ISSUER_ERROR);
      const compact = credentials[0]['credential'];

      // Exactly what the wallet will rely on when it presents the credential (ADR-0007).
      const result = await verifyStoredCredential(compact, {
        verifier: ctx.verifier, hasher: ctx.hasher, chainValidator: ctx.chainValidator, trustRegistry: ctx.trustRegistry,
        statusChecker: ctx.statusChecker, supportedVcts: ctx.supportedVcts, now: ctx.clock.now(),
      });
      const credential = result.credential;
      // A credential that verified except for a list that could not be read is kept as `unknown`.
      const listsDown = !result.ok && credential !== undefined && onlyListsUnavailable(result.checks);
      if (!credential || (!result.ok && !listsDown)) throw new Fail(C.CREDENTIAL_INVALID, result.checks);
      if (credential.iss !== state.issuerUri) throw new Fail(C.ISSUER_MISMATCH);
      if (credential.vct !== state.vct) throw new Fail(C.ISSUER_ERROR);
      if (!credential.cnfJwk || (await jwkThumbprint(credential.cnfJwk, ctx.hasher)) !== (await jwkThumbprint(publicJwk, ctx.hasher))) throw new Fail(C.CNF_MISMATCH);
      // Every claim of the type must be its own disclosure and absent from the plain payload, or the
      // wallet could never withhold it (holder_binding passed, so the disclosures match the digests).
      const { payload, disclosures } = decodeCredentialUnverified(compact);
      const required = REQUIRED_CLAIMS[credential.vct];
      const disclosedOnce = (n: string) => disclosures.filter((d) => d.name === n && typeof d.value === 'string' && d.value !== '').length === 1;
      if (!required || !required.every((n) => !Object.hasOwn(payload, n) && disclosedOnce(n))) throw new Fail(C.CLAIMS_INCOMPLETE);

      return storeReceived(state, { compact, keyId, vct: credential.vct, iss: credential.iss, issuerName: credential.issuer?.ten ?? null, listsDown });
    } catch (e) {
      await ctx.keyStore.delete(keyId).catch(() => {});
      return fails(e, tokenUsable(state));
    } finally {
      responseSecret?.fill(0);
    }
  }

  return { resolve, accept, discard };
}

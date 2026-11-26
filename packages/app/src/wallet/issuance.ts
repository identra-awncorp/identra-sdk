// The wallet's side of OpenID4VCI 1.0, pre-authorized code (ADR-0010, docs/architecture.md section 8).
// resolve: QR text -> offer by reference -> metadata, all on the QR's origin; nothing is created.
// accept: token (PIN) -> c_nonce -> new wallet key -> proof -> encrypted credential request ->
// the credential is verified as the wallet would verify it to present it -> vault. Any failure after
// the key was created deletes the key again, and nothing is saved; except a credential whose issuer
// DID could not be resolved (ADR-0020), kept in memory with its key to be verified again by the next accept.
import {
  decodeCredentialUnverified, DIPLOMA_CLAIMS, isCertNetDid, isDidStatusListUri, isStatusListUri, jwkThumbprint, STATUS_LIST_ENTRIES, VCT, verifyStoredCredential,
  type CredentialVerificationResult, type EcPublicJwk, type HttpFetch,
} from '@identra/sdk-core';
import { generateSecretKey, P256, uncompressedPointToJwk } from '../crypto/noble.js';
import { Fail, keyFailureCode, WalletErrorCodes as C, type WalletFailure } from './errors.js';
import { guardFetch, httpsOrigin, PROTOCOL_MAX_BYTES, PROTOCOL_TIMEOUT_MS } from './fetch.js';
import { createProof, failureOf, requestAccessToken, requestCredential, requestNonce, resolveMetadata, resolveOffer, type IssuerSession, type LibraryDeps } from './library.js';
import { verifyOptionsOf, type WalletContext } from './context.js';

/** Claims a credential type must disclose to the holder; only holder-bound types can be received. */
export const REQUIRED_CLAIMS: Readonly<Record<string, readonly string[]>> = Object.freeze({ [VCT.diploma]: DIPLOMA_CLAIMS });

/**
 * The longest DID the wallet accepts from an issuer (`identra_issuer_did`; a credential's `iss` must
 * then be that DID). CertNet states no maximum for the method-specific id; `did:certnet:testnet:`
 * is 20 characters and the ids seen are far shorter than the remaining 108.
 */
export const MAX_DID_LENGTH = 128;
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
  /**
   * The DID the issuer's metadata declares (`identra_issuer_did`, ADR-0020): NOT verified yet (no
   * gateway request is made at resolve); accept checks that the credential is signed by it. Null:
   * an X.509 issuer. With a DID, show the DID rather than the self-declared `issuerDisplay` name.
   */
  issuerDid: string | null;
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
 * trust list was the one missing. On the DID path (ADR-0020) `issuerDid` is the issuer's DID and
 * `issuerName` is always null; `issuerDid` is absent on the X.509 path.
 */
export type AcceptResult =
  | { ok: true; credentialId: string; vct: string; issuerName: string | null; issuerDid?: string; status: 'valid' | 'unknown' }
  | AcceptFailure;

/**
 * `retryable`: true when `accept` on the SAME resolved offer can still complete (the PIN was wrong
 * and the offer still exists, the PIN was missing, a token request got no answer, the wallet still
 * holds an unexpired, unused access token, or a received credential waits to be stored or, its
 * issuer DID not resolved yet, to be verified); false when a new offer is needed.
 * A received credential whose issuer DID could not be resolved (the CertNet gateway gave no usable
 * answer) is NETWORK_ERROR with `checks`: it was not stored, and the next accept verifies it again.
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

interface Received { compact: string; keyId: string; vct: string; issuerDid: string | null; issuerName: string | null; listsDown: boolean }
/** A credential the issuer sent, not verified yet, with the wallet key it is bound to. */
interface Unverified { compact: string; keyId: string; publicJwk: EcPublicJwk }

interface OfferState {
  issuerUri: string;
  /** `identra_issuer_did` of the metadata (ADR-0020 decision 7): the credential must be of the DID path with this `iss`; null: X.509 with `iss` = issuerUri. */
  issuerDid: string | null;
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
  /** A received credential whose issuer DID could not be resolved; its wallet key is kept for it. */
  unverified: Unverified | null;
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
function checkMetadata(session: IssuerSession, origin: string, supportedVcts: readonly string[]): { configurationId: string; vct: string; display: DisplayEntry[]; issuerDid: string | null } {
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
  const issuerDid = ci['identra_issuer_did'];
  if (issuerDid !== undefined && (!isCertNetDid(issuerDid) || issuerDid.length > MAX_DID_LENGTH)) throw new Fail(C.OFFER_INVALID);
  return { configurationId, vct: supported['vct'], display: displayOf(isObject(meta) ? meta['display'] : supported['display']), issuerDid: issuerDid ?? null };
}

/**
 * True when every failing check is only a list that could not be read: issuer_trust with
 * TRUST_LIST_UNAVAILABLE (and status SKIPPED because of it), or status with STATUS_UNAVAILABLE.
 * Chain (or DID resolution), signature, validity, type and disclosures must all have passed, and the
 * credential must carry a well-formed status reference (`<iss>/status/<n>`, on the DID path
 * `https://<host>/<path>/status/<n>`; idx inside the list): a missing or malformed one is not a list
 * that was unreachable, and trying again would never settle it. On the DID path the trust list is
 * the CertNet trust registry.
 */
export function onlyListsUnavailable(result: Pick<CredentialVerificationResult, 'checks' | 'credential'>): boolean {
  const c = result.credential;
  const uriOk = c?.trustPath === 'did' ? isDidStatusListUri(c.status?.uri) : !!c?.status && isStatusListUri(c.status.uri, c.iss);
  if (!c?.status || !uriOk || c.status.idx >= STATUS_LIST_ENTRIES) return false;
  const { checks } = result;
  const trustListDown = checks.some((c) => c.id === 'issuer_trust' && c.code === 'TRUST_LIST_UNAVAILABLE');
  return checks.every(
    (c) => c.ok || (c.id === 'issuer_trust' && c.code === 'TRUST_LIST_UNAVAILABLE') || (c.id === 'status' && (c.code === 'STATUS_UNAVAILABLE' || (c.code === 'SKIPPED' && trustListDown))),
  );
}

/**
 * The issuer DID could not be resolved because the gateway gave no usable answer: the signature was
 * never checked, so nothing is known about the credential yet (neither valid nor forged).
 */
export const didUnresolved = (result: Pick<CredentialVerificationResult, 'checks'>): boolean =>
  result.checks.some((c) => c.id === 'did_resolution' && c.code === 'DID_RESOLUTION_UNAVAILABLE');

/**
 * The receipt rule (ADR-0020 decision 7): the issuer declared a DID -> the DID path with exactly that
 * `iss`, and its status list `<credential_issuer>/status/<n>` (as `<iss>/status/<n>` binds it on the
 * X.509 path); no DID declared -> the X.509 path with `iss` = the credential issuer URL. Applied to
 * the unverified payload before verification (`trustPath` not known yet), so nothing is fetched for
 * a credential that would be refused anyway, and to the verified credential afterwards.
 */
export function matchesDeclaredIssuer(
  c: { trustPath?: 'x509' | 'did'; iss: unknown; statusUri: unknown },
  declared: { issuerUri: string; issuerDid: string | null },
): boolean {
  if (declared.issuerDid !== null) return (c.trustPath ?? 'did') === 'did' && c.iss === declared.issuerDid && isStatusListUri(c.statusUri, declared.issuerUri);
  return (c.trustPath ?? 'x509') === 'x509' && c.iss === declared.issuerUri;
}

/** No answer, or the issuer's 503 (a temporary failure before it spent anything): the same request may be sent again. */
const retryLater = (f: { code: string; httpStatus: number | null }) => f.code === 'NETWORK_ERROR' || f.httpStatus === 503;

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
      // The row's issuer is the credential issuer URL on both paths (re-issuance, catalogue); the DID beside it.
      savedId = await storage(() => ctx.vault.save({ compact: r.compact, vct: r.vct, issuer: state.issuerUri, ...(r.issuerDid ? { issuerDid: r.issuerDid } : {}), keyId: r.keyId }));
      const id = savedId;
      await storage(() => ctx.vault.setStatus(id, r.listsDown ? 'unavailable' : 'valid', ctx.clock.now()));
      state.received = null;
      return { ok: true, credentialId: id, vct: r.vct, issuerName: r.issuerName, ...(r.issuerDid ? { issuerDid: r.issuerDid } : {}), status: r.listsDown ? 'unknown' : 'valid' };
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
    if (state.unverified) await ctx.keyStore.delete(state.unverified.keyId).catch(() => {});
    state.received = null;
    state.unverified = null;
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
      const { configurationId, vct, display, issuerDid } = checkMetadata(session, origin, ctx.supportedVcts);
      // A DID issuer's credential could never be accepted without the DID path: refused before the PIN is spent.
      if (issuerDid !== null && (!ctx.dpki || (ctx.didNetwork !== null && !isCertNetDid(issuerDid, ctx.didNetwork)))) throw new Fail(C.TRUST_PATH_UNSUPPORTED);
      const grant = (offer['grants'] as Record<string, Record<string, unknown>>)[PRE_AUTHORIZED_GRANT]!;
      const tx = grant['tx_code'];
      const state: OfferState = {
        issuerUri: offer['credential_issuer'] as string, issuerDid, offerUri, origin, session, configurationId, vct, codeUsed: false, txCodeRequired: isObject(tx),
        token: null, nonce: null, received: null, unverified: null, queue: Promise.resolve(),
      };
      const resolved: ResolvedOffer = {
        issuerUri: offer['credential_issuer'] as string,
        issuerOrigin: origin,
        issuerDid,
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
    if (state.unverified) return receive(state, state.unverified);
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
        // Unanswered, or 503 (the issuer spent nothing): the code may still be unredeemed. Anything else is final.
        return f.oauthError === 'invalid_grant' ? wrongPinOrExpired(state, deps.fetch) : { ok: false, code: f.code, retryable: retryLater(f) };
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
    // Once the credential is received, receive() owns the key (and deletes it on a failure).
    let keyHandedOver = false;
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
        // No answer at all, or 503 (the issuer did not spend the token): the same token may be tried
        // again. Any other answer from the issuer is definitive.
        if (!retryLater(failureOf(e))) state.token = null;
        throw new Fail(failureOf(e).code);
      }
      if (!Array.isArray(credentials) || credentials.length !== 1 || !isObject(credentials[0]) || typeof credentials[0]['credential'] !== 'string') throw new Fail(C.ISSUER_ERROR);
      keyHandedOver = true;
      return await receive(state, { compact: credentials[0]['credential'], keyId, publicJwk });
    } catch (e) {
      if (!keyHandedOver) await ctx.keyStore.delete(keyId).catch(() => {});
      return fails(e, tokenUsable(state));
    } finally {
      responseSecret?.fill(0);
    }
  }

  /**
   * Verifies a received credential, then stores it. Never throws. Its wallet key is deleted on a
   * failure, except when the issuer DID could not be resolved: the credential is then kept in memory
   * (not stored) for the next accept to verify again.
   */
  async function receive(state: OfferState, u: Unverified): Promise<AttemptResult> {
    state.unverified = null;
    try {
      const { compact, keyId, publicJwk } = u;
      let claimed: Record<string, unknown> | null = null;
      try {
        claimed = decodeCredentialUnverified(compact).payload;
      } catch {
        // not decodable: verification below says why
      }
      const claimedStatus = claimed && isObject(claimed['status']) && isObject(claimed['status']['status_list']) ? claimed['status']['status_list']['uri'] : undefined;
      if (claimed && !matchesDeclaredIssuer({ iss: claimed['iss'], statusUri: claimedStatus }, state)) throw new Fail(C.ISSUER_MISMATCH);
      // Exactly what the wallet will rely on when it presents the credential (ADR-0007).
      const result = await verifyStoredCredential(compact, verifyOptionsOf(ctx));
      if (didUnresolved(result)) {
        // Only for the DID this issuer declared; anything else will not become acceptable by waiting.
        if (state.issuerDid === null || decodeCredentialUnverified(compact).payload['iss'] !== state.issuerDid) throw new Fail(C.ISSUER_MISMATCH);
        state.unverified = u;
        return { ok: false, code: C.NETWORK_ERROR, checks: result.checks, retryable: true };
      }
      const credential = result.credential;
      // A credential that verified except for a list that could not be read is kept as `unknown`.
      const listsDown = !result.ok && onlyListsUnavailable(result);
      if (!credential || (!result.ok && !listsDown)) throw new Fail(C.CREDENTIAL_INVALID, result.checks);
      // The receipt rule again, on what verification established: this is the check that counts.
      if (!matchesDeclaredIssuer({ trustPath: credential.trustPath, iss: credential.iss, statusUri: credential.status?.uri }, state)) throw new Fail(C.ISSUER_MISMATCH);
      if (credential.vct !== state.vct) throw new Fail(C.ISSUER_ERROR);
      if (!credential.cnfJwk || (await jwkThumbprint(credential.cnfJwk, ctx.hasher)) !== (await jwkThumbprint(publicJwk, ctx.hasher))) throw new Fail(C.CNF_MISMATCH);
      // Every claim of the type must be its own disclosure and absent from the plain payload, or the
      // wallet could never withhold it (holder_binding passed, so the disclosures match the digests).
      const { payload, disclosures } = decodeCredentialUnverified(compact);
      const required = REQUIRED_CLAIMS[credential.vct];
      const disclosedOnce = (n: string) => disclosures.filter((d) => d.name === n && typeof d.value === 'string' && d.value !== '').length === 1;
      if (!required || !required.every((n) => !Object.hasOwn(payload, n) && disclosedOnce(n))) throw new Fail(C.CLAIMS_INCOMPLETE);

      const issuerDid = credential.trustPath === 'did' ? credential.issuerDid : null;
      return storeReceived(state, { compact, keyId, vct: credential.vct, issuerDid, issuerName: credential.issuer?.ten ?? null, listsDown });
    } catch (e) {
      await ctx.keyStore.delete(u.keyId).catch(() => {});
      return fails(e, tokenUsable(state));
    }
  }

  return { resolve, accept, discard };
}

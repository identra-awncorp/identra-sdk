// The wallet's side of OpenID4VP 1.0, cross-device, direct_post.jwt (ADR-0011, ADR-0015 sections 5
// and 6, ADR-0008 sections 4 and 5, docs/architecture.md section 9).
// resolve: QR -> request object (GET, the QR's origin only) -> our checks of the JWS, the
// certificate chain and the client_id -> trust lookup -> DCQL match against the vault. Nothing is
// signed and no key is touched. submit: presentation of exactly the chosen claim set, KB-JWT bound
// to client_id and nonce, encrypted to the session key, POSTed to response_uri. decline: local only.
import {
  base64UrlDecode, claimSetsNested, createPresentation, decodeCredentialUnverified, normalizeEcPublicJwk, UNSAFE_DISPLAY_TEXT, utf8Decode, utf8Encode,
  type EcPublicJwk, type ErrorCode,
} from '@identra/sdk-core';
import { encryptJwe, type JweEnc } from '../jwe.js';
import type { WalletContext } from './context.js';
import { issuerNameOf } from './credentials.js';
import { CredentialVaultError } from '../credential-vault.js';
import { Fail, keyFailureCode, vaultFailureCode, WalletErrorCodes as C, type WalletErrorCode, type WalletFailure } from './errors.js';
import { guardFetch, httpsOrigin, PROTOCOL_MAX_BYTES, PROTOCOL_TIMEOUT_MS, WalletFetchError } from './fetch.js';
import { failureOf, matchDcql, resolvePresentationRequest, type JarToCheck } from './library.js';

const QR_PREFIX = 'openid4vp://?';
const CLIENT_ID = /^x509_hash:[A-Za-z0-9_-]{43}$/;
const SKEW_SECONDS = 60;
const MAX_REQUEST_SECONDS = 600;
const SIOP_AUDIENCE = 'https://self-issued.me/v2';

export type VerifierIdentity = { trusted: true; ten: string; maToChuc: string } | { trusted: false };

export interface PresentationMatch {
  credentialId: string;
  vct: string;
  issuerName: string | null;
  /** The claim sets this credential can satisfy, in the verifier's order of preference. */
  claimSets: { index: number; claims: string[] }[];
}

export interface ResolvedPresentation {
  clientId: string;
  verifier: VerifierIdentity;
  /** VERIFIER_NOT_TRUSTED when the verifier is not in the trust list: show a red warning (ADR-0011 point 3). */
  warning?: typeof C.VERIFIER_NOT_TRUSTED;
  /** The trusted verifier's stated purpose (DCQL credential set `purpose`), sanitised; never for an untrusted verifier. */
  purpose?: string | { vi?: string; en?: string };
  matches: PresentationMatch[];
  expiresAt: string;
}

interface RequestState {
  origin: string;
  clientId: string;
  trusted: boolean;
  nonce: string;
  state: string | undefined;
  responseUri: string;
  encryptionJwk: EcPublicJwk & { kid?: string };
  enc: JweEnc;
  queryId: string;
  claimSets: string[][];
  expiresAt: number;
  offered: Map<string, number[]>;
}
const requests = new WeakMap<ResolvedPresentation, RequestState>();

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const fail = (code: WalletErrorCode): WalletFailure => ({ ok: false, code });

/** `client_id` and `request_uri` of a QR text that carries exactly those two parameters. */
function parseQr(qrText: unknown): { clientId: string; requestUri: string; origin: string } {
  if (typeof qrText !== 'string' || !qrText.startsWith(QR_PREFIX) || qrText.length > 2048) throw new Fail(C.REQUEST_INVALID);
  const params = new URLSearchParams(qrText.slice(QR_PREFIX.length));
  const names: string[] = [];
  params.forEach((_v, k) => names.push(k));
  const clientId = params.get('client_id');
  const requestUri = params.get('request_uri');
  // No request by value, no request_uri_method (GET only), no other client identifier prefix, nothing else.
  if (names.length !== 2 || clientId === null || requestUri === null || !CLIENT_ID.test(clientId)) throw new Fail(C.REQUEST_INVALID);
  const origin = httpsOrigin(requestUri);
  if (origin === null) throw new Fail(C.URL_NOT_ALLOWED);
  return { clientId, requestUri, origin };
}

const MAX_PURPOSE_LENGTH = 300;
const safeText = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= MAX_PURPOSE_LENGTH && !UNSAFE_DISPLAY_TEXT.test(v);

/**
 * The verifier's stated purpose (`credential_sets[0].purpose`) when it is a safe string or
 * `{ vi?, en? }` of safe strings (at most 300 characters, none of UNSAFE_DISPLAY_TEXT); anything
 * else is dropped, not an error.
 */
function purposeOf(q: Record<string, unknown>): string | { vi?: string; en?: string } | undefined {
  const raw = Array.isArray(q['credential_sets']) && isObject(q['credential_sets'][0]) ? q['credential_sets'][0]['purpose'] : undefined;
  if (safeText(raw)) return raw;
  if (!isObject(raw) || Object.keys(raw).some((k) => k !== 'vi' && k !== 'en') || Object.keys(raw).length === 0) return undefined;
  if (!Object.values(raw).every(safeText)) return undefined;
  return { ...(raw['vi'] !== undefined ? { vi: raw['vi'] as string } : {}), ...(raw['en'] !== undefined ? { en: raw['en'] as string } : {}) };
}

/** The one `credential_sets` form accepted: absent, or exactly one set with exactly one option naming `id` (it carries the purpose). */
function plainCredentialSets(q: Record<string, unknown>, id: string): boolean {
  const sets = q['credential_sets'];
  if (sets === undefined) return true;
  if (!Array.isArray(sets) || sets.length !== 1 || !isObject(sets[0])) return false;
  const { options, required, purpose, ...rest } = sets[0];
  void purpose;
  return Object.keys(rest).length === 0 && (required === undefined || required === true) && Array.isArray(options) && options.length === 1 &&
    Array.isArray(options[0]) && options[0].length === 1 && options[0][0] === id;
}

export function createPresentations(ctx: WalletContext) {
  const depsFor = (origin: string) => ({
    fetch: guardFetch(ctx.fetch, { allow: (_u: string, o: string) => o === origin, maxBytes: PROTOCOL_MAX_BYTES, timeoutMs: PROTOCOL_TIMEOUT_MS }),
    hasher: ctx.hasher,
    random: ctx.random,
  });

  /** Every rule on the request object (architecture section 9); the code of the first broken one, or the parts the wallet uses. */
  async function checkJar(jar: JarToCheck, qr: { clientId: string; origin: string }) {
    const now = ctx.clock.now();
    if (jar.alg !== 'ES256' || jar.header['alg'] !== 'ES256') throw new Fail(C.ALG_NOT_ALLOWED);
    if (jar.header['typ'] !== 'oauth-authz-req+jwt' || !Array.isArray(jar.x5c) || !jar.x5c.every((c) => typeof c === 'string')) throw new Fail(C.REQUEST_INVALID);
    const chain = await ctx.chainValidator.validate({ x5c: jar.x5c as string[], profile: 'request', now });
    if (!chain.ok || !chain.leaf?.publicJwk || !chain.fingerprint) throw new Fail((chain.code ?? C.CERT_CHAIN_UNTRUSTED) as WalletErrorCode);
    let signature: Uint8Array;
    try {
      signature = base64UrlDecode(jar.signature);
    } catch {
      throw new Fail(C.SIGNATURE_INVALID);
    }
    if (signature.length !== 64 || !(await ctx.verifier.verify(chain.leaf.publicJwk, utf8Encode(jar.signingInput), signature))) throw new Fail(C.SIGNATURE_INVALID);
    let p: Record<string, unknown>;
    try {
      p = JSON.parse(utf8Decode(base64UrlDecode(jar.signingInput.split('.')[1] ?? ''))) as Record<string, unknown>;
    } catch {
      throw new Fail(C.REQUEST_INVALID);
    }
    if (`x509_hash:${chain.fingerprint}` !== qr.clientId || p['client_id'] !== qr.clientId) throw new Fail(C.CLIENT_ID_MISMATCH);
    if (p['response_mode'] !== 'direct_post.jwt' || p['response_type'] !== 'vp_token' || p['aud'] !== SIOP_AUDIENCE) throw new Fail(C.REQUEST_INVALID);
    if (httpsOrigin(p['response_uri']) !== qr.origin) throw new Fail(C.URL_NOT_ALLOWED);
    if (typeof p['nonce'] !== 'string' || p['nonce'].length < 16 || (p['state'] !== undefined && typeof p['state'] !== 'string')) throw new Fail(C.REQUEST_INVALID);
    const t = now.getTime() / 1000;
    if (typeof p['exp'] !== 'number' || !Number.isFinite(p['exp'])) throw new Fail(C.REQUEST_INVALID);
    if (p['iat'] !== undefined && (typeof p['iat'] !== 'number' || p['iat'] > t + SKEW_SECONDS)) throw new Fail(C.REQUEST_INVALID);
    // A request lives minutes, not years: exp at most 600 s after min(iat, now).
    if (p['exp'] > Math.min((p['iat'] as number | undefined) ?? t, t) + MAX_REQUEST_SECONDS) throw new Fail(C.REQUEST_INVALID);
    // No skew here: the library refuses an exp in the past with a generic error, and submit refuses an
    // expired request anyway, so an exp that is not in the future is REQUEST_EXPIRED, decided by us first.
    if (p['exp'] <= t) throw new Fail(C.REQUEST_EXPIRED);
    const meta = isObject(p['client_metadata']) ? p['client_metadata'] : {};
    const keys = isObject(meta['jwks']) && Array.isArray(meta['jwks']['keys']) ? (meta['jwks']['keys'] as unknown[]).filter((k) => isObject(k) && k['alg'] === 'ECDH-ES' && (k['use'] ?? 'enc') === 'enc') : [];
    const key = keys.length === 1 ? (keys[0] as Record<string, unknown>) : null;
    const publicJwk = normalizeEcPublicJwk(key);
    if (!key || !publicJwk) throw new Fail(C.REQUEST_INVALID);
    const encValues = Array.isArray(meta['encrypted_response_enc_values_supported']) ? meta['encrypted_response_enc_values_supported'] : ['A128GCM'];
    const enc: JweEnc | null = encValues.includes('A256GCM') ? 'A256GCM' : encValues.includes('A128GCM') ? 'A128GCM' : null;
    const query = isObject(p['dcql_query']) ? p['dcql_query'] : null;
    const credentialQueries = query && Array.isArray(query['credentials']) ? query['credentials'] : [];
    const cq = credentialQueries.length === 1 && isObject(credentialQueries[0]) ? credentialQueries[0] : null;
    if (!enc || !query || !cq || cq['format'] !== 'dc+sd-jwt' || typeof cq['id'] !== 'string') throw new Fail(C.REQUEST_INVALID);
    // One credential, no `multiple`, no value matching, credential_sets only in the form that carries the purpose.
    if (cq['multiple'] === true || !plainCredentialSets(query, cq['id'])) throw new Fail(C.REQUEST_INVALID);
    // Claim set entries are claim ids; each claim must be one top-level name, which is what gets disclosed.
    const claimNames = new Map<string, string>();
    for (const c of Array.isArray(cq['claims']) ? cq['claims'] : []) {
      const path = isObject(c) ? c['path'] : undefined;
      if (!isObject(c) || typeof c['id'] !== 'string' || !Array.isArray(path) || path.length !== 1 || typeof path[0] !== 'string' || 'values' in c) throw new Fail(C.REQUEST_INVALID);
      claimNames.set(c['id'], path[0]);
    }
    const sets = Array.isArray(cq['claim_sets']) ? (cq['claim_sets'] as unknown[]) : [[...claimNames.keys()]];
    const claimSets = sets.map((set) => (Array.isArray(set) ? set.map((id) => claimNames.get(id as string)) : []));
    if (claimSets.some((set) => set.length === 0 || set.some((n) => n === undefined))) throw new Fail(C.REQUEST_INVALID);
    // ADR-0008 section 5: each later option only shrinks the first, so "share less" never adds a field.
    if (!claimSetsNested(claimSets as string[][])) throw new Fail(C.REQUEST_INVALID);
    return {
      jwk: chain.leaf.publicJwk, fingerprint: chain.fingerprint, organisation: chain.leaf.subject.organizationIdentifier,
      state: {
        nonce: p['nonce'], state: p['state'] as string | undefined, responseUri: p['response_uri'] as string,
        encryptionJwk: { ...publicJwk, ...(typeof key['kid'] === 'string' ? { kid: key['kid'] } : {}) }, enc,
        queryId: cq['id'], claimSets: claimSets as string[][], expiresAt: (p['exp'] as number) * 1000, query, purpose: purposeOf(query),
      },
    };
  }

  /** The vault's credentials the query can use, with the claim sets each satisfies. */
  async function match(query: Record<string, unknown>, queryId: string, claimSets: string[][]): Promise<PresentationMatch[]> {
    const vcts = (((query['credentials'] as Record<string, unknown>[])[0]!['meta'] as Record<string, unknown> | undefined)?.['vct_values'] as unknown[] | undefined) ?? [];
    let rows;
    try {
      rows = (await ctx.vault.list()).filter((r) => vcts.includes(r.vct));
    } catch (e) {
      throw new Fail(vaultFailureCode(e));
    }
    const held: { id: string; vct: string; compact: string; claims: Record<string, unknown> }[] = [];
    for (const row of rows) {
      let compact: string;
      try {
        compact = await ctx.vault.open(row.id);
      } catch (e) {
        // A row that does not decrypt is not offered (purgeUndecryptable reports it); a data key that
        // cannot be read (cancelled, locked, invalidated) or a failing vault ends the resolve.
        if (e instanceof CredentialVaultError && e.code === 'UNDECRYPTABLE') continue;
        throw new Fail(vaultFailureCode(e));
      }
      try {
        const d = decodeCredentialUnverified(compact);
        held.push({ id: row.id, vct: d.payload['vct'] as string, compact, claims: Object.fromEntries(d.disclosures.map((x) => [x.name, x.value])) });
      } catch {
        // not a compact this wallet stored: skipped
      }
    }
    const satisfied = matchDcql(query, queryId, held);
    if (!satisfied) throw new Fail(C.REQUEST_INVALID);
    const out: PresentationMatch[] = [];
    for (let i = 0; i < held.length; i++) {
      if (satisfied[i]!.length === 0) continue;
      out.push({
        credentialId: held[i]!.id, vct: held[i]!.vct, issuerName: await issuerNameOf(ctx, held[i]!.compact),
        claimSets: satisfied[i]!.map((index) => ({ index, claims: [...claimSets[index]!] })),
      });
    }
    return out;
  }

  async function resolve(qrText: string): Promise<{ ok: true; request: ResolvedPresentation } | WalletFailure> {
    try {
      const qr = parseQr(qrText);
      if (ctx.allowedOrigins && !ctx.allowedOrigins.includes(qr.origin)) throw new Fail(C.URL_NOT_ALLOWED);
      const deps = depsFor(qr.origin);
      let checked: Awaited<ReturnType<typeof checkJar>> | undefined;
      let refused: unknown;
      let fetchFailure: WalletErrorCode | undefined;
      const recording = async (url: string, init?: Parameters<typeof deps.fetch>[1]) =>
        deps.fetch(url, init).catch((e: unknown) => {
          if (e instanceof WalletFetchError) fetchFailure = e.code === 'ISSUER_ERROR' ? C.VERIFIER_ERROR : e.code;
          throw e;
        });
      try {
        await resolvePresentationRequest(qrText, { ...deps, fetch: recording, now: ctx.clock.now() }, async (jar) => {
          try {
            checked = await checkJar(jar, qr);
            return checked.jwk;
          } catch (e) {
            refused = e;
            return null;
          }
        });
      } catch (e) {
        // The library swallows fetch errors and our own refusal; report what we recorded.
        if (refused) throw refused;
        throw new Fail(fetchFailure ?? (failureOf(e).code === 'ISSUER_ERROR' ? C.REQUEST_INVALID : failureOf(e).code));
      }
      if (!checked) throw new Fail(C.REQUEST_INVALID);
      let entry;
      try {
        entry = await ctx.trustRegistry.lookup(checked.fingerprint, ctx.clock.now());
      } catch {
        // Fail closed (TrustListUnavailableError or any other failure): the wallet cannot tell the user who is asking.
        throw new Fail(C.TRUST_LIST_UNAVAILABLE);
      }
      const trusted = entry !== null && entry.mucDich === 'request' && entry.maToChuc === checked.organisation;
      const s = checked.state;
      const matches = await match(s.query, s.queryId, s.claimSets);
      const resolved: ResolvedPresentation = {
        clientId: qr.clientId,
        verifier: trusted ? { trusted: true, ten: entry!.ten, maToChuc: entry!.maToChuc } : { trusted: false },
        ...(trusted ? {} : { warning: C.VERIFIER_NOT_TRUSTED }),
        // Free text from an unverified party under a warning would be an impersonation tool.
        ...(trusted && s.purpose !== undefined ? { purpose: s.purpose } : {}),
        matches,
        expiresAt: new Date(s.expiresAt).toISOString(),
      };
      requests.set(resolved, {
        origin: qr.origin, clientId: qr.clientId, trusted, nonce: s.nonce, state: s.state, responseUri: s.responseUri,
        encryptionJwk: s.encryptionJwk, enc: s.enc, queryId: s.queryId, claimSets: s.claimSets, expiresAt: s.expiresAt,
        offered: new Map(matches.map((m) => [m.credentialId, m.claimSets.map((c) => c.index)])),
      });
      return { ok: true, request: resolved };
    } catch (e) {
      return e instanceof Fail ? fail(e.code) : fail(failureOf(e).code);
    }
  }

  /**
   * A resolved request is answered at most once: it is forgotten right before the response is sent,
   * so a second submit (or a decline afterwards) is REQUEST_INVALID. A failure before sending
   * (biometric prompt cancelled, untrusted verifier refused, storage) leaves it usable.
   */
  async function submit(resolved: ResolvedPresentation, choice: { credentialId: string; claimSetIndex: number; allowUntrusted?: boolean }): Promise<{ ok: true } | WalletFailure> {
    const s = requests.get(resolved);
    if (!s) return fail(C.REQUEST_INVALID);
    if (!s.offered.get(choice.credentialId)?.includes(choice.claimSetIndex)) throw new TypeError('credentialId and claimSetIndex must be one of the offered matches');
    if (!s.trusted && choice.allowUntrusted !== true) return fail(C.VERIFIER_NOT_TRUSTED);
    if (ctx.clock.now().getTime() >= s.expiresAt) return fail(C.REQUEST_EXPIRED);
    let row;
    let compact: string;
    try {
      row = await ctx.vault.getMeta(choice.credentialId);
      if (row === null) return fail(C.CREDENTIAL_NOT_FOUND);
      compact = await ctx.vault.open(row.id);
    } catch (e) {
      return fail(vaultFailureCode(e));
    }
    // The platform asks for biometrics when the key is read (software store) or used (hardware store,
    // ADR-0009 point 4): both rejections are kept to report their code.
    let keyError: unknown;
    let presentation: string;
    try {
      const signer = await ctx.keyStore.signer(row.key_id);
      const holderSigner = { ...signer, sign: (data: Uint8Array) => signer.sign(data).catch((e: unknown) => Promise.reject((keyError = e))) };
      presentation = await createPresentation({
        compact, disclose: s.claimSets[choice.claimSetIndex]!, holderSigner, audience: s.clientId, nonce: s.nonce, now: ctx.clock.now(), hasher: ctx.hasher,
      });
    } catch (e) {
      return fail(keyFailureCode(keyError ?? e));
    }
    const payload = { vp_token: { [s.queryId]: [presentation] }, ...(s.state !== undefined ? { state: s.state } : {}) };
    const header = s.encryptionJwk.kid !== undefined ? { kid: s.encryptionJwk.kid } : {};
    const jwe = encryptJwe({ recipientPublicJwk: s.encryptionJwk, enc: s.enc, plaintext: utf8Encode(JSON.stringify(payload)), random: ctx.random, header });
    if (!requests.delete(resolved)) return fail(C.REQUEST_INVALID); // a concurrent submit got here first
    try {
      const r = await depsFor(s.origin).fetch(s.responseUri, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `response=${encodeURIComponent(jwe)}`, maxBytes: 16_384,
      });
      return r.status === 200 ? { ok: true } : fail(C.VERIFIER_ERROR);
    } catch (e) {
      const code: ErrorCode = e instanceof WalletFetchError && e.code !== 'ISSUER_ERROR' ? e.code : C.VERIFIER_ERROR;
      return fail(code as WalletErrorCode);
    }
  }

  /** Forgets the request; REQUEST_INVALID when it was already answered or declined. No network call: an OpenID4VP error response is optional and not sent. */
  function decline(resolved: ResolvedPresentation): { ok: true } | WalletFailure {
    return requests.delete(resolved) ? { ok: true } : fail(C.REQUEST_INVALID);
  }

  return { resolve, submit, decline };
}

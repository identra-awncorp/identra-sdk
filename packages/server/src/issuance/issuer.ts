// OpenID4VCI 1.0 Credential Issuer and its authorization server, pre-authorized code flow
// (ADR-0010, vc-api.md section 4, docs/architecture.md section 8). Every protocol operation returns
// a ready HTTP response and never throws for bad input from the network; it throws only when a
// dependency (state store, callbacks, signer) fails.
import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  base64UrlDecode, base64UrlEncode, issueDiploma, jwkThumbprint, normalizeEcPublicJwk, VCT,
  type Clock, type DiplomaClaims, type EcPublicJwk, type Hasher, type RandomSource, type Signer, type Verifier,
} from '@identra/sdk-core';
import { ACCESS_TOKEN_SECONDS, signAccessToken, verifyAccessToken } from './access-token.js';
import { jsonResponse, oauthError, type HttpRequest, type HttpResponse } from './http.js';
import type { IssuerKeys } from './keys.js';
import { createIssuerLibrary, PRE_AUTHORIZED_GRANT, type ConfigurationMetadata, type Display, type JweEnc } from './library.js';
import { verifyProof } from './proof.js';
import type { ProtocolStateStore } from '../state-store.js';

export const OFFER_SECONDS = 600;
export const OFFER_STATUS_SECONDS = 1800;
export const NONCE_SECONDS = 300;
export const MAX_TX_CODE_ATTEMPTS = 5;
const MAX_BODY_BYTES = 65536;
const ID = /^[A-Za-z0-9_-]{22}$/;
const CODE = /^[A-Za-z0-9_-]{43}$/;
const TX_CODE_DESCRIPTION = 'Nhập mã PIN 6 chữ số được cấp cùng mã QR';

/** Credential configurations this SDK can issue; the caller supplies the handlers per id. */
export const CREDENTIAL_CONFIGURATIONS: Readonly<Record<string, ConfigurationMetadata>> = Object.freeze({
  'bang-tot-nghiep-v1': {
    vct: VCT.diploma,
    display: { vi: 'Bằng tốt nghiệp', en: 'Diploma' },
    claims: [
      { name: 'ho_ten', display: { vi: 'Họ và tên', en: 'Full name' } },
      { name: 'ngay_sinh', display: { vi: 'Ngày sinh', en: 'Date of birth' } },
      { name: 'ma_sinh_vien', display: { vi: 'Mã sinh viên', en: 'Student ID' } },
      { name: 'nganh', display: { vi: 'Ngành', en: 'Major' } },
      { name: 'hang_tot_nghiep', display: { vi: 'Hạng tốt nghiệp', en: 'Classification' } },
      { name: 'nam_tot_nghiep', display: { vi: 'Năm tốt nghiệp', en: 'Year of graduation' } },
      { name: 'so_hieu_bang', display: { vi: 'Số hiệu bằng', en: 'Diploma number' } },
    ],
  },
});

export interface IssuedEvent {
  offerId: string;
  subjectRef: string;
  statusUri: string;
  statusIdx: number;
  /** RFC 7638 thumbprint of the wallet key in `cnf.jwk`. */
  cnfThumbprint: string;
  issuedAt: Date;
}

export interface CredentialHandlers {
  /** The subject's diploma claims from the school's records, or null when there is none. */
  resolveClaims(subjectRef: string): Promise<DiplomaClaims | null>;
  /** Persists the issuance record (never the credential); called after the credential is built, before it is sent. */
  onIssued(event: IssuedEvent): Promise<{ credentialId: string }>;
}

export interface CredentialIssuerConfig {
  /** `https://api-identra.awncorp.vn/issuers/<name>`: identifier, `iss`, and the base of every endpoint. */
  issuerUri: string;
  display: Display;
  /** The issuer's `vc` signer: x5c [leaf, issuing CA], leaf SAN URI = issuerUri. */
  signer: Signer;
  /** Reserves a fresh status list entry (StatusListService.allocate); an index is never handed out twice. */
  allocateStatus(): Promise<{ uri: string; idx: number }>;
  hasher: Hasher;
  verifier: Verifier;
  random: RandomSource;
  clock: Clock;
  store: ProtocolStateStore;
  keys: IssuerKeys;
  credentials: Record<string, CredentialHandlers>;
}

export type OfferStatus = 'pending' | 'issued' | 'expired';

export interface CredentialIssuer {
  metadata(): HttpResponse;
  authorizationServerMetadata(): HttpResponse;
  jwks(): HttpResponse;
  /** The PIN is returned here once and stored only as a keyed hash. */
  createOffer(input: { subjectRef: string; configurationId: string }): Promise<{ offerId: string; offerUri: string; txCode: string; expiresAt: string }>;
  offer(offerId: string): Promise<HttpResponse>;
  /** Null when unknown or older than 30 minutes. */
  offerStatus(offerId: string): Promise<{ status: OfferStatus; subjectRef: string; credentialId?: string } | null>;
  token(request: HttpRequest): Promise<HttpResponse>;
  nonce(): Promise<HttpResponse>;
  credential(request: HttpRequest): Promise<HttpResponse>;
}

interface OfferRecord { offer: unknown; subjectRef: string; configurationId: string; pinKey: string; pinMac: string; expiresAt: number }
interface StatusRecord { status: 'pending' | 'issued' | 'destroyed'; subjectRef: string; createdAt: number; expiresAt: number; credentialId?: string }
interface TokenRecord { offerId: string; subjectRef: string; configurationId: string }

const mac = (key: string, pin: string) => createHmac('sha256', base64UrlDecode(key)).update(pin, 'utf8').digest();
const contentType = (r: HttpRequest) => (r.headers['content-type'] ?? '').toLowerCase();

/** Six decimal digits, uniform: 32-bit draws above the largest multiple of 10^6 are drawn again. */
function drawPin(random: RandomSource): string {
  const limit = Math.floor(2 ** 32 / 1e6) * 1e6;
  for (let i = 0; i < 16; i++) {
    const b = random.bytes(4);
    const n = ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
    if (n < limit) return String(n % 1e6).padStart(6, '0');
  }
  throw new Error('RandomSource keeps returning out-of-range values');
}

export function createCredentialIssuer(config: CredentialIssuerConfig): CredentialIssuer {
  const { issuerUri, signer, hasher, verifier, random, clock, store, keys } = config;
  if (typeof issuerUri !== 'string' || !/^https:\/\/[^/?#]+\/[^?#]*[^/?#]$/.test(issuerUri)) throw new TypeError('issuerUri must be an https URL with a path and no trailing slash');
  for (const id of Object.keys(config.credentials)) if (!Object.hasOwn(CREDENTIAL_CONFIGURATIONS, id)) throw new TypeError(`unknown credential configuration ${id}`);
  const configurations = Object.fromEntries(Object.keys(config.credentials).map((id) => [id, CREDENTIAL_CONFIGURATIONS[id]!]));
  const lib = createIssuerLibrary({
    issuerUri, display: config.display, configurations, hasher, random,
    requestEncryptionJwk: keys.requestEncryption.publicJwk, decryptionKey: keys.requestEncryption.privateKey,
  });
  const key = (kind: string, id: string) => `vci:${issuerUri}:${kind}:${id}`;
  const newId = () => base64UrlEncode(random.bytes(16));
  const read = async <T>(k: string): Promise<T | null> => {
    const v = await store.get(k);
    return v === null ? null : (JSON.parse(v) as T);
  };
  const ok = (value: unknown) => jsonResponse(200, value);

  /** Code and offer are gone; the status reads `expired` from now on. */
  async function destroyOffer(offerId: string, code: string): Promise<void> {
    await store.take(key('code', code));
    await store.take(key('offer', offerId));
    const status = await read<StatusRecord>(key('status', offerId));
    if (status) await putStatus(offerId, { ...status, status: 'destroyed' });
  }
  async function putStatus(offerId: string, s: StatusRecord): Promise<void> {
    const left = Math.ceil((s.createdAt + OFFER_STATUS_SECONDS * 1000 - clock.now().getTime()) / 1000);
    if (left > 0) await store.put(key('status', offerId), JSON.stringify(s), left);
  }

  return {
    metadata: () => ok(lib.credentialIssuerMetadata),
    authorizationServerMetadata: () => ok(lib.authorizationServerMetadata),
    jwks: () => ok({ keys: [keys.accessToken.publicJwk] }),

    async createOffer({ subjectRef, configurationId }) {
      if (typeof subjectRef !== 'string' || subjectRef === '' || subjectRef.length > 256) throw new TypeError('subjectRef must be a non-empty string');
      if (!Object.hasOwn(config.credentials, configurationId)) throw new TypeError('unknown configurationId');
      const offerId = newId();
      const code = base64UrlEncode(random.bytes(32));
      const txCode = drawPin(random);
      const pinKey = base64UrlEncode(random.bytes(32));
      const now = clock.now().getTime();
      const expiresAt = now + OFFER_SECONDS * 1000;
      const { offerUri, offer } = await lib.createOffer({ offerUri: `${issuerUri}/offers/${offerId}`, configurationId, preAuthorizedCode: code, txCodeDescription: TX_CODE_DESCRIPTION });
      const record: OfferRecord = { offer, subjectRef, configurationId, pinKey, pinMac: base64UrlEncode(mac(pinKey, txCode)), expiresAt };
      await putStatus(offerId, { status: 'pending', subjectRef, createdAt: now, expiresAt });
      await store.put(key('offer', offerId), JSON.stringify(record), OFFER_SECONDS);
      await store.put(key('code', code), offerId, OFFER_SECONDS);
      return { offerId, offerUri, txCode, expiresAt: new Date(expiresAt).toISOString() };
    },

    async offer(offerId) {
      const record = ID.test(offerId) ? await read<OfferRecord>(key('offer', offerId)) : null;
      if (!record || record.expiresAt <= clock.now().getTime()) return jsonResponse(404, { error: 'not_found' });
      return ok(record.offer);
    },

    async offerStatus(offerId) {
      const s = ID.test(offerId) ? await read<StatusRecord>(key('status', offerId)) : null;
      if (!s) return null;
      const status: OfferStatus = s.status === 'issued' ? 'issued' : s.status === 'destroyed' || s.expiresAt <= clock.now().getTime() ? 'expired' : 'pending';
      return { status, subjectRef: s.subjectRef, ...(s.credentialId !== undefined ? { credentialId: s.credentialId } : {}) };
    },

    async token(request) {
      if (!contentType(request).startsWith('application/x-www-form-urlencoded') || request.body.length > 4096) return oauthError(400, 'invalid_request', 'form-encoded token request expected');
      const params = new URLSearchParams(request.body);
      if (new Set(params.keys()).size !== [...params.keys()].length) return oauthError(400, 'invalid_request', 'a parameter is repeated');
      if (params.get('grant_type') !== PRE_AUTHORIZED_GRANT) return oauthError(400, 'unsupported_grant_type', 'only the pre-authorized code grant is supported');
      const code = params.get('pre-authorized_code');
      const txCode = params.get('tx_code');
      if (!code || txCode === null) return oauthError(400, 'invalid_request', 'pre-authorized_code and tx_code are required');
      const invalidGrant = oauthError(400, 'invalid_grant', 'the pre-authorized code or the transaction code is not valid');
      if (!CODE.test(code)) return invalidGrant;

      const offerId = await store.get(key('code', code));
      const record = offerId === null ? null : await read<OfferRecord>(key('offer', offerId));
      if (offerId === null || !record || record.expiresAt <= clock.now().getTime()) return invalidGrant;
      // The attempt is counted before the comparison, so concurrent guesses cannot exceed the limit.
      const attempt = await store.increment(key('attempts', offerId), OFFER_SECONDS);
      if (attempt > MAX_TX_CODE_ATTEMPTS) return invalidGrant;
      const given = mac(record.pinKey, txCode);
      if (!/^[0-9]{6}$/.test(txCode) || !timingSafeEqual(given, base64UrlDecode(record.pinMac))) {
        if (attempt === MAX_TX_CODE_ATTEMPTS) await destroyOffer(offerId, code);
        return invalidGrant;
      }
      // Single use: of concurrent requests with the right PIN, only the one that takes the code wins.
      if ((await store.take(key('code', code))) === null) return invalidGrant;
      await store.take(key('offer', offerId));
      const jti = newId();
      const token: TokenRecord = { offerId, subjectRef: record.subjectRef, configurationId: record.configurationId };
      await store.put(key('token', jti), JSON.stringify(token), ACCESS_TOKEN_SECONDS);
      const accessToken = await signAccessToken({ signer: keys.accessToken.signer, issuerUri, jti, now: clock.now() });
      return ok({ access_token: accessToken, token_type: 'Bearer', expires_in: ACCESS_TOKEN_SECONDS });
    },

    async nonce() {
      const cNonce = base64UrlEncode(random.bytes(16));
      await store.put(key('nonce', cNonce), '1', NONCE_SECONDS);
      return ok({ c_nonce: cNonce, c_nonce_expires_in: NONCE_SECONDS });
    },

    async credential(request) {
      const now = clock.now();
      const jti = await verifyAccessToken(request.headers['authorization'], { publicJwk: keys.accessToken.publicJwk, verifier, issuerUri, now });
      const token = jti === null ? null : await read<TokenRecord>(key('token', jti));
      const invalidToken = oauthError(401, 'invalid_token', 'the access token is not valid');
      if (jti === null || !token) return invalidToken;
      if (request.body.length > MAX_BODY_BYTES) return oauthError(400, 'invalid_credential_request', 'the request is too large');

      const encrypted = contentType(request).startsWith('application/jwt');
      const parsed = await lib.parseCredentialRequest({ contentType: contentType(request), body: request.body });
      if (!parsed.ok) return oauthError(400, parsed.error, 'the credential request is not acceptable');
      if (parsed.configurationId !== token.configurationId) return oauthError(400, 'invalid_credential_request', 'the access token does not cover this credential configuration');
      let encryption: { jwk: EcPublicJwk & { alg: 'ECDH-ES' }; enc: JweEnc } | null = null;
      if (parsed.responseEncryption) {
        const { jwk, enc } = parsed.responseEncryption;
        const publicJwk = normalizeEcPublicJwk(jwk);
        // OpenID4VCI 1.0 section 10: a request asking for an encrypted response must itself be encrypted.
        if (!encrypted || !publicJwk || (jwk as { alg?: unknown }).alg !== 'ECDH-ES' || (enc !== 'A256GCM' && enc !== 'A128GCM')) {
          return oauthError(400, 'invalid_encryption_parameters', 'credential response encryption parameters are not acceptable');
        }
        encryption = { jwk: { ...publicJwk, alg: 'ECDH-ES' }, enc };
      }
      if (parsed.jwtProofs.length !== 1 || parsed.otherProofs) return oauthError(400, 'invalid_proof', 'exactly one jwt proof is required');
      const proof = await verifyProof(parsed.jwtProofs[0], { issuerUri, verifier, now });
      if (!proof.ok) return oauthError(400, 'invalid_proof', 'the proof is not valid');
      if ((await store.take(key('nonce', proof.nonce))) === null) return oauthError(400, 'invalid_nonce', 'the c_nonce is unknown, expired or used');
      // One credential per access token: consumed here, before any effect.
      if ((await store.take(key('token', jti))) === null) return invalidToken;

      // Order of effects (architecture section 8): a failure from here on throws; the token is spent,
      // an allocated status index stays reserved and unused, and the offer is not marked issued.
      const claims = await config.credentials[token.configurationId]!.resolveClaims(token.subjectRef);
      if (claims === null) return oauthError(400, 'credential_request_denied', 'no credential is available for this offer');
      const status = await config.allocateStatus();
      const issuedAt = new Date(now.getTime());
      const compact = await issueDiploma({ signer, hasher, random, clock: { now: () => issuedAt }, iss: issuerUri, cnfJwk: proof.jwk, status, claims });
      const response = await lib.credentialResponse(compact, encryption);
      const cnfThumbprint = await jwkThumbprint(proof.jwk, hasher);
      const { credentialId } = await config.credentials[token.configurationId]!.onIssued({
        offerId: token.offerId, subjectRef: token.subjectRef, statusUri: status.uri, statusIdx: status.idx, cnfThumbprint, issuedAt,
      });
      try {
        const s = await read<StatusRecord>(key('status', token.offerId));
        if (s) await putStatus(token.offerId, { ...s, status: 'issued', credentialId });
      } catch {
        // The credential is issued and recorded by onIssued; only the portal's display status lags.
      }
      return { status: 200, headers: { 'Content-Type': response.contentType, 'Cache-Control': 'no-store' }, body: response.body };
    },
  };
}

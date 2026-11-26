// did:certnet resolved through the CertNet gateway (ADR-0020 sections 4 and 9; CertNet spec of
// 25/11: 1-did-certnet.md, 4-openapi.yaml `GET /v1/dids/{did}`). The gateway's answers are unsigned:
// its URL is trusted configuration. Every request goes through the injected HttpFetch.
import { DID_RESOLUTION_UNAVAILABLE_ERROR } from './did-jwk.js';
import type { Clock, DidDocument, DidResolutionResult, DidResolver, DidVerificationMethod, HttpFetch } from './interfaces.js';
import { fetchBody } from './token-cache.js';

export type CertNetNetwork = 'local' | 'testnet' | 'mainnet';
const NETWORKS: readonly string[] = ['local', 'testnet', 'mainnet'];
const CERTNET_DID = /^did:certnet:(local|testnet|mainnet):[A-Za-z0-9_-]+$/;
const GATEWAY = /^https:\/\/[A-Za-z0-9.-]+(:[0-9]{1,5})?(\/[A-Za-z0-9._~-]+)*$/;

/** Every `didResolutionMetadata.error` of the did:certnet resolver; only `unavailable` means "try later". */
export const DID_CERTNET_ERRORS = Object.freeze({
  /** Not `did:certnet:<network>:<id>`, of another network than configured, or refused by the gateway (422). */
  invalidDid: 'invalidDid',
  /** 404. */
  notFound: 'notFound',
  /** 410, or `metadata.deactivated` true. */
  deactivated: 'deactivated',
  /** A 200 answer that is not the contract's DidResolutionResult for this DID. */
  invalidDidDocument: 'invalidDidDocument',
  /** `versionTime` was given (the gateway of 25/11 answers 501). */
  versionTimeNotSupported: 'versionTimeNotSupported',
  /** 5xx, another status, timeout, fetch rejection, oversized or non-JSON body. */
  unavailable: DID_RESOLUTION_UNAVAILABLE_ERROR,
});

/** Size cap of one gateway answer (DID document or trust registry record), in bytes. */
export const CERTNET_RESPONSE_MAX_BYTES = 65_536;
export const DID_CERTNET_DEFAULT_CACHE_SECONDS = 60;
export const DID_CERTNET_MAX_CACHE_SECONDS = 300;
export const DID_CERTNET_CACHE_MAX_ENTRIES = 100;

/** True for `did:certnet:(local|testnet|mainnet):[A-Za-z0-9_-]+`, of `network` when given. */
export function isCertNetDid(did: unknown, network?: CertNetNetwork): did is string {
  return typeof did === 'string' && CERTNET_DID.test(did) && (network === undefined || did.split(':')[2] === network);
}

/**
 * The checked gateway base URL (an https origin, optionally with a path prefix, without a trailing
 * slash) and network, shared by the resolver and the trust registry; TypeError otherwise.
 */
export function certNetGateway(o: { gatewayUrl: string; network: CertNetNetwork; fetch: HttpFetch }): string {
  const url = typeof o?.gatewayUrl === 'string' ? o.gatewayUrl.replace(/\/$/, '') : '';
  if (!GATEWAY.test(url) || url.split('/').slice(3).some((s) => s === '.' || s === '..')) {
    throw new TypeError('gatewayUrl must be https://host[:port][/path] without query, fragment or dot segments');
  }
  if (!NETWORKS.includes(o.network)) throw new TypeError('network must be local, testnet or mainnet');
  if (typeof o.fetch !== 'function') throw new TypeError('fetch is required');
  return url;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isStringList = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === 'string');

function failure(error: string, message: string): DidResolutionResult {
  return { didDocument: null, didDocumentMetadata: {}, didResolutionMetadata: { error, message } };
}

/** The resolution result of a 200 body, or a failure when it is not the contract's DidResolutionResult for `did`. */
function fromBody(did: string, body: Record<string, unknown>): DidResolutionResult {
  const bad = (message: string) => failure(DID_CERTNET_ERRORS.invalidDidDocument, message);
  const doc = body['document'];
  const meta = body['metadata'];
  if (body['did'] !== did || !isObject(doc) || doc['id'] !== did) return bad('the answer is not about this DID');
  if (meta !== undefined && !isObject(meta)) return bad('metadata is not an object');
  if (meta !== undefined && meta['deactivated'] !== undefined && typeof meta['deactivated'] !== 'boolean') return bad('metadata.deactivated is not a boolean');
  if (meta?.['deactivated'] === true) return failure(DID_CERTNET_ERRORS.deactivated, 'the DID is deactivated');
  const vms = doc['verificationMethod'];
  if (!Array.isArray(vms)) return bad('verificationMethod is not a list');
  const methods: DidVerificationMethod[] = [];
  for (const vm of vms) {
    if (!isObject(vm) || typeof vm['id'] !== 'string' || typeof vm['type'] !== 'string' || !isObject(vm['publicKeyJwk'])) return bad('a verification method lacks id, type or publicKeyJwk');
    if (!vm['id'].startsWith(`${did}#`) || vm['controller'] !== did) return bad('a verification method belongs to another DID');
    if (methods.some((m) => m.id === vm['id'])) return bad('two verification methods share one id');
    methods.push({ id: vm['id'], type: vm['type'], controller: did, publicKeyJwk: { ...vm['publicKeyJwk'] } });
  }
  const context = doc['@context'];
  if (context !== undefined && !isStringList(context)) return bad('@context is not a list of strings');
  const document: DidDocument = { '@context': context ? [...context] : ['https://www.w3.org/ns/did/v1'], id: did, verificationMethod: methods };
  for (const rel of ['authentication', 'assertionMethod', 'capabilityInvocation'] as const) {
    const v = doc[rel];
    if (v === undefined) continue;
    if (!isStringList(v)) return bad(`${rel} is not a list of strings`);
    document[rel] = [...v];
  }
  const metadata: Record<string, unknown> = {};
  for (const k of ['created', 'updated', 'versionId', 'deactivated']) if (meta?.[k] !== undefined) metadata[k] = meta[k];
  return { didDocument: document, didDocumentMetadata: metadata, didResolutionMetadata: { contentType: 'application/did+json' } };
}

/**
 * DidResolver for `did:certnet:<network>:<id>` over `GET <gatewayUrl>/v1/dids/<encoded DID>`. Never
 * throws for bad input. Only DIDs of the configured network are requested. Successful resolutions are
 * cached per DID for `cacheSeconds` (default 60, at most 300; 0 = no cache) as counted by `clock`, a
 * clock that stepped back makes an entry stale; failures are never cached. TypeError for bad options.
 */
export function createCertNetDidResolver(options: {
  gatewayUrl: string;
  network: CertNetNetwork;
  fetch: HttpFetch;
  clock: Clock;
  cacheSeconds?: number;
  maxEntries?: number;
}): DidResolver {
  const base = certNetGateway(options);
  const { network, fetch: httpFetch, clock, cacheSeconds = DID_CERTNET_DEFAULT_CACHE_SECONDS, maxEntries = DID_CERTNET_CACHE_MAX_ENTRIES } = options;
  if (typeof clock?.now !== 'function') throw new TypeError('clock is required');
  if (!Number.isSafeInteger(cacheSeconds) || cacheSeconds < 0 || cacheSeconds > DID_CERTNET_MAX_CACHE_SECONDS) {
    throw new TypeError(`cacheSeconds must be an integer from 0 to ${DID_CERTNET_MAX_CACHE_SECONDS}`);
  }
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) throw new TypeError('maxEntries must be a positive integer');
  // Held as JSON text: every caller gets its own copy.
  const cache = new Map<string, { json: string; atMs: number }>();

  async function fetchResolution(did: string): Promise<DidResolutionResult> {
    const unavailable = (message: string) => failure(DID_CERTNET_ERRORS.unavailable, message);
    let res: { status: number; body: string | null };
    try {
      res = await fetchBody(httpFetch, `${base}/v1/dids/${encodeURIComponent(did)}`, CERTNET_RESPONSE_MAX_BYTES, 'application/json');
    } catch {
      return unavailable('the gateway did not answer');
    }
    if (res.status === 404) return failure(DID_CERTNET_ERRORS.notFound, 'the DID does not exist');
    if (res.status === 410) return failure(DID_CERTNET_ERRORS.deactivated, 'the DID is deactivated');
    if (res.status === 422) return failure(DID_CERTNET_ERRORS.invalidDid, 'the gateway refused the DID');
    if (res.status !== 200) return unavailable(`the gateway answered HTTP ${res.status}`);
    if (res.body === null) return unavailable('the answer is too large');
    let body: unknown;
    try {
      body = JSON.parse(res.body);
    } catch {
      return unavailable('the answer is not JSON');
    }
    return isObject(body) ? fromBody(did, body) : failure(DID_CERTNET_ERRORS.invalidDidDocument, 'the answer is not an object');
  }

  return {
    async resolve(did, opts) {
      try {
        if (!isCertNetDid(did)) return failure(DID_CERTNET_ERRORS.invalidDid, 'not did:certnet:<network>:<id>');
        if (!isCertNetDid(did, network)) return failure(DID_CERTNET_ERRORS.invalidDid, 'a DID of another network');
        if (opts?.versionTime !== undefined) return failure(DID_CERTNET_ERRORS.versionTimeNotSupported, 'resolving at a versionTime is not supported');
        const now = clock.now().getTime();
        const held = cache.get(did);
        if (held && now - held.atMs >= 0 && now - held.atMs < cacheSeconds * 1000) return JSON.parse(held.json) as DidResolutionResult;
        cache.delete(did);
        const result = await fetchResolution(did);
        if (result.didDocument && cacheSeconds > 0) {
          if (cache.size >= maxEntries) cache.delete(cache.keys().next().value!);
          cache.set(did, { json: JSON.stringify(result), atMs: now });
        }
        return result;
      } catch {
        return failure(DID_CERTNET_ERRORS.unavailable, 'resolution failed');
      }
    },
  };
}

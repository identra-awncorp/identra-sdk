// DidTrustRegistry over the CertNet trust registry (TIR) through the gateway (ADR-0020 section 5;
// CertNet spec of 25/11: 3-trust-registry.md, 4-openapi.yaml `GET /v1/trust-registry/issuers/{issuerDid}`).
// Nothing is cached: a withdrawn recognition takes effect at the next check.
import { certNetGateway, CERTNET_RESPONSE_MAX_BYTES, isCertNetDid, type CertNetNetwork } from '../did-certnet.js';
import type { DidIssuerTrust, DidTrustRegistry, HttpFetch } from '../interfaces.js';
import { TrustListUnavailableError } from '../results.js';
import { fetchBody } from '../token-cache.js';
import { CLOCK_SKEW_MS } from '../x509/chain.js';

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$/;

/** Milliseconds of an RFC 3339 date-time naming a real instant (fraction truncated to ms), else null. */
function instantMs(s: unknown): number | null {
  const m = typeof s === 'string' ? RFC3339.exec(s) : null;
  if (!m) return null;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const t = new Date(Date.UTC(y, mo - 1, d, h, mi, se, Number((m[7] ?? '').padEnd(3, '0').slice(0, 3))));
  // The round trip refuses 2026-02-30, 24:00:00, a leap second and years below 100, which Date.UTC would roll over.
  if (t.getUTCFullYear() !== y || t.getUTCMonth() !== mo - 1 || t.getUTCDate() !== d || t.getUTCHours() !== h || t.getUTCMinutes() !== mi || t.getUTCSeconds() !== se) return null;
  if (m[8] === undefined) return t.getTime();
  const [oh, om] = [Number(m[9]), Number(m[10])];
  if (oh > 23 || om > 59) return null;
  return t.getTime() - (m[8] === '-' ? -1 : 1) * (oh * 60 + om) * 60_000;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const notTrusted = (detail: string): DidIssuerTrust => ({ trusted: false, detail });

/**
 * `lookupIssuer(did, vct, at)` asks `GET <gatewayUrl>/v1/trust-registry/issuers/<did>?vcType=<vct>`
 * and trusts only a 200 whose `issuerDid` is `did`, `recognition` is `recognized`, `vcTypes` holds
 * exactly `vct` (compared here, the gateway's filter is not relied on), and `at` is within
 * `[validFrom − 60 s, validUntil + 60 s]` for each bound present and not null. 404, `rejected`, another
 * type or outside the window: not trusted. Any other answer (5xx, another status, timeout, oversized,
 * not the contract's shape, another `issuerDid`): rejects with TrustListUnavailableError. A DID that is
 * not `did:certnet` of `network` is not trusted without a request. TypeError for bad options or `at`.
 */
export function createCertNetTrustRegistry(options: { gatewayUrl: string; network: CertNetNetwork; fetch: HttpFetch }): DidTrustRegistry {
  const base = certNetGateway(options);
  const { network, fetch: httpFetch } = options;
  return {
    async lookupIssuer(did, vct, at) {
      const t = at instanceof Date ? at.getTime() : NaN;
      if (Number.isNaN(t)) throw new TypeError('at must be a valid Date');
      if (!isCertNetDid(did, network)) return notTrusted(`not a did:certnet DID of ${network}`);
      if (typeof vct !== 'string' || vct === '') return notTrusted('no credential type');
      const unavailable = (why: string) => new TrustListUnavailableError(`CertNet trust registry: ${why}`);
      let res: { status: number; body: string | null };
      try {
        res = await fetchBody(httpFetch, `${base}/v1/trust-registry/issuers/${encodeURIComponent(did)}?vcType=${encodeURIComponent(vct)}`, CERTNET_RESPONSE_MAX_BYTES, 'application/json');
      } catch {
        throw unavailable('no answer');
      }
      if (res.status === 404) return notTrusted('the issuer is not in the CertNet trust registry');
      if (res.status !== 200) throw unavailable(`HTTP ${res.status}`);
      if (res.body === null) throw unavailable('the answer is too large');
      let r: unknown;
      try {
        r = JSON.parse(res.body);
      } catch {
        throw unavailable('the answer is not JSON');
      }
      if (!isObject(r) || (r['recognition'] !== 'recognized' && r['recognition'] !== 'rejected')) throw unavailable('the answer is not a TrustLookupResult');
      if (r['issuerDid'] !== did) throw unavailable('the answer is about another DID');
      const types = r['vcTypes'];
      if (types !== undefined && !(Array.isArray(types) && types.every((v) => typeof v === 'string'))) throw unavailable('vcTypes is not a list of strings');
      const window: (number | null)[] = [];
      for (const name of ['validFrom', 'validUntil'] as const) {
        const v = r[name];
        const ms = v === undefined || v === null ? null : instantMs(v);
        if (v !== undefined && v !== null && ms === null) throw unavailable(`${name} is not a date-time`);
        window.push(ms);
      }
      if (r['recognition'] !== 'recognized') return notTrusted('the issuer is rejected in the CertNet trust registry');
      if (!types?.includes(vct)) return notTrusted('the issuer is not recognised for this credential type');
      const [from, until] = window;
      if (from != null && t < from - CLOCK_SKEW_MS) return notTrusted('the recognition is not valid yet');
      if (until != null && t > until + CLOCK_SKEW_MS) return notTrusted('the recognition has expired');
      return { trusted: true };
    },
  };
}

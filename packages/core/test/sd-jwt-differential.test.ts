// Differential test: our hand-written SD-JWT verification (compact.ts, holder-binding.ts,
// verify.ts) against the reference library's strict verification (SdJwtVcInstance.verify), on
// a deterministic corpus of valid and mutated presentations. Rule: we never accept what the
// library rejects; we may reject what it accepts only for the documented stricter classes below.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { base64UrlToUint8Array, Disclosure } from '@sd-jwt/core';
import { SdJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import {
  base64UrlDecode, base64UrlEncode, createPresentation, ErrorCodes, issueDiploma, METADATA_CLAIMS, parseCertificate,
  utf8Decode, utf8Encode, VCT, verifyPresentation, verifyStoredCredential, type RandomSource, type Signer,
} from '@identra/sdk-core';
import { disclosureDigest, sdHashOf } from '../dist/sd-jwt/holder-binding.js';
import { nobleHasher, nobleSigner, nobleVerifier } from './helpers/noble.js';
import { NOW, pemFile, x5c } from './helpers/pki.js';
import { AUD, clock, DIPLOMA, ISS, NONCE, NOW_S, presentationOptions, rawJws, STATUS, verifyOptions } from './helpers/sdjwt.js';

// --- deterministic randomness ----------------------------------------------------------------
let seed = 20261119;
const rand = () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const int = (n: number) => Math.floor(rand() * n);
const pick = <T>(a: readonly T[]): T => a[int(a.length)]!;
const random: RandomSource = { bytes: (n) => Uint8Array.from({ length: n }, () => int(256)) };
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const b64json = (v: unknown, spaced = false) => base64UrlEncode(utf8Encode(spaced ? JSON.stringify(v).replace(/,/g, ', ') : JSON.stringify(v)));

// --- the classes where we are deliberately stricter than the library, with the code we report --
const STRICTER: Record<string, string> = {
  'kb-in-stored-mode': ErrorCodes.MALFORMED, // a stored credential never carries a KB-JWT
  'iat-only-via-disclosure': ErrorCodes.MALFORMED, // iat must be a visible payload claim (library lets it through)
  'too-many-disclosures': ErrorCodes.TOO_LARGE, // ADR-0007: at most 50 (library has no limit)
  'too-large': ErrorCodes.TOO_LARGE, // ADR-0007: at most 16 384 bytes (library has no limit)
  'nested-disclosure': ErrorCodes.DISCLOSURE_INVALID, // our credential types have none (nested _sd inside a disclosure)
  'array-element-disclosure': ErrorCodes.MALFORMED, // "..." below the top level of the payload (step 1 shape rule)
  // RFC 9901 shape rules enforced even when no disclosure is presented (the library checks them
  // only while unpacking disclosures).
  'sd-alg-wrong-no-disclosures': ErrorCodes.MALFORMED,
  'sd-nested-undisclosed': ErrorCodes.MALFORMED,
  // A KB-JWT signature whose last base64url character differs only in the unused trailing bits:
  // same bytes, non-canonical text. We decode strictly (RFC 4648 section 3.5); the library accepts
  // it for the KB-JWT (it rejects the same change on the issuer signature, case
  // non-canonical-issuer-signature, which is therefore not listed here).
  'non-canonical-kb-signature': ErrorCodes.KB_INVALID,
};
/** Sets the unused low bits of the last character (a 64-byte value leaves 4 of 6 bits unused). */
const nonCanonical = (sig: string) => sig.slice(0, -1) + B64URL[B64URL.indexOf(sig.at(-1)!) | 0b0101]!;

// --- keys and base credentials ------------------------------------------------------------------
async function issuerSigner(): Promise<Signer> {
  const der = Buffer.from(pemFile('test/leaf/vc.key.pem').replace(/-----[A-Z ]+-----|\s/g, ''), 'base64');
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  return { ...nobleSigner(base64UrlDecode((await crypto.subtle.exportKey('jwk', key)).d!)), x5c: x5c('vc') };
}
const leafJwk = parseCertificate(Buffer.from(x5c('vc')[0]!, 'base64')).publicJwk!;

/** A hand-made credential: disclosures as given (encoding, spacing, shape), digests in `_sd`. */
async function crafted(issuer: Signer, holder: Signer, disclosures: string[], payloadPatch: Record<string, unknown> = {}, topLevel = disclosures) {
  const sd = (await Promise.all(topLevel.map((d) => disclosureDigest(d, nobleHasher)))).sort();
  const payload = { iss: ISS, vct: VCT.diploma, iat: Math.floor(NOW_S) - 3600, cnf: { jwk: holder.publicJwk }, status: { status_list: STATUS }, _sd: sd, _sd_alg: 'sha-256', ...payloadPatch };
  return `${await rawJws({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: x5c('vc') }, payload, issuer)}~${disclosures.map((d) => `${d}~`).join('')}`;
}
const salt = () => base64UrlEncode(random.bytes(16));
const kb = (sdJwt: string, holder: Signer, patch: Record<string, unknown> = {}) =>
  sdHashOf(sdJwt, nobleHasher).then((sd_hash) => rawJws({ typ: 'kb+jwt', alg: 'ES256' }, { iat: Math.floor(NOW_S), aud: AUD, nonce: NONCE, sd_hash, ...patch }, holder));
const parts = (p: string) => p.split('~');

// --- the two verifiers ----------------------------------------------------------------------------
type Mode = 'presentation' | 'stored';
interface Case { kind: string; mode: Mode; compact: string }

async function library(c: Case): Promise<{ ok: true; claims: Record<string, unknown> } | { ok: false; error: string }> {
  const hasher = (data: string | ArrayBuffer, alg: string) => {
    if (alg !== 'sha-256') throw new Error('hash alg');
    return nobleHasher.sha256(typeof data === 'string' ? utf8Encode(data) : new Uint8Array(data));
  };
  const verify = (jwk: unknown) => async (data: string, sig: string) => nobleVerifier.verify(jwk as never, utf8Encode(data), base64UrlToUint8Array(sig));
  const instance = new SdJwtVcInstance({
    hasher,
    verifier: verify(leafJwk), // the leaf key, bound in the closure
    kbVerifier: (data: string, sig: string, payload: { cnf?: { jwk?: unknown } }) => verify(payload?.cnf?.jwk)(data, sig),
    fetch: async () => { throw new Error('no network in tests'); },
  } as never);
  try {
    const r = await instance.verify(c.compact, {
      allowedIssuerAlgorithms: ['ES256'], allowedKeyBindingAlgorithms: ['ES256'], skewSeconds: 60, currentDate: Math.floor(NOW_S), disableStatusVerification: true,
      ...(c.mode === 'presentation' ? { keyBindingNonce: NONCE, expectedKeyBindingAudience: AUD, keyBindingMaxAgeSeconds: 300 } : {}),
    } as never);
    return { ok: true, claims: r.payload as Record<string, unknown> };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}
const ours = (c: Case) => (c.mode === 'presentation' ? verifyPresentation(c.compact, presentationOptions()) : verifyStoredCredential(c.compact, verifyOptions()));

// --- corpus ---------------------------------------------------------------------------------------
async function corpus(): Promise<Case[]> {
  const issuer = await issuerSigner();
  const holder = nobleSigner(random.bytes(32));
  const names = Object.keys(DIPLOMA);
  const nfd = Object.fromEntries(Object.entries(DIPLOMA).map(([k, v]) => [k, v.normalize('NFD')])) as typeof DIPLOMA;
  const issue = (claims: typeof DIPLOMA) => issueDiploma({ signer: issuer, hasher: nobleHasher, random, clock, iss: ISS, cnfJwk: holder.publicJwk, status: STATUS, claims });
  const spaced = await crafted(issuer, holder, Object.entries(DIPLOMA).map(([k, v]) => b64json([salt(), k, v], true)));
  const bases = [await issue(DIPLOMA), await issue(nfd), spaced];
  const present = (compact: string, disclose: string[]) => createPresentation({ compact, disclose, holderSigner: holder, audience: AUD, nonce: NONCE, now: NOW, hasher: nobleHasher });
  const subset = () => names.filter(() => rand() < 0.5);
  const without = (p: string) => p.slice(0, p.lastIndexOf('~') + 1);
  const cases: Case[] = [];
  const add = (kind: string, compact: string, mode: Mode = 'presentation') => cases.push({ kind, mode, compact });

  for (const base of bases) {
    for (let i = 0; i < 12; i++) {
      const p = await present(base, subset());
      add('valid', p);
      add('valid-stored', without(p), 'stored');
      add('kb-in-stored-mode', p, 'stored');
      const segs = parts(p);
      // one changed character in a random segment
      for (let j = 0; j < 4; j++) {
        const s = int(segs.length);
        const seg = segs[s]!;
        const at = int(seg.length);
        if (seg[at] === '.') continue;
        const ch = pick([...B64URL].filter((x) => x !== seg[at]));
        const flipped = [...segs];
        flipped[s] = seg.slice(0, at) + ch + seg.slice(at + 1);
        add(`flip-segment-${s === 0 ? 'issuer' : s === segs.length - 1 ? 'kb' : 'disclosure'}`, flipped.join('~'));
      }
      const ds = segs.slice(1, -1);
      const head = segs[0]!;
      if (ds.length >= 2) {
        const reordered = `${head}~${[...ds].reverse().join('~')}~`;
        add('reorder-before-kb', reordered + (await kb(reordered, holder)));
        add('reorder-after-kb', `${reordered}${segs.at(-1)}`);
        const dropped = `${head}~${ds.slice(1).join('~')}~`;
        add('drop-before-kb', dropped + (await kb(dropped, holder)));
        add('drop-after-kb', `${dropped}${segs.at(-1)}`);
      }
      if (ds.length >= 1) {
        const dup = `${without(p)}${ds[0]}~`;
        add('duplicate', dup + (await kb(dup, holder)));
        const respaced = b64json(JSON.parse(utf8Decode(base64UrlDecode(ds[0]!))), true);
        const reenc = `${head}~${[respaced, ...ds.slice(1)].join('~')}~`;
        if (respaced !== ds[0]) add('respaced-disclosure', reenc + (await kb(reenc, holder)));
        const arr = JSON.parse(utf8Decode(base64UrlDecode(ds[0]!))) as [string, string, string];
        const nfdValue = b64json([arr[0], arr[1], String(arr[2]).normalize('NFD')]);
        const nfcValue = b64json([arr[0], arr[1], String(arr[2]).normalize('NFC')]);
        const variant = nfdValue === ds[0] ? nfcValue : nfdValue;
        if (variant !== ds[0]) {
          const v = `${head}~${[variant, ...ds.slice(1)].join('~')}~`;
          add('unicode-variant', v + (await kb(v, holder)));
        }
        add('padding', `${head}~${ds[0]}=~${ds.slice(1).map((d) => `${d}~`).join('')}${segs.at(-1)}`);
      }
      const foreign = `${without(p)}${b64json([salt(), 'email', 'a@example.com'])}~`;
      add('foreign-disclosure', foreign + (await kb(foreign, holder)));
      add('swapped-kb', without(p) + parts(await present(base, subset())).at(-1));
      add('wrong-sd-hash', without(p) + (await kb(without(p), holder, { sd_hash: base64UrlEncode(random.bytes(32)) })));
      add('wrong-nonce', without(p) + (await kb(without(p), holder, { nonce: 'other' })));
      add('wrong-aud', without(p) + (await kb(without(p), holder, { aud: 'other' })));
      add('kb-by-other-key', without(p) + (await kb(without(p), nobleSigner(random.bytes(32)))));
      const [h, pl] = head.split('.');
      add('tampered-issuer-signature', `${h}.${pl}.${base64UrlEncode(random.bytes(64))}~${segs.slice(1).join('~')}`);
      add('padding', `${h}.${pl}.${head.split('.')[2]}=~${segs.slice(1).join('~')}`);
      add('non-canonical-issuer-signature', `${h}.${pl}.${nonCanonical(head.split('.')[2]!)}~${segs.slice(1).join('~')}`);
      const kbParts = segs.at(-1)!.split('.');
      add('padding', `${without(p)}${kbParts[0]}.${kbParts[1]}.${kbParts[2]}=`);
      add('non-canonical-kb-signature', `${without(p)}${kbParts[0]}.${kbParts[1]}.${nonCanonical(kbParts[2]!)}`);
      add('empty-disclosure', `${head}~~${segs.slice(1).join('~')}`);
      add('trailing-tilde', `${p}~`);
      add('whitespace', `${p.slice(0, 40)} ${p.slice(40)}`);
      add('whitespace', `${p}\n`);
      add('no-kb', without(p));
    }
  }
  // Classes built by hand.
  const ok = (d: string[], patch?: Record<string, unknown>, topLevel?: string[]) => crafted(issuer, holder, d, patch, topLevel);
  const withKb = async (sdJwt: string) => sdJwt + (await kb(sdJwt, holder));
  for (let i = 0; i < 5; i++) {
    const iatOnly = await ok([b64json([salt(), 'iat', 1_700_000_000]), b64json([salt(), 'ho_ten', 'A'])], { iat: undefined });
    add('iat-only-via-disclosure', await withKb(iatOnly));
    add('too-many-disclosures', await withKb(await ok(Array.from({ length: 51 }, (_, k) => b64json([salt(), `c${k}`, k])))));
    add('too-large', await withKb(await ok([b64json([salt(), 'blob', 'x'.repeat(14_000)])])));
    const inner = b64json([salt(), 'duong', 'Hai Bà Trưng']);
    const outer = b64json([salt(), 'dia_chi', { _sd: [await disclosureDigest(inner, nobleHasher)] }]);
    add('nested-disclosure', await withKb(await ok([outer, inner], {}, [outer])));
    const element = b64json([salt(), 'VN']);
    add('array-element-disclosure', await withKb(await ok([element], { quoc_tich: [{ '...': await disclosureDigest(element, nobleHasher) }] }, [])));
    add('valid-spaced-json', await withKb(await ok([b64json([salt(), 'ho_ten', 'Nguyễn'], true)])));
    // RFC 9901 shape rules, checked in step 1 even without disclosures (stored mode).
    const d0 = b64json([salt(), 'ho_ten', 'A']);
    const digest = await disclosureDigest(d0, nobleHasher);
    add('sd-duplicate-digest', await ok([d0], { _sd: [digest, digest] }, []), 'stored');
    add('sd-alg-wrong-no-disclosures', await ok([], { _sd: [await disclosureDigest(salt(), nobleHasher)], _sd_alg: 'sha-512' }, []), 'stored');
    add('sd-nested-undisclosed', await ok([], { dia_chi: { _sd: [digest] } }, []), 'stored');
  }
  return cases;
}

test('differential: our verification agrees with SdJwtVcInstance.verify', async (t) => {
  const cases = await corpus();
  assert.ok(cases.length >= 300, `corpus has ${cases.length} cases`);
  const stats: Record<string, { n: number; bothAccept: number; bothReject: number; stricter: number }> = {};
  const disagreements: string[] = [];
  for (const c of cases) {
    const [lib, our] = await Promise.all([library(c), ours(c)]);
    const kind = c.kind;
    const s = (stats[kind] ??= { n: 0, bothAccept: 0, bothReject: 0, stricter: 0 });
    s.n++;
    const failed = our.checks.find((x) => !x.ok && !x.skipped);
    if (our.ok && !lib.ok) disagreements.push(`${kind}: we ACCEPT, library rejects (${lib.error})`);
    else if (!our.ok && lib.ok) {
      if (STRICTER[kind] !== undefined && failed?.code === STRICTER[kind]) s.stricter++;
      else disagreements.push(`${kind}: we reject (${failed?.id} ${failed?.code}), library accepts`);
    } else if (our.ok && lib.ok) {
      s.bothAccept++;
      const expected = Object.fromEntries(Object.entries(lib.claims).filter(([k]) => !METADATA_CLAIMS.includes(k) && k !== '_sd' && k !== '_sd_alg'));
      assert.deepEqual(our.credential?.claims, expected, `${kind}: claims`);
      const segs = parts(c.compact);
      for (const d of segs.slice(1, -1)) {
        const hash = { hasher: (x: string | ArrayBuffer) => nobleHasher.sha256(typeof x === 'string' ? utf8Encode(x) : new Uint8Array(x)), alg: 'sha-256' };
        const libDigest = await (await Disclosure.fromEncode(d, hash)).digest(hash);
        assert.equal(await disclosureDigest(d, nobleHasher), libDigest, `${kind}: digest`);
      }
      if (c.mode === 'presentation') {
        const kbPayload = JSON.parse(utf8Decode(base64UrlDecode(segs.at(-1)!.split('.')[1]!))) as { sd_hash: string };
        assert.equal(await sdHashOf(c.compact.slice(0, c.compact.lastIndexOf('~') + 1), nobleHasher), kbPayload.sd_hash, `${kind}: sd_hash`);
      }
    } else s.bothReject++;
  }
  t.diagnostic(`cases: ${cases.length}`);
  for (const [kind, s] of Object.entries(stats).sort()) t.diagnostic(`${kind.padEnd(28)} n=${s.n} bothAccept=${s.bothAccept} bothReject=${s.bothReject} oursStricter=${s.stricter}`);
  assert.deepEqual(disagreements, []);
  // Positive classes really are accepted by both, so the comparison is not vacuous.
  for (const kind of ['valid', 'valid-stored', 'reorder-before-kb', 'drop-before-kb', 'valid-spaced-json']) assert.equal(stats[kind]!.bothAccept, stats[kind]!.n, kind);
  // Every documented stricter class really is one (the library accepts it), so the list holds no dead entries.
  for (const kind of Object.keys(STRICTER)) assert.equal(stats[kind]!.stricter, stats[kind]!.n, `${kind}: stricter in every case`);
});

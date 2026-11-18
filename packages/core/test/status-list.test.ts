// Status list model (ADR-0013 sections 1-2) against the Token Status List draft 21 section 4.1
// example, and every rule of verifyStatusListToken (docs/architecture.md section 7).
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { deflateRawSync, deflateSync } from 'node:zlib';
import { StatusList as LibraryStatusList } from '@owf/token-status-list';
import {
  base64UrlEncode, createStatusList, createStatusListToken, decodeStatusList, STATUS_LIST_BYTES, statusListFromBytes,
  verifyStatusListToken, type StatusValue, type TrustRegistry,
} from '@identra/sdk-core';
import { webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { NOW } from './helpers/pki.js';
import { ORG, otherOrgStatus, servedRegistry, statusSigner } from './helpers/lists.js';
import { ISS, issuerSigner, NOW_S, rawJws, validator } from './helpers/sdjwt.js';

const URI = `${ISS}/status/1`;
const lst = (raw: Uint8Array) => base64UrlEncode(deflateSync(raw));
const rawWith = (head: number[], size = STATUS_LIST_BYTES) => {
  const raw = new Uint8Array(size);
  raw.set(head);
  return raw;
};

describe('bit layout: Token Status List section 4.1, 2-bit example', () => {
  // status[0..11] = 1 2 0 3 0 1 0 1 1 2 3 3 -> bytes C9 44 F9 -> lst eNo76fITAAPfAgc
  const SPEC = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];

  test('the library reads the specification vector as specified', () => {
    const l = LibraryStatusList.decompressStatusListFromBytes(Buffer.from('eNo76fITAAPfAgc', 'base64url'), 2);
    assert.deepEqual(SPEC.map((_, i) => l.getStatus(i)), SPEC);
    assert.equal(Buffer.from(new LibraryStatusList(SPEC, 2).compressStatusListToBytes()).toString('base64url'), 'eNo76fITAAPfAgc');
  });

  test('our list packs the 0-2 entries of the example into the example bytes (3 is not an Identra value)', () => {
    const list = createStatusList();
    SPEC.forEach((v, i) => v !== 3 && list.setStatus(i, v as StatusValue));
    // C9 44 F9 with the pairs holding 3 (entry 3: bits 6-7 of byte 0; entries 10, 11: bits 4-7 of byte 2) cleared.
    assert.deepEqual([...list.toBytes().subarray(0, 4)], [0x09, 0x44, 0x09, 0x00]);
    assert.equal(list.toBytes().length, STATUS_LIST_BYTES);
  });

  test('a full-size list compressed by an independent zlib decodes in specification order', () => {
    const list = decodeStatusList({ bits: 2, lst: lst(rawWith([0x09, 0x44, 0x09])) });
    assert.deepEqual(SPEC.map((_, i) => list.getStatus(i)), SPEC.map((v) => (v === 3 ? 0 : v)));
    assert.equal(list.getStatus(131_071), 0);
  });

  test('the value 3 of the example is refused, from bytes and from lst', () => {
    assert.throws(() => statusListFromBytes(rawWith([0xc9, 0x44, 0xf9])), /entry 3 has the value 3/);
    assert.throws(() => decodeStatusList({ bits: 2, lst: lst(rawWith([0, 0, 0, 0xc0])) }), /entry 15 has the value 3/);
  });
});

describe('model', () => {
  test('a new list has 131 072 valid entries; set / get / round trips', () => {
    const list = createStatusList();
    assert.equal(list.getStatus(0), 0);
    assert.equal(list.getStatus(131_071), 0);
    const set: [number, StatusValue][] = [[0, 1], [1, 2], [77_777, 1], [131_071, 2], [131_070, 1]];
    for (const [i, v] of set) list.setStatus(i, v);
    list.setStatus(1, 0);
    set[1] = [1, 0];
    const fromLst = decodeStatusList(list.encode());
    const fromBytes = statusListFromBytes(list.toBytes());
    for (const [i, v] of set) {
      assert.equal(list.getStatus(i), v);
      assert.equal(fromLst.getStatus(i), v);
      assert.equal(fromBytes.getStatus(i), v);
    }
    assert.deepEqual(fromBytes.toBytes(), list.toBytes());
    assert.equal(list.encode().bits, 2);
    assert.match(list.encode().lst, /^[A-Za-z0-9_-]+$/);
  });

  test('strict range checks', () => {
    const list = createStatusList();
    for (const idx of [-1, 131_072, 1.5, Number.NaN, '1', undefined]) {
      assert.throws(() => list.getStatus(idx as number), RangeError);
      assert.throws(() => list.setStatus(idx as number, 0), RangeError);
    }
    for (const v of [3, -1, 1.5, '1', null, 7]) assert.throws(() => list.setStatus(0, v as StatusValue), RangeError);
    assert.equal(list.getStatus(0), 0, 'a refused value leaves the entry unchanged');
    for (const bytes of [new Uint8Array(STATUS_LIST_BYTES - 1), new Uint8Array(STATUS_LIST_BYTES + 1), [...new Uint8Array(STATUS_LIST_BYTES)]]) {
      assert.throws(() => statusListFromBytes(bytes as Uint8Array), TypeError);
    }
  });

  test('decode rejections', () => {
    const good = lst(new Uint8Array(STATUS_LIST_BYTES));
    assert.equal(decodeStatusList({ bits: 2, lst: good }).getStatus(5), 0);
    const bad: [string, unknown, RegExp][] = [
      ['bits 1', { bits: 1, lst: good }, /bits must be 2/],
      ['bits 8', { bits: 8, lst: good }, /bits must be 2/],
      ['bits "2"', { bits: '2', lst: good }, /bits must be 2/],
      ['no lst', { bits: 2 }, /lst must be/],
      ['not an object', [2, good], /not an object/],
      ['one byte short', { bits: 2, lst: lst(new Uint8Array(STATUS_LIST_BYTES - 1)) }, /exactly 32768 bytes/],
      ['one byte long', { bits: 2, lst: lst(new Uint8Array(STATUS_LIST_BYTES + 1)) }, /ZLIB stream of at most 32768/],
      ['not base64url', { bits: 2, lst: `${good}=` }, /ZLIB stream/],
      ['raw DEFLATE without the ZLIB wrapper', { bits: 2, lst: base64UrlEncode(deflateRawSync(new Uint8Array(STATUS_LIST_BYTES))) }, /ZLIB stream/],
      ['bytes after the ZLIB stream', { bits: 2, lst: base64UrlEncode(Buffer.concat([deflateSync(new Uint8Array(STATUS_LIST_BYTES)), Buffer.from([0])])) }, /ZLIB stream/],
    ];
    for (const [name, claim, message] of bad) assert.throws(() => decodeStatusList(claim), message, name);
  });

  test('zip bomb: 64 MiB of zeros in a small lst is refused without inflating it', () => {
    const bomb = lst(new Uint8Array(64 * 1024 * 1024));
    assert.ok(bomb.length < 100_000);
    const before = process.memoryUsage().arrayBuffers;
    const t0 = performance.now();
    assert.throws(() => decodeStatusList({ bits: 2, lst: bomb }), /at most 32768/);
    assert.ok(performance.now() - t0 < 500, 'stops early');
    assert.ok(process.memoryUsage().arrayBuffers - before < 16 * 1024 * 1024, 'did not inflate the bomb');
  });
});

describe('verifyStatusListToken: one negative test per rule', async () => {
  const signer = await statusSigner();
  const list = createStatusList();
  list.setStatus(42, 1);
  list.setStatus(43, 2);
  const { registry } = await servedRegistry();
  const opts = (o: Partial<Parameters<typeof verifyStatusListToken>[1]> = {}) => ({
    uri: URI, issuer: { maToChuc: ORG.truongMau }, chainValidator: validator, trustRegistry: registry as TrustRegistry, verifier: webCryptoVerifier, now: NOW, ...o,
  });
  const token = (o: Partial<Parameters<typeof createStatusListToken>[0]> = {}) => createStatusListToken({ list, uri: URI, signer, now: NOW, ...o });
  const payload = (o: Record<string, unknown> = {}) => ({ sub: URI, iat: NOW_S, exp: NOW_S + 86_400, ttl: 900, status_list: list.encode(), ...o });
  const header = (o: Record<string, unknown> = {}) => ({ alg: 'ES256', typ: 'statuslist+jwt', x5c: signer.x5c, ...o });
  const expectReason = async (t: unknown, reason: string, detail?: RegExp, o = {}) => {
    const r = await verifyStatusListToken(t, opts(o));
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.equal(r.reason, reason, r.detail);
      if (detail) assert.match(r.detail, detail);
    }
  };

  test('a good token: header, payload and the statuses', async () => {
    const t = await token();
    const [h, p] = t.split('.').slice(0, 2).map((x) => JSON.parse(Buffer.from(x, 'base64url').toString()));
    assert.deepEqual(h, { alg: 'ES256', typ: 'statuslist+jwt', x5c: signer.x5c });
    assert.deepEqual(p, { sub: URI, iat: NOW_S, exp: NOW_S + 86_400, ttl: 900, status_list: list.encode() });
    const r = await verifyStatusListToken(t, opts());
    assert.ok(r.ok);
    assert.deepEqual([r.list.getStatus(41), r.list.getStatus(42), r.list.getStatus(43)], [0, 1, 2]);
    assert.deepEqual({ iat: r.iat, exp: r.exp, ttl: r.ttl, maToChuc: r.signer.maToChuc }, { iat: NOW_S, exp: NOW_S + 86_400, ttl: 900, maToChuc: ORG.truongMau });
  });
  test('size cap before parsing', () => expectReason('a'.repeat(128 * 1024 + 1), 'too_large'));
  test('not a JWS', () => expectReason('a.b', 'malformed'));
  test('wrong typ', async () => {
    await expectReason(await rawJws(header({ typ: 'jwt' }), payload(), signer), 'typ');
    await expectReason(await rawJws(header({ typ: undefined }), payload(), signer), 'typ');
  });
  test('HS256 and none', async () => {
    await expectReason(await rawJws(header({ alg: 'HS256' }), payload(), signer), 'alg');
    await expectReason(await rawJws(header({ alg: 'none' }), payload(), signer), 'alg');
  });
  test('a chain of another PKI', async () => {
    const evil = await issuerSigner('evil-vc', 'evil-issuing');
    await expectReason(await rawJws(header({ x5c: evil.x5c }), payload(), evil), 'chain', /CERT_CHAIN_UNTRUSTED/);
  });
  test('a signature that does not verify', async () => expectReason((await token()).slice(0, -4) + 'AAAA', 'signature'));
  test('signed by the vc certificate of the same organisation', async () => {
    const vc = await issuerSigner();
    await expectReason(await token({ signer: vc }), 'not_trusted', /purpose is not status/);
  });
  test('signed by the status certificate of ANOTHER trusted organisation', async () => {
    const { signer: other } = await otherOrgStatus();
    await expectReason(await token({ signer: other }), 'not_trusted', /another organisation/);
    // ... which is accepted for that organisation's own credentials.
    assert.equal((await verifyStatusListToken(await token({ signer: other }), opts({ issuer: { maToChuc: ORG.nhaSanXuat } }))).ok, true);
  });
  test('signer absent from the trust list', async () => {
    const unlisted = await issuerSigner('utf8');
    await expectReason(await token({ signer: unlisted }), 'not_trusted', /not in the trust list/);
  });
  test('organizationIdentifier of the certificate differs from the trust list entry', async () => {
    const lying: TrustRegistry = { lookup: async () => ({ maToChuc: ORG.nhaSanXuat, ten: 'x', mucDich: 'status' }) };
    await expectReason(await token(), 'not_trusted', /organizationIdentifier differs/, { trustRegistry: lying, issuer: { maToChuc: ORG.nhaSanXuat } });
  });
  test('trust list unavailable', async () => {
    const { registry: down } = await servedRegistry('not a token');
    await expectReason(await token(), 'trust_list_unavailable', undefined, { trustRegistry: down });
    const broken: TrustRegistry = { lookup: async () => { throw new Error('boom'); } };
    await expectReason(await token(), 'not_trusted', /trust registry failed/, { trustRegistry: broken });
  });
  test('sub is not the uri', async () => {
    await expectReason(await token(), 'claims', /sub/, { uri: `${ISS}/status/2` });
    await expectReason(await rawJws(header(), payload({ sub: undefined }), signer), 'claims', /sub/);
  });
  test('expired (60 s skew)', async () => {
    const t = await token({ lifetimeSeconds: 3600 });
    assert.equal((await verifyStatusListToken(t, opts({ now: new Date(NOW.getTime() + 3659_000) }))).ok, true);
    await expectReason(t, 'expired', undefined, { now: new Date(NOW.getTime() + 3660_000) });
  });
  test('iat in the future (60 s skew)', async () => {
    assert.equal((await verifyStatusListToken(await token({ now: new Date(NOW.getTime() + 60_000) }), opts())).ok, true);
    await expectReason(await token({ now: new Date(NOW.getTime() + 61_000) }), 'not_yet_valid');
  });
  test('missing exp, missing iat, bad ttl', async () => {
    await expectReason(await rawJws(header(), payload({ exp: undefined }), signer), 'claims', /exp is missing/);
    await expectReason(await rawJws(header(), payload({ iat: '1' }), signer), 'claims', /iat is missing/);
    for (const ttl of [0, -1, 1.5, '900']) await expectReason(await rawJws(header(), payload({ ttl }), signer), 'claims', /ttl/);
    assert.equal((await verifyStatusListToken(await rawJws(header(), payload({ ttl: undefined }), signer), opts())).ok, true, 'ttl is optional');
  });
  test('tampered lst', async () => {
    const [h, , s] = (await token()).split('.');
    const other = createStatusList();
    const p = base64UrlEncode(Buffer.from(JSON.stringify(payload({ status_list: other.encode() }))));
    await expectReason(`${h}.${p}.${s}`, 'signature');
  });
  test('a signed but malformed status_list', async () => {
    await expectReason(await rawJws(header(), payload({ status_list: { bits: 1, lst: list.encode().lst } }), signer), 'claims', /bits must be 2/);
  });
  test('programmer errors throw', async () => {
    await assert.rejects(verifyStatusListToken(await token(), opts({ issuer: { maToChuc: '' } })), TypeError);
    await assert.rejects(createStatusListToken({ list, uri: 'http://x/status/1', signer, now: NOW }), TypeError);
    await assert.rejects(createStatusListToken({ list, uri: URI, signer: { ...signer, x5c: [signer.x5c![0]!] }, now: NOW }), TypeError);
    await assert.rejects(createStatusListToken({ list, uri: URI, signer, now: NOW, ttlSeconds: 0 }), TypeError);
  });
});

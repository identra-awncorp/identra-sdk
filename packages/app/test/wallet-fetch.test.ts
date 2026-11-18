// guardFetch, the one wrapper of the app's fetch: https only, allow-list, timeout, no redirect, size cap.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { HttpFetch } from '@identra/sdk-core';
import { guardFetch, WalletFetchError } from '../dist/wallet/fetch.js';

const answer = (status: number, body = '', headers: Record<string, string> = {}): HttpFetch => async () => ({
  status, headers: { get: (n: string) => headers[n.toLowerCase()] ?? null }, text: async () => body,
});
const guarded = (inner: HttpFetch, timeoutMs = 1000) => guardFetch(inner, { allow: (_u, o) => o === 'https://a.example', maxBytes: 10, timeoutMs });
const code = (p: Promise<unknown>) => p.then(() => 'resolved', (e: unknown) => (e instanceof WalletFetchError ? e.code : `other: ${String(e)}`));

test('refuses non-https, userinfo, unparseable and disallowed URLs without calling the app fetch', async () => {
  let calls = 0;
  const f = guarded(async () => (calls++, { status: 200, headers: { get: () => null }, text: async () => '' }));
  for (const url of ['http://a.example/x', 'https://u:p@a.example/x', 'https://b.example/x', 'not a url', 'https://a.example.evil.example/x']) {
    assert.equal(await code(f(url)), 'URL_NOT_ALLOWED', url);
  }
  assert.equal(calls, 0);
  assert.equal(await code(f('https://a.example/x')), 'resolved');
});

test('a redirect and an oversized body (declared or actual) are ISSUER_ERROR; a failing app fetch is NETWORK_ERROR', async () => {
  assert.equal(await code(guarded(answer(302, '', { location: 'https://evil.example/' }))('https://a.example/x')), 'ISSUER_ERROR');
  assert.equal(await code(guarded(answer(200, 'small', { 'content-length': '11' }))('https://a.example/x')), 'ISSUER_ERROR');
  assert.equal(await code(guarded(answer(200, '12345678901'))('https://a.example/x')), 'ISSUER_ERROR');
  assert.equal(await code(guarded(async () => Promise.reject(new TypeError('fetch failed')))('https://a.example/x')), 'NETWORK_ERROR');
  const brokenBody: HttpFetch = async () => ({ status: 200, headers: { get: () => null }, text: () => Promise.reject(new Error('reset')) });
  assert.equal(await code(guarded(brokenBody)('https://a.example/x')), 'NETWORK_ERROR');
  const ok = await guarded(answer(404, 'not found'))('https://a.example/x');
  assert.deepEqual([ok.status, await ok.text()], [404, 'not found']);
});

test('the timeout is enforced here and passed to the app fetch, capped by the guard', async () => {
  let seen: number | undefined;
  const hanging: HttpFetch = (_url, init) => ((seen = init?.timeoutMs), new Promise(() => {}));
  const started = Date.now();
  assert.equal(await code(guarded(hanging, 50)('https://a.example/x', { timeoutMs: 60_000 })), 'NETWORK_ERROR');
  assert.equal(seen, 50);
  assert.ok(Date.now() - started < 1000);
  const slowBody: HttpFetch = async () => ({ status: 200, headers: { get: () => null }, text: () => new Promise(() => {}) });
  assert.equal(await code(guarded(slowBody, 50)('https://a.example/x')), 'NETWORK_ERROR');
});

test('maxBytes: per call, capped by the guard, 256 KB by default, and passed to the app fetch', async () => {
  const seen: (number | undefined)[] = [];
  const recording = (body: string): HttpFetch => async (_u, init) => (seen.push(init?.maxBytes), { status: 200, headers: { get: () => null }, text: async () => body });
  const open = (inner: HttpFetch, maxBytes?: number) => guardFetch(inner, { allow: () => true, timeoutMs: 1000, ...(maxBytes !== undefined ? { maxBytes } : {}) });
  assert.equal(await code(open(recording('x'.repeat(262_145)))('https://a.example/x')), 'ISSUER_ERROR');
  assert.equal(await code(open(recording('x'.repeat(262_144)))('https://a.example/x')), 'resolved');
  assert.equal(await code(open(recording('12345'))('https://a.example/x', { maxBytes: 4 })), 'ISSUER_ERROR');
  assert.equal(await code(open(recording('12345'), 4)('https://a.example/x', { maxBytes: 100 })), 'ISSUER_ERROR', 'a call cannot raise the ceiling');
  assert.deepEqual(seen, [262_144, 262_144, 4, 4]);
});

// createMappedFetch: only exact canonical origins are redirected; everything else is untouched.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createMappedFetch, type HttpFetch } from '@identra/sdk-core';

test('maps exact-origin prefixes only and passes init through', async () => {
  const seen: [string, unknown][] = [];
  const inner: HttpFetch = async (url, init) => (seen.push([url, init]), { status: 200, headers: { get: () => null }, text: async () => '' });
  const f = createMappedFetch(inner, { 'https://api-identra.awncorp.vn': 'http://127.0.0.1:47610' });
  const init = { timeoutMs: 5000 };
  const cases: [string, string][] = [
    ['https://api-identra.awncorp.vn/issuers/truong-mau/status/1', 'http://127.0.0.1:47610/issuers/truong-mau/status/1'],
    ['https://api-identra.awncorp.vn', 'http://127.0.0.1:47610'],
    ['https://api-identra.awncorp.vn?x=1', 'http://127.0.0.1:47610?x=1'],
    ['https://api-identra.awncorp.vn.evil.example/trust-list', 'https://api-identra.awncorp.vn.evil.example/trust-list'],
    ['https://api-identra.awncorp.vn:8443/trust-list', 'https://api-identra.awncorp.vn:8443/trust-list'],
    ['http://api-identra.awncorp.vn/trust-list', 'http://api-identra.awncorp.vn/trust-list'],
    ['https://identra.awncorp.vn/x', 'https://identra.awncorp.vn/x'],
  ];
  for (const [url] of cases) await f(url, init);
  assert.deepEqual(seen, cases.map(([, to]) => [to, init]));
});

test('refuses maps that are not plain origins', () => {
  const inner: HttpFetch = async () => ({ status: 200, headers: { get: () => null }, text: async () => '' });
  for (const map of [
    { 'http://api-identra.awncorp.vn': 'http://127.0.0.1:4000' },
    { 'https://api-identra.awncorp.vn/': 'http://127.0.0.1:4000' },
    { 'https://api-identra.awncorp.vn': 'http://127.0.0.1:4000/base' },
    { 'https://api-identra.awncorp.vn': 'ftp://127.0.0.1' },
  ]) {
    assert.throws(() => createMappedFetch(inner, map), TypeError, JSON.stringify(map));
  }
});

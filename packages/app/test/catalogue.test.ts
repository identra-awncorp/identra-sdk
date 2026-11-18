// Backup catalogue (ADR-0009 section 5, ADR-0014 section 2).
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { buildCatalogue, diffCatalogue, MAX_CATALOGUE_LENGTH, parseCatalogue, serializeCatalogue, type CredentialRow } from '@identra/sdk-app';

const DIPLOMA = 'https://identra.awncorp.vn/vct/bang-tot-nghiep/v1';
const EVENT = 'https://identra.awncorp.vn/vct/su-kien-vong-doi/v1';
const SCHOOL = 'https://api-identra.awncorp.vn/issuers/truong-mau';
const FACTORY = 'https://api-identra.awncorp.vn/issuers/nha-may-mau';

const row = (id: string, vct: string, issuer: string): CredentialRow => ({
  id,
  vct,
  issuer,
  key_id: `key-${id}`,
  ciphertext: 'AQ-secret-ciphertext',
  status_cache: 'valid',
  status_checked_at: '2026-11-19T08:00:00.000Z',
  created_at: '2026-11-19T07:00:00.000Z',
});

describe('catalogue', () => {
  test('contains only vct and issuer, one item per document, sorted', () => {
    // Ten batch copies of the diploma (ADR-0014 section 3) and one event credential.
    const rows = [row('e1', EVENT, FACTORY), ...Array.from({ length: 10 }, (_, i) => row(`d${i}`, DIPLOMA, SCHOOL))];
    const catalogue = buildCatalogue(rows);
    assert.deepEqual(catalogue, {
      version: 1,
      items: [
        { vct: DIPLOMA, issuer: SCHOOL },
        { vct: EVENT, issuer: FACTORY },
      ],
    });
    const text = serializeCatalogue(catalogue);
    for (const leaked of ['key-', 'AQ-secret', '2026', 'd0', 'e1', 'valid']) assert.equal(text.includes(leaked), false, leaked);
    assert.deepEqual(parseCatalogue(text), catalogue);
  });

  test('serialize drops anything extra an item object carries', () => {
    const smuggled = { version: 1 as const, items: [{ vct: DIPLOMA, issuer: SCHOOL, claims: { ho_ten: 'x' } }] };
    assert.equal(serializeCatalogue(smuggled), `{"version":1,"items":[{"vct":"${DIPLOMA}","issuer":"${SCHOOL}"}]}`);
  });

  test('parse rejects extra fields, wrong types, duplicates and oversize input', () => {
    const ok = { version: 1, items: [{ vct: DIPLOMA, issuer: SCHOOL }] };
    const bad: unknown[] = [
      { ...ok, extra: true },
      { ...ok, version: 2 },
      { items: ok.items },
      { version: 1, items: [{ vct: DIPLOMA, issuer: SCHOOL, key_id: 'k' }] },
      { version: 1, items: [{ vct: DIPLOMA }] },
      { version: 1, items: [{ vct: DIPLOMA, issuer: 7 }] },
      { version: 1, items: [{ vct: '', issuer: SCHOOL }] },
      { version: 1, items: [{ vct: 'x'.repeat(2049), issuer: SCHOOL }] },
      { version: 1, items: [ok.items[0], ok.items[0]] },
      { version: 1, items: [['vct', 'issuer']] },
      { version: 1, items: {} },
      [ok],
      null,
    ];
    assert.deepEqual(parseCatalogue(JSON.stringify(ok)), ok);
    for (const b of bad) assert.equal(parseCatalogue(JSON.stringify(b)), null, JSON.stringify(b));
    assert.equal(parseCatalogue('{not json'), null);
    assert.equal(parseCatalogue(42 as unknown as string), null);
    const huge = JSON.stringify({ version: 1, items: [{ vct: DIPLOMA, issuer: SCHOOL + ' '.repeat(MAX_CATALOGUE_LENGTH) }] });
    assert.equal(parseCatalogue(huge), null);
    const many = JSON.stringify({ version: 1, items: Array.from({ length: 501 }, (_, i) => ({ vct: `v${i}`, issuer: 'i' })) });
    assert.ok(many.length < MAX_CATALOGUE_LENGTH);
    assert.equal(parseCatalogue(many), null);
  });

  test('diff lists the documents to ask for again on a new phone', () => {
    const catalogue = buildCatalogue([row('d', DIPLOMA, SCHOOL), row('e', EVENT, FACTORY)]);
    assert.deepEqual(diffCatalogue(catalogue, []), catalogue.items);
    assert.deepEqual(diffCatalogue(catalogue, [row('x', EVENT, FACTORY)]), [{ vct: DIPLOMA, issuer: SCHOOL }]);
    assert.deepEqual(diffCatalogue(catalogue, [row('x', DIPLOMA, FACTORY)]).length, 2);
    assert.deepEqual(diffCatalogue(catalogue, [row('a', DIPLOMA, SCHOOL), row('b', EVENT, FACTORY)]), []);
  });

  test('build refuses rows without vct or issuer', () => {
    assert.throws(() => buildCatalogue([{ vct: '', issuer: SCHOOL }]), TypeError);
  });
});

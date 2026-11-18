// GS1 identifiers: check digits (General Specifications 7.9.1), AI (21) set 82 (figure 7.11-1),
// element strings and the strict GS1 Digital Link path.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { formatDigitalLinkPath, formatProductCode, gs1CheckDigit, issueProductEvent, parseDigitalLinkPath, parseProductCode } from '@identra/sdk-core';
import { issuerContext, STATUS } from './helpers/sdjwt.js';

const SAMPLE = '09520123456788';
const SET82 = `!"%&'()*+,-./0123456789:;<=>?ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz`;

test('check digit: the worked example of GS1 General Specifications figure 7.9.1-2 and known GTINs', () => {
  // Figure 7.9.1-2: 18-digit field 3761042500212345 6 → sum 101 → check digit 9.
  assert.equal(gs1CheckDigit('37610425002123456'), 9);
  assert.equal(gs1CheckDigit('400638133393'), 1); // EAN-13 4006381333931
  assert.equal(gs1CheckDigit('0952012345678'), 8); // ADR-0012 sample: 0·3+9+5·3+2+0·3+1+2·3+3+4·3+5+6·3+7+8·3 = 102 → 8
  assert.equal(gs1CheckDigit('0000000000000'), 0);
  assert.throws(() => gs1CheckDigit('12a'), TypeError);
  assert.throws(() => gs1CheckDigit(''), TypeError);
});

test('set 82 has exactly 82 characters, none of them a space', () => {
  assert.equal(new Set(SET82).size, 82);
  assert.equal(parseProductCode(`(01)${SAMPLE}(21)${SET82.slice(0, 20)}`)?.serial, SET82.slice(0, 20));
});

test('element string: valid forms and every refusal', () => {
  assert.deepEqual(parseProductCode(`(01)${SAMPLE}(21)SN-0001`), { gtin: SAMPLE, serial: 'SN-0001' });
  assert.deepEqual(parseProductCode(`(01)${SAMPLE}(21)A(21)B`), { gtin: SAMPLE, serial: 'A(21)B' }); // AI 21 is last: the rest is the serial
  assert.equal(formatProductCode(SAMPLE, 'x/y?'), `(01)${SAMPLE}(21)x/y?`);
  for (const bad of [
    `(01)09520123456789(21)A`, // wrong check digit
    `(01)0952012345678(21)A`, // 13 digits
    `(01)${SAMPLE}(21)`, // empty serial
    `(01)${SAMPLE}(21)${'A'.repeat(21)}`,
    `(01)${SAMPLE}(21)A B`, // space
    `(01)${SAMPLE}(21)A#`, '(01)' + SAMPLE + '(21)A~', `(01)${SAMPLE}(21)Đ`,
    `(01)${SAMPLE}(21)%41`, // looks percent-encoded
    `(01)${SAMPLE}`, `(21)A(01)${SAMPLE}`, `(01)${SAMPLE}(10)A`, ` (01)${SAMPLE}(21)A`, `(01)${SAMPLE}(21)A\n`,
    `(01)${SAMPLE}(21)A`.repeat(3),
  ]) assert.equal(parseProductCode(bad), null, bad);
  assert.equal(parseProductCode(undefined), null);
  assert.throws(() => formatProductCode('09520123456789', 'A'), TypeError);
  assert.throws(() => formatProductCode(SAMPLE, ''), TypeError);
});

test('Digital Link path: formats and parses, percent-encoding exactly the non-raw characters', () => {
  assert.equal(formatDigitalLinkPath(SAMPLE, 'SN-0001'), `/01/${SAMPLE}/21/SN-0001`);
  assert.equal(formatDigitalLinkPath(SAMPLE, 'a/b?c#'.replace('#', '%')), `/01/${SAMPLE}/21/a%2Fb%3Fc%25`);
  assert.equal(formatDigitalLinkPath(SAMPLE, '"!&'), `/01/${SAMPLE}/21/%22%21%26`);
  for (let i = 0; i < SET82.length; i += 20) {
    const serial = SET82.slice(i, i + 20);
    assert.deepEqual(parseDigitalLinkPath(formatDigitalLinkPath(SAMPLE, serial)), { gtin: SAMPLE, serial }, serial);
  }
  assert.deepEqual(parseDigitalLinkPath(`/01/${SAMPLE}/21/a%2fb`), { gtin: SAMPLE, serial: 'a/b' }); // lower-case hex
  assert.deepEqual(parseDigitalLinkPath(`/01/${SAMPLE}/21/50%25`), { gtin: SAMPLE, serial: '50%' });
  assert.deepEqual(parseDigitalLinkPath(`/01/${SAMPLE}/21/${'%2F'.repeat(20)}`)?.serial, '/'.repeat(20));
});

test('Digital Link path: hostile and non-canonical paths are refused', () => {
  for (const bad of [
    `/01/09520123456789/21/A`, // check digit
    `/01/9520123456788/21/A`, // 13 digits (GTIN-13 not padded)
    `/01/${SAMPLE}/21/`, `/01/${SAMPLE}`, `/01/${SAMPLE}/21`, `/01/${SAMPLE}/21/A/`, `/01/${SAMPLE}/21/A/10/L1`,
    `/01/${SAMPLE}/10/L1/21/A`, `/21/A/01/${SAMPLE}`, `01/${SAMPLE}/21/A`, `//01/${SAMPLE}/21/A`, `/01//${SAMPLE}/21/A`,
    `/01/${SAMPLE}/21/A?x=1`, `/01/${SAMPLE}/21/A#frag`, `/01/${SAMPLE}/21/A%23frag`, // %23 = '#', not in set 82
    `/01/${SAMPLE}/21/A%2541`, // double encoding: decodes to "A%41"
    `/01/${SAMPLE}/21/%41`, // an unreserved character percent-encoded
    `/01/${SAMPLE}/21/A%2`, `/01/${SAMPLE}/21/A%zz`, `/01/${SAMPLE}/21/A%00`, `/01/${SAMPLE}/21/A%C3%90`, `/01/${SAMPLE}/21/A%20B`,
    `/01/${SAMPLE}/21/a!b`, `/01/${SAMPLE}/21/a:b`, `/01/${SAMPLE}/21/a(b)`, // raw where the syntax wants %-encoding
    `/01/${SAMPLE}/21/Đ`, `/01/${SAMPLE}/21/A B`, `/01/${SAMPLE}/21/A\\B`, `/01/${SAMPLE}/21/..`.replace('..', '%2E%2E'),
    `/01/${SAMPLE}/21/${'A'.repeat(21)}`, `/01/${SAMPLE}/21/${'%2F'.repeat(21)}`,
    `/01/${SAMPLE}/21/A`.repeat(2000),
    `https://identra.awncorp.vn/01/${SAMPLE}/21/A`, `/01/${SAMPLE}/21/A\n`, '',
  ]) assert.equal(parseDigitalLinkPath(bad), null, bad.slice(0, 80));
  assert.equal(parseDigitalLinkPath(null), null);
  // `.` and `..` are dot segments to every URL parser (also as %2E): refused as serials everywhere.
  for (const dots of ['.', '..']) {
    assert.equal(parseDigitalLinkPath(`/01/${SAMPLE}/21/${dots}`), null);
    assert.equal(parseProductCode(`(01)${SAMPLE}(21)${dots}`), null);
  }
  assert.deepEqual(parseDigitalLinkPath(`/01/${SAMPLE}/21/...`)?.serial, '...');
});

test('issueProductEvent refuses a ma_san_pham whose GTIN check digit is wrong or whose serial is outside set 82', async () => {
  const claims = { ma_san_pham: `(01)${SAMPLE}(21)SN-0001`, cong_doan: 'san_xuat' as const, thoi_diem: '2026-05-30T00:00:00Z', dia_diem: 'HN', mo_ta: 'lô 1' };
  const input = { ...(await issuerContext()), iss: 'https://api-identra.awncorp.vn/issuers/truong-mau', status: STATUS };
  assert.equal(typeof (await issueProductEvent({ ...input, claims })), 'string');
  for (const ma_san_pham of ['(01)09520123456789(21)SN-0001', `(01)${SAMPLE}(21)SN#1`, `(01)${SAMPLE}(21)SN 1`]) {
    await assert.rejects(issueProductEvent({ ...input, claims: { ...claims, ma_san_pham } }), /ma_san_pham must be a GS1 element string/);
  }
});

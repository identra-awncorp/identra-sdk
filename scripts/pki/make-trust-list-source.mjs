#!/usr/bin/env node
// Derives the trust-list source JSON ({ issuers, verifiers }, ADR-0015 section 6) for the DEMO
// organisations from a directory written by make-demo-pki.sh. Fingerprints are computed from the
// .cert.pem files, ma_to_chuc is read from each certificate's organizationIdentifier, validFrom is
// the latest notBefore and validUntil the earliest notAfter of the organisation's certificates
// (not "now": a client whose clock runs slightly behind would otherwise see the issuer as unknown).
// Needs the built SDK (npm run build). Usage: make-trust-list-source.mjs <demo-pki-dir> [--out file]
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { base64Decode, parseCertificate, validateTrustListContent, VCT } from '@identra/sdk-core';

// name, display name, certificate files and their purpose, scope.
const ORGANISATIONS = [
  { name: 'truong-mau', ten: 'Trường Mẫu (DEMO)', certs: { vc: 'vc', status: 'status' }, vct: [VCT.diploma] },
  { name: 'nha-san-xuat', ten: 'Nhà Sản Xuất (DEMO)', certs: { 'vc-product': 'vc', status: 'status' }, vct: [VCT.productEvent], cong_doan: ['san_xuat'] },
  { name: 'kiem-dinh', ten: 'Kiểm Định (DEMO)', certs: { 'vc-product': 'vc', status: 'status' }, vct: [VCT.productEvent], cong_doan: ['kiem_dinh'] },
  { name: 'phan-phoi', ten: 'Phân Phối (DEMO)', certs: { 'vc-product': 'vc', status: 'status' }, vct: [VCT.productEvent], cong_doan: ['phan_phoi'] },
  { name: 'nha-tuyen-dung-mau', ten: 'Nhà Tuyển Dụng Mẫu (DEMO)', certs: { request: 'request' }, verifier: true },
];

function usage() {
  console.error('usage: make-trust-list-source.mjs <demo-pki-dir> [--out file]');
  process.exit(2);
}

const args = process.argv.slice(2);
const dir = args[0];
if (!dir || dir.startsWith('--') || !(args.length === 1 || (args.length === 3 && args[1] === '--out'))) usage();
const out = args[2];

function certificate(path) {
  const m = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(readFileSync(path, 'utf8'));
  if (!m) throw new Error(`${path} holds no certificate`);
  const der = base64Decode(m[1].replace(/\s+/g, ''));
  return { cert: parseCertificate(der), sha256: createHash('sha256').update(der).digest('base64url') };
}

const issuers = [];
const verifiers = [];
for (const org of ORGANISATIONS) {
  const loaded = Object.entries(org.certs).map(([file, purpose]) => ({ ...certificate(join(dir, 'orgs', org.name, `${file}.cert.pem`)), purpose }));
  const ids = new Set(loaded.map((c) => c.cert.subject.organizationIdentifier));
  if (ids.size !== 1 || !loaded[0].cert.subject.organizationIdentifier) throw new Error(`${org.name}: certificates disagree on or lack organizationIdentifier`);
  const notBefore = new Date(Math.max(...loaded.map((c) => c.cert.notBefore.getTime())));
  const notAfter = new Date(Math.min(...loaded.map((c) => c.cert.notAfter.getTime())));
  const entry = {
    ma_to_chuc: loaded[0].cert.subject.organizationIdentifier,
    ten: org.ten,
    chung_thu: loaded.map((c) => ({ sha256: c.sha256, muc_dich: c.purpose })),
  };
  const validity = { validFrom: notBefore.toISOString(), validUntil: notAfter.toISOString() };
  if (org.verifier) verifiers.push({ ...entry, ...validity });
  else issuers.push({ ...entry, vct: org.vct, ...(org.cong_doan ? { cong_doan: org.cong_doan } : {}), ...validity });
}

const content = { issuers, verifiers };
const check = validateTrustListContent(content);
if (!check.ok) throw new Error(`generated trust list is invalid: ${check.detail}`);
const json = `${JSON.stringify(content, null, 2)}\n`;
if (out) writeFileSync(out, json);
else process.stdout.write(json);

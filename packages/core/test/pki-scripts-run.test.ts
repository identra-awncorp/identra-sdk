// scripts/pki: validation before any key, clean-up of failed runs, read-back, fresh serials,
// file modes, the two-machine issuing-CA ceremony, show and export-root-der.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { REPO } from './helpers/pki.js';

const repo = fileURLToPath(REPO);
const scripts = `${repo}scripts/pki`;
const dir = mkdtempSync(`${repo}.pki/script-run-`);
after(() => rmSync(dir, { recursive: true, force: true }));

function run(script: string, args: string[], env: Record<string, string> = {}) {
  const r = spawnSync('bash', [`${scripts}/${script}`, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });
  return { ok: r.status === 0, out: r.stdout, err: r.stderr };
}
const pki = (...args: string[]) => run('identra-pki.sh', args);
const listing = (d: string): string[] => (existsSync(d) ? readdirSync(d, { recursive: true }).map(String).sort() : []);

/** An `openssl` that fails the n-th `openssl ca` call (signing), to provoke a failure mid-run. */
function failingOpenssl(n: number): string {
  const path = `${dir}/openssl-fails-${n}`;
  writeFileSync(path, `#!/bin/sh\nif [ "$1" = ca ]; then c=$(cat "${path}.count" 2>/dev/null || echo 0); c=$((c+1)); echo $c > "${path}.count"; [ $c -ge ${n} ] && exit 1; fi\nexec openssl "$@"\n`);
  chmodSync(path, 0o755);
  return path;
}

test('make-demo-pki.sh validates the base URL before generating anything', () => {
  for (const base of ['http://localhost:3000/issuers', 'https://x.test/a#b', 'https://x.test/$HOME', "https://x.test/a'b"]) {
    const out = `${dir}/demo-bad`;
    const r = run('make-demo-pki.sh', [out, base]);
    assert.equal(r.ok, false, base);
    assert.equal(existsSync(out), false, `${base}: nothing created`);
  }
});

test('a failed make-demo-pki.sh run removes what it created, and only that', () => {
  const fresh = `${dir}/demo-fails`;
  assert.equal(run('make-demo-pki.sh', [fresh], { OPENSSL: failingOpenssl(4) }).ok, false);
  assert.equal(existsSync(fresh), false);
  const empty = `${dir}/demo-empty`;
  mkdirSync(empty);
  assert.equal(run('make-demo-pki.sh', [empty], { OPENSSL: failingOpenssl(6) }).ok, false);
  assert.deepEqual(listing(empty), [], 'the pre-existing empty directory stays, empty');
  const full = `${dir}/demo-full`;
  mkdirSync(full);
  writeFileSync(`${full}/keep.txt`, 'x');
  assert.equal(run('make-demo-pki.sh', [full]).ok, false);
  assert.deepEqual(listing(full), ['keep.txt']);
});

test('a failed identra-pki.sh issuance leaves no certificate, chain or database copy behind', () => {
  const root = `${dir}/r1`;
  const issuing = `${dir}/i1`;
  assert.ok(pki('init-root', '--dir', root, '--o', 'Identra TEST', '--cn', 'R1').ok);
  assert.ok(pki('init-issuing', '--dir', issuing, '--root-dir', root, '--o', 'Identra TEST', '--cn', 'I1').ok);
  assert.ok(pki('new-key-and-csr', '--key', `${dir}/o1/vc.key.pem`, '--csr', `${dir}/o1/vc.csr.pem`, '--o', 'Org TEST', '--mst', '0100000009', '--cn', 'Org').ok);
  const before = listing(`${issuing}/db/certs`);
  const r = run('identra-pki.sh', ['issue-leaf', '--ca-dir', issuing, '--csr', `${dir}/o1/vc.csr.pem`, '--purpose', 'status', '--out', `${dir}/o1/s.cert.pem`, '--chain', `${dir}/o1/s.chain.pem`], { OPENSSL: failingOpenssl(1) });
  assert.equal(r.ok, false);
  assert.deepEqual(listing(`${dir}/o1`), ['vc.csr.pem', 'vc.key.pem']);
  assert.deepEqual(listing(`${issuing}/db/certs`), before);
  // A failed init-root removes the directory it created.
  assert.equal(run('identra-pki.sh', ['init-root', '--dir', `${dir}/r2/root`, '--o', 'O', '--cn', 'CN'], { OPENSSL: failingOpenssl(1) }).ok, false);
  assert.equal(existsSync(`${dir}/r2`), false);
});

test('read-back: a certificate whose SAN differs from the request fails the comparison', () => {
  const cert = `${repo}.pki/test/leaf/vc.cert.pem`;
  const check = (expected: string) =>
    spawnSync('bash', ['-c', `. "${scripts}/pki-lib.sh"; init_run; expect_sans "$1" "$2"`, 'x', cert, expected], { encoding: 'utf8' });
  assert.equal(check('https://api-identra.awncorp.vn/issuers/truong-mau').status, 0);
  const r = check('https://api-identra.awncorp.vn/issuers/truong-mau#frag');
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /SAN .* differs from the request/);
});

test('explicit argument validation', () => {
  const args = (...extra: string[]) => ['init-root', '--dir', `${dir}/never`, '--o', 'O', '--cn', 'CN', ...extra];
  for (const [extra, pattern] of [
    [['--start', ''], /missing value/],
    [['--start', '2026'], /--start must be/],
    [['--start', '20260101000000'], /--start must be/],
    [['--o', 'again'], /given twice/],
    [['--cn'], /missing value/],
  ] as const) {
    const r = pki(...args(...extra));
    assert.equal(r.ok, false, extra.join(' '));
    assert.match(r.err, pattern);
  }
  assert.equal(existsSync(`${dir}/never`), false);
  for (const o of ['A#b', 'A"b', ' A', 'A ', 'A`b', 'A\tb']) assert.match(pki('init-root', '--dir', `${dir}/never`, '--o', o, '--cn', 'CN').err, /--o must be/, JSON.stringify(o));
  assert.match(pki('init-root', '--dir', `${dir}/$x`, '--o', 'O', '--cn', 'CN').err, /path must/);
});

test('serials are fresh random values; keys and directories are private', () => {
  const serial = (path: string) => /serial=([0-9A-F]+)/.exec(spawnSync('openssl', ['x509', '-in', path, '-noout', '-serial'], { encoding: 'utf8' }).stdout)![1]!;
  const a = BigInt(`0x${serial(`${repo}.pki/demo/orgs/truong-mau/vc.cert.pem`)}`);
  const b = BigInt(`0x${serial(`${repo}.pki/demo/orgs/truong-mau/status.cert.pem`)}`);
  assert.ok(a - b > 1000n || b - a > 1000n, 'not consecutive');
  for (const path of ['ca/root/ca.key.pem', 'orgs/truong-mau/vc.key.pem', 'trust-list-signer/trust-list.key.pem']) {
    assert.equal(statSync(`${repo}.pki/demo/${path}`).mode & 0o777, 0o600, path);
  }
  for (const path of ['', 'orgs', 'orgs/truong-mau', 'ca/issuing/db']) assert.equal(statSync(`${repo}.pki/demo/${path}`).mode & 0o777, 0o700, path || '<outdir>');
});

test('the two-machine issuing-CA ceremony, show and export-root-der', () => {
  const root = `${dir}/cer-root`;
  const issuing = `${dir}/cer-issuing`;
  assert.ok(pki('init-root', '--dir', root, '--o', 'Identra TEST', '--cn', 'Ceremony Root').ok);
  const csr = pki('new-issuing-key-and-csr', '--dir', issuing, '--o', 'Identra TEST', '--cn', 'Ceremony Issuing');
  assert.ok(csr.ok, csr.err);
  assert.match(csr.out, /SHA-256 [0-9a-f]{64}/);
  assert.equal(existsSync(`${issuing}/ca.cert.pem`), false);
  // The Root machine refuses a leaf-shaped CSR and signs the issuing CSR.
  assert.ok(pki('new-key-and-csr', '--key', `${dir}/leafish.key.pem`, '--csr', `${dir}/leafish.csr.pem`, '--o', 'O', '--mst', '0100000009', '--cn', 'CN').ok);
  assert.match(pki('sign-issuing-csr', '--root-dir', root, '--csr', `${dir}/leafish.csr.pem`, '--out', `${dir}/x.pem`).err, /issuing CA CSR subject must be exactly C=VN, O, CN/);
  const signed = pki('sign-issuing-csr', '--root-dir', root, '--csr', `${issuing}/ca.csr.pem`, '--out', `${issuing}/ca.cert.pem`);
  assert.ok(signed.ok, signed.err);
  const show = pki('show', '--cert', `${issuing}/ca.cert.pem`);
  for (const field of ['subject:', 'issuer:', 'SAN URI:', 'notBefore:', 'notAfter:', 'basicConstraints:', 'keyUsage:', 'SHA-256 (hex):', 'SHA-256 (base64url):']) {
    assert.match(show.out, new RegExp(field.replace(/[()]/g, '\\$&')), field);
  }
  assert.match(show.out, /basicConstraints: +critical CA:TRUE, pathlen:0|basicConstraints: +CA:TRUE, pathlen:0/);
  assert.match(show.out, /keyUsage: +Certificate Sign, CRL Sign/);
  // The issuing CA, installed on its own machine, can issue.
  assert.ok(pki('new-key-and-csr', '--key', `${dir}/cer-org/s.key.pem`, '--csr', `${dir}/cer-org/s.csr.pem`, '--o', 'Org', '--mst', '0100000009', '--cn', 'Org').ok);
  const leaf = pki('issue-leaf', '--ca-dir', issuing, '--csr', `${dir}/cer-org/s.csr.pem`, '--purpose', 'vc', '--san-uri', 'https://api-identra.awncorp.vn/issuers/org', '--out', `${dir}/cer-org/s.cert.pem`, '--chain', `${dir}/cer-org/s.chain.pem`);
  assert.ok(leaf.ok, leaf.err);
  assert.match(leaf.out, /SAN URI: +https:\/\/api-identra\.awncorp\.vn\/issuers\/org/);
  // export-root-der writes the DER pin and refuses to overwrite it.
  assert.ok(pki('export-root-der', '--in', `${root}/ca.cert.pem`, '--out', `${dir}/root.der`).ok);
  const pem = readFileSync(`${root}/ca.cert.pem`, 'utf8').replace(/-----[A-Z ]+-----|\s/g, '');
  assert.deepEqual(readFileSync(`${dir}/root.der`), Buffer.from(pem, 'base64'));
  assert.match(pki('export-root-der', '--in', `${root}/ca.cert.pem`, '--out', `${dir}/root.der`).err, /refusing to overwrite/);
});

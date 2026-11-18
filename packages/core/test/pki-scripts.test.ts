// The operational script scripts/pki/identra-pki.sh refuses what ADR-0015 forbids.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { REPO } from './helpers/pki.js';

const repo = fileURLToPath(REPO);
const script = `${repo}scripts/pki/identra-pki.sh`;
const dir = mkdtempSync(`${repo}.pki/script-test-`);
after(() => rmSync(dir, { recursive: true, force: true }));

function pki(...args: string[]) {
  const r = spawnSync('bash', [script, ...args], { encoding: 'utf8' });
  return { ok: r.status === 0, err: r.stderr };
}
function refused(pattern: RegExp, ...args: string[]) {
  const r = pki(...args);
  assert.equal(r.ok, false, `expected refusal: ${args.join(' ')}`);
  assert.match(r.err, pattern);
}
function openssl(...args: string[]) {
  const r = spawnSync('openssl', args, { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
}

test('identra-pki.sh refusals', () => {
  const root = `${dir}/root`;
  const issuing = `${dir}/issuing`;
  assert.ok(pki('init-root', '--dir', root, '--o', 'Identra TEST', '--cn', 'Script Root').ok);
  refused(/refusing to overwrite/, 'init-root', '--dir', root, '--o', 'Identra TEST', '--cn', 'Script Root');
  assert.ok(pki('init-issuing', '--dir', issuing, '--root-dir', root, '--o', 'Identra TEST', '--cn', 'Script Issuing').ok);

  refused(/unexpected argument/, 'init-root', '--dir', `${dir}/x`, '--o', 'O', '--cn', 'CN', '--days', '1');
  refused(/--o must be non-empty/, 'init-root', '--dir', `${dir}/x`, '--o', 'A/CN=evil', '--cn', 'CN');
  refused(/--mst must be/, 'new-key-and-csr', '--key', `${dir}/a.key.pem`, '--csr', `${dir}/a.csr.pem`, '--o', 'O', '--mst', '123', '--cn', 'CN');

  const csr = `${dir}/org.csr.pem`;
  assert.ok(pki('new-key-and-csr', '--key', `${dir}/org.key.pem`, '--csr', csr, '--o', 'Org TEST', '--mst', '0100000009', '--cn', 'Org').ok);
  refused(/refusing to overwrite/, 'new-key-and-csr', '--key', `${dir}/org.key.pem`, '--csr', `${dir}/other.csr.pem`, '--o', 'O', '--mst', '0100000009', '--cn', 'CN');
  const leafArgs = (purpose: string, out: string, ...extra: string[]) =>
    ['issue-leaf', '--ca-dir', issuing, '--csr', csr, '--purpose', purpose, '--out', `${dir}/${out}.cert.pem`, '--chain', `${dir}/${out}.chain.pem`, ...extra];
  refused(/--san-uri .* is required/, ...leafArgs('vc', 'a'));
  refused(/--san-uri must be https/, ...leafArgs('vc', 'a', '--san-uri', 'http://insecure.example/x'));
  refused(/only applies to vc/, ...leafArgs('status', 'a', '--san-uri', 'https://example.test/x'));
  refused(/--purpose must be/, ...leafArgs('trust-list', 'a'));
  assert.ok(pki(...leafArgs('vc', 'good', '--san-uri', 'https://example.test/issuers/org')).ok);
  refused(/refusing to overwrite/, ...leafArgs('status', 'good'));

  // CSRs that do not meet ADR-0015 sections 3 and 9.
  openssl('req', '-new', '-key', `${repo}.pki/test/leaf/rsa.key.pem`, '-subj', '/C=VN/O=O/organizationIdentifier=VATVN-0100000009/CN=CN', '-out', `${dir}/rsa.csr.pem`);
  refused(/not EC P-256/, ...leafArgs('status', 'b').map((a) => (a === csr ? `${dir}/rsa.csr.pem` : a)));
  for (const [name, subject] of [
    ['no-org-id', '/C=VN/O=O/CN=CN'],
    ['not-vn', '/C=US/O=O/organizationIdentifier=VATVN-0100000009/CN=CN'],
    ['bad-org-id', '/C=VN/O=O/organizationIdentifier=NTRVN-0100000009/CN=CN'],
    ['extra-attribute', '/C=VN/O=O/OU=Unit/organizationIdentifier=VATVN-0100000009/CN=CN'],
  ]) {
    openssl('req', '-new', '-key', `${dir}/org.key.pem`, '-subj', subject!, '-out', `${dir}/${name}.csr.pem`);
    refused(/CSR subject must be exactly/, ...leafArgs('status', name!).map((a) => (a === csr ? `${dir}/${name}.csr.pem` : a)));
  }
});

test('a CA never issues past its own notAfter', () => {
  const oldRoot = `${dir}/old-root`;
  assert.ok(pki('init-root', '--dir', oldRoot, '--o', 'Identra TEST', '--cn', 'Old Root', '--start', '20010101000000Z').ok); // ends 2026-01-01
  refused(/would exceed the CA's own notAfter/, 'init-issuing', '--dir', `${dir}/late-issuing`, '--root-dir', oldRoot, '--o', 'Identra TEST', '--cn', 'Late');
  assert.ok(pki('init-issuing', '--dir', `${dir}/early-issuing`, '--root-dir', oldRoot, '--o', 'Identra TEST', '--cn', 'Early', '--start', '20010101000000Z').ok);
});

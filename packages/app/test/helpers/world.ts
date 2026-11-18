// A demo-like world over REAL HTTP on 127.0.0.1: a tiny node:http server mounting the sdk-server
// issuer at the paths of vc-api.md section 4 (each route is "parse HTTP -> call the SDK -> write
// HTTP"), plus the trust list and the status lists of the same server, all signed with the test
// PKI. Wallets reach it through createMappedFetch from the canonical origin.
import http from 'node:http';
import { readFileSync } from 'node:fs';
import {
  base64Decode, base64Encode, base64UrlEncode, createCertificateChainValidator, createMappedFetch, createSignedTrustListRegistry, createStatusListChecker, VCT,
  type CertificateChainValidator, type TrustRegistry,
  type DiplomaClaims, type EcPublicJwk, type HttpFetch, type Signer, type TrustListContent,
} from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair, webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import {
  createCredentialIssuer, createMemoryStateStore, createPresentationVerifier, type PresentationVerifier, type Scenario, createMemoryStatusListStorage, createStatusListService, createTrustListService, generateIssuerKeys,
  type CredentialHandlers, type CredentialIssuer, type HttpResponse, type IssuedEvent, type IssuerKeyStore, type ProtocolStateStore,
} from '@identra/sdk-server';
import { createCredentialVault, createInMemoryCredentialRepository, createInMemorySecretStorage, createSoftwareKeyStore, createWallet, type CredentialRow, type WalletKeyStore } from '@identra/sdk-app';

export const ORIGIN = 'https://api-identra.awncorp.vn';
export const ISSUERS = `${ORIGIN}/issuers`;
export const ISS = `${ISSUERS}/truong-mau`;
export const TRUST_URL = `${ORIGIN}/trust-list`;
/** Every certificate of the test PKI is valid at this instant. */
export const NOW = new Date('2026-06-01T00:00:00Z');
export const DIPLOMA: DiplomaClaims = {
  ho_ten: 'Nguyễn Văn A', ngay_sinh: '2001-02-03', ma_sinh_vien: 'SV123456', nganh: 'Khoa học máy tính',
  hang_tot_nghiep: 'Giỏi', nam_tot_nghiep: '2024', so_hieu_bang: 'B-0001',
};

const PKI = new URL('../../../../.pki/test/', import.meta.url);
const pem = (path: string) => readFileSync(new URL(path, PKI), 'utf8');
const der = (path: string) => base64Decode(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END/.exec(pem(path))![1]!.replace(/\s+/g, ''));
export const rootDer = () => der('ca/root/ca.cert.pem');
const fingerprint = async (d: Uint8Array) => base64UrlEncode(await webCryptoHasher.sha256(d));
/** Signer of a test PKI leaf with its CA, e.g. leafSigner('vc') or leafSigner('evil-vc', 'evil-issuing'). */
export const leafSigner = (name: string, ca = 'issuing') =>
  createWebCryptoSigner({ privateKey: pem(`leaf/${name}.key.pem`), x5c: [base64Encode(der(`leaf/${name}.cert.pem`)), base64Encode(der(`ca/${ca}/ca.cert.pem`))] });

export function fakeClock(start = NOW) {
  let t = start.getTime();
  return { now: () => new Date(t), advance: (seconds: number) => void (t += seconds * 1000) };
}

/** The test's HttpFetch on Node: never follows a redirect, honours timeoutMs and maxBytes. */
export const nodeHttpFetch: HttpFetch = async (url, init) => {
  const r = await fetch(url, {
    method: init?.method ?? 'GET', redirect: 'manual', signal: AbortSignal.timeout(init?.timeoutMs ?? 10_000),
    ...(init?.headers ? { headers: init.headers } : {}), ...(init?.body !== undefined ? { body: init.body } : {}),
  });
  const max = init?.maxBytes ?? 262_144;
  // A declared size over the cap is refused without reading the body (the caller sees Content-Length too).
  if (Number(r.headers.get('content-length') ?? 0) > max) {
    await r.body?.cancel();
    return { status: r.status, headers: r.headers, text: () => Promise.reject(new Error('response too large')) };
  }
  const text = await r.text();
  if (text.length > max) throw new Error('response too large');
  return { status: r.status, headers: r.headers, text: async () => text };
};

export const UNG_TUYEN: Scenario = {
  vct: VCT.diploma,
  claimSets: [['ho_ten', 'nganh', 'hang_tot_nghiep', 'nam_tot_nghiep'], ['ho_ten', 'nganh']],
  purpose: { vi: 'Ứng tuyển vị trí kỹ sư phần mềm', en: 'Job application: software engineer' },
};

export interface Request { method: string; path: string; headers: Record<string, string | undefined>; body: string }
export type Handler = (req: Request) => Promise<HttpResponse>;

/** Calls the handler of "METHOD /path" in `routes` (a trailing * matches one segment); 404 when there is none, 500 when it throws. */
export async function dispatch(routes: Map<string, Handler>, req: Request): Promise<HttpResponse> {
  const key = `${req.method} ${req.path}`;
  const handler = routes.get(key) ?? routes.get(key.replace(/\/[^/]+$/, '/*'));
  if (!handler) return { status: 404, headers: {}, body: '' };
  return handler(req).catch(() => ({ status: 500, headers: {}, body: '{"error":"server_error"}' }));
}

/** One listener per test file, serving `routes`. */
export async function startListener(port: number) {
  const routes = new Map<string, Handler>();
  const requests: string[] = [];
  const log: { path: string; contentType: string | undefined; body: string; status: number; responseType: string | undefined }[] = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.setEncoding('utf8').on('data', (c: string) => (body += c)).on('end', async () => {
      const path = (req.url ?? '/').split('?')[0]!;
      requests.push(`${req.method} ${path}`);
      const r = await dispatch(routes, { method: req.method!, path, headers: req.headers as Record<string, string | undefined>, body });
      log.push({ path, contentType: req.headers['content-type'], body, status: r.status, responseType: r.headers['Content-Type'] });
      res.writeHead(r.status, { 'Content-Length': String(Buffer.byteLength(r.body)), ...r.headers }).end(r.body);
    });
  });
  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve));
  return {
    routes, requests, log,
    localOrigin: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const IN_PROCESS = 'http://in-process.invalid';
/** The same routes without a socket, for a fetch that calls them in-process. */
export function inProcessListener(): Listener {
  return { routes: new Map(), requests: [], log: [], localOrigin: IN_PROCESS, close: async () => {} };
}

/** An HttpFetch for the canonical origin that calls `listener`'s routes directly (no socket). */
export function inProcessFetch(listener: Listener) {
  return async (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => {
    if (!url.startsWith(`${ORIGIN}/`)) throw new Error(`host unreachable: ${url}`);
    const headers = Object.fromEntries(Object.entries(init?.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    const path = url.slice(ORIGIN.length).split('?')[0]!;
    listener.requests.push(`${init?.method ?? 'GET'} ${path}`);
    const r = await dispatch(listener.routes, { method: init?.method ?? 'GET', path, headers, body: init?.body ?? '' });
    const rh = Object.fromEntries(Object.entries(r.headers).map(([k, v]) => [k.toLowerCase(), v]));
    return { status: r.status, headers: { get: (n: string) => rh[n.toLowerCase()] ?? null }, text: async () => r.body };
  };
}

/** The verifier routes of vc-api.md section 6. */
export function mountVerifier(routes: Map<string, Handler>, verifier: PresentationVerifier) {
  routes.set('GET /oid4vp/request/*', (req) => verifier.requestObject(req.path.split('/').pop()!));
  routes.set('POST /oid4vp/response/*', (req) => verifier.handleResponse(req.path.split('/').pop()!, req));
}
export type Listener = Awaited<ReturnType<typeof startListener>>;

/** The controller of vc-api.md section 4: HTTP in, SDK call, HTTP out. */
export function mountIssuer(routes: Map<string, Handler>, name: string, issuer: CredentialIssuer) {
  routes.set(`GET /.well-known/openid-credential-issuer/issuers/${name}`, async () => issuer.metadata());
  routes.set(`GET /.well-known/oauth-authorization-server/issuers/${name}`, async () => issuer.authorizationServerMetadata());
  routes.set(`GET /issuers/${name}/jwks`, async () => issuer.jwks());
  routes.set(`GET /issuers/${name}/offers/*`, (req) => issuer.offer(req.path.split('/').pop()!));
  routes.set(`POST /issuers/${name}/token`, (req) => issuer.token(req));
  routes.set(`POST /issuers/${name}/nonce`, () => issuer.nonce());
  routes.set(`POST /issuers/${name}/credential`, (req) => issuer.credential(req));
}

/** IssuerKeyStore over the test PKI: truong-mau `vc` and `status`, and the trust-list signer. */
function testKeyStore(): IssuerKeyStore {
  const signers = { vc: leafSigner('vc'), status: leafSigner('status') };
  return {
    async signer(organisation, purpose) {
      if (organisation !== 'truong-mau' || purpose === 'request') throw new Error('no such key in the test key store');
      return signers[purpose];
    },
    trustListSigner: () => createWebCryptoSigner({ privateKey: pem('leaf/trust-list.key.pem'), x5c: [base64Encode(der('leaf/trust-list.cert.pem'))] }),
    trustedRoots: () => [rootDer()],
  };
}

async function trustContent(): Promise<TrustListContent & { verifiers: NonNullable<TrustListContent['verifiers']> }> {
  return {
    issuers: [{
      ma_to_chuc: 'VATVN-0100000001', ten: 'Trường Mẫu (TEST)',
      chung_thu: [{ sha256: await fingerprint(der('leaf/vc.cert.pem')), muc_dich: 'vc' }, { sha256: await fingerprint(der('leaf/status.cert.pem')), muc_dich: 'status' }],
      vct: [VCT.diploma], validFrom: '2026-01-01T00:00:00Z', validUntil: '2029-01-01T00:00:00Z',
    }],
    verifiers: [{ ma_to_chuc: 'VATVN-0100000005', ten: 'Nhà Tuyển Dụng Mẫu (TEST)', chung_thu: [{ sha256: await fingerprint(der('leaf/request.cert.pem')), muc_dich: 'request' }] }],
  };
}

/** WalletKeyStore on WebCrypto (non-extractable keys), to run the wallet on a second crypto backend. */
function webCryptoKeyStore(secrets: Map<string, Signer>): WalletKeyStore {
  return {
    async create() {
      const { privateKey, publicJwk } = await generateWebCryptoKeyPair();
      const keyId = base64UrlEncode(webCryptoRandom.bytes(16));
      secrets.set(keyId, await createWebCryptoSigner({ privateKey, publicJwk }));
      return { keyId, publicJwk };
    },
    async signer(keyId) {
      const s = secrets.get(keyId);
      if (!s) throw new Error('KEY_NOT_FOUND');
      return s;
    },
    async delete(keyId) {
      secrets.delete(keyId);
    },
  };
}

export interface WorldOptions {
  handlers?: Partial<CredentialHandlers>;
  store?: (inner: ProtocolStateStore) => ProtocolStateStore;
  issuerName?: string;
  /** Leave the verifier out of the trust list the world serves. */
  untrustedVerifier?: boolean;
}

/** The issuer, its lists and its routes on `listener`; wallets are made with newWallet. */
export async function createWorld(listener: Listener, o: WorldOptions = {}) {
  listener.routes.clear();
  listener.requests.length = 0;
  const clock = fakeClock();
  const keyStore = testKeyStore();
  const statusStorage = createMemoryStatusListStorage();
  const statusService = createStatusListService({ issuerUri: (n) => `${ISSUERS}/${n}`, keyStore, storage: statusStorage, random: webCryptoRandom, clock });
  const trust = { content: await trustContent() as TrustListContent };
  const verifierEntry = trust.content.verifiers![0]!;
  if (o.untrustedVerifier) trust.content = { ...trust.content, verifiers: [] };
  const trustList = createTrustListService({ source: () => trust.content, keyStore, clock });
  const store = (o.store ?? ((s) => s))(createMemoryStateStore(clock));
  const keys = await generateIssuerKeys(webCryptoRandom);
  const issued: IssuedEvent[] = [];
  const name = o.issuerName ?? 'truong-mau';
  const issuer = createCredentialIssuer({
    issuerUri: `${ISSUERS}/${name}`, display: { vi: 'Trường Mẫu', en: 'Sample University' },
    signer: await keyStore.signer('truong-mau', 'vc'), allocateStatus: () => statusService.allocate('truong-mau'),
    hasher: webCryptoHasher, verifier: webCryptoVerifier, random: webCryptoRandom, clock, store, keys,
    credentials: {
      'bang-tot-nghiep-v1': {
        resolveClaims: o.handlers?.resolveClaims ?? (async () => ({ ...DIPLOMA })),
        onIssued: o.handlers?.onIssued ?? (async (e) => (issued.push(e), { credentialId: `cred-${issued.length}` })),
      },
    },
  });
  mountIssuer(listener.routes, name, issuer);
  listener.routes.set('GET /trust-list', async () => ({ status: 200, headers: { 'Content-Type': 'application/jwt' }, body: await trustList.token() }));
  listener.routes.set('GET /issuers/truong-mau/status/*', async (req) => {
    const token = await statusService.token('truong-mau', Number(req.path.split('/').pop()));
    return token ? { status: 200, headers: { 'Content-Type': 'application/statuslist+jwt' }, body: token } : { status: 404, headers: {}, body: '' };
  });

  // The server's own view of the lists: always reloaded (maxAgeSeconds 0), as identra-server verifies.
  const serverFetch: HttpFetch = listener.localOrigin === IN_PROCESS ? inProcessFetch(listener) : createMappedFetch(nodeHttpFetch, { [ORIGIN]: listener.localOrigin });
  const serverValidator = createCertificateChainValidator({ trustedRoots: [rootDer()], verifier: webCryptoVerifier, hasher: webCryptoHasher });
  const serverRegistry = createSignedTrustListRegistry({ url: TRUST_URL, fetch: serverFetch, verifier: webCryptoVerifier, chainValidator: serverValidator, clock, maxAgeSeconds: 0 });

  /** The verifier nha-tuyen-dung-mau with the `request` certificate, mounted at the section 6 paths. */
  async function newVerifier(v: { signer?: Signer; chainValidator?: CertificateChainValidator; trustRegistry?: TrustRegistry; mount?: boolean } = {}) {
    const chainValidator = v.chainValidator ?? serverValidator;
    const trustRegistry = v.trustRegistry ?? serverRegistry;
    const statusChecker = createStatusListChecker({ fetch: serverFetch, verifier: webCryptoVerifier, chainValidator, trustRegistry, clock, maxAgeSeconds: 0 });
    const verifier = await createPresentationVerifier({
      apiOrigin: ORIGIN, signer: v.signer ?? (await leafSigner('request')),
      verification: { verifier: webCryptoVerifier, hasher: webCryptoHasher, chainValidator, trustRegistry, statusChecker, supportedVcts: [VCT.diploma] },
      random: webCryptoRandom, clock, store: createMemoryStateStore(clock), scenarios: { 'ung-tuyen': UNG_TUYEN },
    });
    if (v.mount !== false) mountVerifier(listener.routes, verifier);
    return verifier;
  }

  function newWallet(
    backend: 'noble' | 'webcrypto' = 'noble',
    fetch: HttpFetch = createMappedFetch(nodeHttpFetch, { [ORIGIN]: listener.localOrigin }),
    walletClock: { now(): Date } = clock,
  ) {
    const secrets = new Map<string, unknown>();
    const rows = new Map<string, CredentialRow>();
    const keyStore =
      backend === 'noble'
        ? createSoftwareKeyStore({ secrets: createInMemorySecretStorage(secrets as Map<string, string>), random: webCryptoRandom })
        : webCryptoKeyStore(secrets as Map<string, Signer>);
    const vault = createCredentialVault({ repository: createInMemoryCredentialRepository(rows), secrets: createInMemorySecretStorage(), random: webCryptoRandom, clock: walletClock });
    const wallet = createWallet({
      keyStore,
      vault,
      fetch, random: webCryptoRandom, clock: walletClock, trustedRoots: [rootDer()], trustListUrl: TRUST_URL,
      ...(backend === 'webcrypto' ? { verifier: webCryptoVerifier, hasher: webCryptoHasher } : {}),
    });
    return { wallet, keyStore, vault, secrets, rows };
  }

  /** Offer -> resolve -> accept into `w`; the credential id. */
  async function issueTo(w: { wallet: ReturnType<typeof createWallet> }) {
    const { offerUri, txCode } = await issuer.createOffer({ subjectRef: 'sv001', configurationId: 'bang-tot-nghiep-v1' });
    const resolved = await w.wallet.offers.resolve(offerUri);
    if (!resolved.ok) throw new Error(`resolve failed: ${resolved.code}`);
    const accepted = await w.wallet.offers.accept(resolved.offer, { txCode });
    if (!accepted.ok) throw new Error(`accept failed: ${accepted.code}`);
    return accepted.credentialId;
  }

  return {
    clock, issuer, keys, store, statusService, statusStorage, issued, trust, verifierEntry, serverFetch, serverRegistry,
    newWallet, newVerifier, issueTo, offer: () => issuer.createOffer({ subjectRef: 'sv001', configurationId: 'bang-tot-nghiep-v1' }),
  };
}
export type World = Awaited<ReturnType<typeof createWorld>>;
export type { EcPublicJwk };

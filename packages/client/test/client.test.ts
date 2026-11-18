// Verifier-session client against a fake fetch: requests, validation, polling, backoff, server clock, expiry, abort.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createVerifierClient,
  isTerminalStatus,
  isValidVerifierQr,
  PRESENTATION_CHECK_IDS,
  serverClockOffset,
  VerifierClientError,
  type VerificationSession,
  type WatchSessionOptions,
} from '@identra/sdk-client';

type Step = Response | Error | ((init: RequestInit, tick: (ms: number) => void) => Promise<Response> | Response);

const BASE = 'https://api.example';
const API = 'https://api-identra.awncorp.vn';
const T0 = Date.parse('2026-11-19T10:00:00.000Z');
const FAR = '2026-11-19T10:05:00.000Z';
const ID = 'sess_0123456789abcdef';
const QR = `openid4vp://?client_id=${encodeURIComponent(`x509_hash:${'A'.repeat(43)}`)}&request_uri=${encodeURIComponent(`${API}/oid4vp/request/req_0123456789abcdef`)}`;
/** Replaced by the fake server with its own clock (the fake local clock plus `serverSkewMs`). */
const NOW = '@server-now';

const res = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers });

/** Answers requests from a queue and records them; an unexpected request gets a 400 so a watch cannot loop. */
function fakeFetch(steps: Step[], serverSkewMs = 0) {
  const calls: { url: string; init: RequestInit; at: number }[] = [];
  let clock = T0;
  const tick = (ms: number) => void (clock += ms);
  const fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    calls.push({ url: String(input), init, at: clock });
    const step = steps.shift();
    if (step === undefined) return res(400, { statusCode: 400, code: 'VALIDATION_FAILED', message: 'unexpected request' });
    if (step instanceof Error) throw step;
    const response = typeof step === 'function' ? await step(init, tick) : step;
    const text = (await response.text()).replaceAll(`"${NOW}"`, JSON.stringify(new Date(clock + serverSkewMs).toISOString()));
    return new Response(text, { status: response.status, headers: response.headers });
  }) as typeof globalThis.fetch;
  return { fetch, calls, now: () => clock, tick };
}

/** A request that only ends when its signal aborts, like a real fetch. */
const hang = (init: RequestInit) =>
  new Promise<Response>((_, reject) => init.signal?.addEventListener('abort', () => reject(init.signal?.reason)));

const session = (status: string, extra: object = {}) => ({
  id: ID,
  status,
  verifier: { name: 'Nhà tuyển dụng mẫu (DEMO)' },
  expiresAt: FAR,
  serverTime: NOW,
  ...extra,
});
const okChecks = PRESENTATION_CHECK_IDS.map((id) => ({ id, ok: true, code: null }));
const okResult = {
  ok: true,
  checks: okChecks,
  claims: { ho_ten: 'Nguyễn Văn A', nganh: 'CNTT', nam_tot_nghiep: '2026' },
  issuer: { maToChuc: 'VATVN-0100000001', ten: 'Trường Đại học Mẫu (DEMO)' },
  verifiedAt: '2026-11-19T10:01:00.000Z',
};
const revokedResult = {
  ok: false,
  checks: okChecks.map((c) => (c.id === 'status' ? { id: 'status', ok: false, code: 'REVOKED' } : c)),
  verifiedAt: '2026-11-19T10:01:00.000Z',
};
const verified = () => res(200, session('verified', { result: okResult }));
const pending = () => res(200, session('pending'));
const created = (extra: object = {}) => ({ id: ID, qr: QR, expiresAt: FAR, serverTime: '2026-11-19T10:00:00.000Z', ...extra });

function watch(steps: Step[], options: WatchSessionOptions = {}, serverSkewMs = 0) {
  const f = fakeFetch(steps, serverSkewMs);
  const updates: VerificationSession[] = [];
  const errors: { kind: string; status: number | undefined; attempt: number; retryInMs: number }[] = [];
  let recoveries = 0;
  const client = createVerifierClient({ baseUrl: BASE, fetch: f.fetch, now: f.now });
  const promise = client.watchSession(ID, {
    intervalMs: 1,
    ...options,
    onUpdate: (s) => {
      updates.push(s);
      options.onUpdate?.(s);
    },
    onError: (e, info) => errors.push({ kind: e.kind, status: e.status, ...info }),
    onRecover: () => void (recoveries += 1),
  });
  return { ...f, promise, updates, errors, recoveries: () => recoveries };
}

/** Counts live timers so a test can prove an abort cleared its wait. */
function trackTimers() {
  const live = new Set<ReturnType<typeof setTimeout>>();
  const realSet = globalThis.setTimeout;
  const realClear = globalThis.clearTimeout;
  globalThis.setTimeout = ((fn: () => void, ms?: number) => {
    const t = realSet(() => {
      live.delete(t);
      fn();
    }, ms);
    live.add(t);
    return t;
  }) as typeof setTimeout;
  globalThis.clearTimeout = ((t: ReturnType<typeof setTimeout>) => {
    live.delete(t);
    realClear(t);
  }) as typeof clearTimeout;
  return {
    live,
    restore: () => {
      globalThis.setTimeout = realSet;
      globalThis.clearTimeout = realClear;
    },
  };
}

test('isTerminalStatus is true for verified, failed and expired only', () => {
  assert.deepEqual(
    (['pending', 'request_retrieved', 'verified', 'failed', 'expired'] as const).map(isTerminalStatus),
    [false, false, true, true, true],
  );
});

test('serverClockOffset is server minus local time', () => {
  assert.equal(serverClockOffset('2026-11-19T10:00:00.000Z', T0 + 11 * 60_000), -11 * 60_000);
  assert.equal(serverClockOffset('not a date', T0), 0);
});

test('the QR must be exactly openid4vp://?client_id=x509_hash:…&request_uri=<api>/oid4vp/request/<id>', () => {
  assert.equal(isValidVerifierQr(QR), true);
  const id = `x509_hash:${'A'.repeat(43)}`;
  const uri = `${API}/oid4vp/request/req_0123456789abcdef`;
  for (const bad of [
    `openid4vp://?client_id=${id}&request_uri=https://evil.example/oid4vp/request/req_0123456789abcdef`,
    `openid4vp://?client_id=${id}&request_uri=${uri}&extra=1`,
    `openid4vp://?client_id=${id}&client_id=${id}&request_uri=${uri}`,
    `openid4vp://?client_id=redirect_uri:x&request_uri=${uri}`,
    `openid4vp://?client_id=${id}&request_uri=${uri}/../x`,
    `openid4vp://?client_id=${id}&request_uri=${API}/oid4vp/request/${'a'.repeat(2048)}`,
    `https://evil.example/?client_id=${id}&request_uri=${uri}`,
  ]) {
    assert.equal(isValidVerifierQr(bad), false, bad.slice(0, 120));
  }
  // A development deployment keeps canonical identifiers, but a client may name another canonical origin.
  assert.equal(isValidVerifierQr(QR.replace(encodeURIComponent(API), encodeURIComponent('https://other.example')), 'https://other.example'), true);
});

test('createSession posts JSON to the sessions route, without cookies, and returns the server time', async () => {
  const f = fakeFetch([res(201, { ...created(), extra: 1 })]);
  const client = createVerifierClient({ baseUrl: `${BASE}///`, fetch: f.fetch });
  assert.deepEqual(await client.createSession({ verifier: 'nha-tuyen-dung-mau', scenario: 'ung-tuyen' }), created());
  assert.equal(f.calls.length, 1);
  const { url, init } = f.calls[0]!;
  assert.equal(url, `${BASE}/v1/verification/sessions`);
  assert.equal(init.method, 'POST');
  assert.equal(init.credentials, 'omit');
  assert.deepEqual(init.headers, { Accept: 'application/json', 'Content-Type': 'application/json' });
  assert.deepEqual(JSON.parse(String(init.body)), { verifier: 'nha-tuyen-dung-mau', scenario: 'ung-tuyen' });
});

test('createSession rejects a malformed answer', async () => {
  const cases: [unknown, string][] = [
    [created({ qr: 'https://evil.example/?x' }), 'qr'],
    [created({ qr: `${QR}&x=${'a'.repeat(2048)}` }), 'qr'],
    [created({ id: '' }), 'id'],
    [created({ id: 'short' }), 'id'],
    [created({ id: 'a'.repeat(257) }), 'id'],
    [created({ expiresAt: 'soon' }), 'expiresAt'],
    [created({ serverTime: undefined }), 'serverTime'],
    [[created()], 'body'],
  ];
  for (const [body, path] of cases) {
    const f = fakeFetch([res(201, body)]);
    await assert.rejects(createVerifierClient({ baseUrl: BASE, fetch: f.fetch }).createSession({ verifier: 'v', scenario: 's' }), {
      name: 'VerifierClientError',
      kind: 'malformed',
      message: `malformed session response: ${path}`,
    });
  }
});

test('getSession encodes the id, sends no cookies and returns a fresh copy without check details', async () => {
  const failing = {
    ok: false,
    checks: [
      { id: 'structure', ok: true, code: null, detail: 'log only' },
      { id: 'issuer_trust', ok: false, code: 'ISSUER_NOT_TRUSTED' },
      { id: 'status', ok: false, code: 'SKIPPED', skipped: true },
      { id: 'future_check', ok: false, code: 'FUTURE_CODE' },
    ],
    verifiedAt: '2026-11-19T10:01:00.000Z',
  };
  const f = fakeFetch([res(200, session('failed', { result: failing }))]);
  const s = await createVerifierClient({ baseUrl: `${BASE}/`, fetch: f.fetch }).getSession('a/b?c');
  assert.equal(f.calls[0]!.url, `${BASE}/v1/verification/sessions/a%2Fb%3Fc`);
  assert.equal(f.calls[0]!.init.method, 'GET');
  assert.equal(f.calls[0]!.init.credentials, 'omit');
  assert.equal(f.calls[0]!.init.body, null);
  assert.deepEqual(f.calls[0]!.init.headers, { Accept: 'application/json' });
  assert.deepEqual(s.result, {
    ok: false,
    checks: [
      { id: 'structure', ok: true, code: null },
      { id: 'issuer_trust', ok: false, code: 'ISSUER_NOT_TRUSTED' },
      { id: 'status', ok: false, code: 'SKIPPED', skipped: true },
      { id: 'future_check', ok: false, code: 'FUTURE_CODE' },
    ],
    verifiedAt: '2026-11-19T10:01:00.000Z',
  });
  assert.equal('claims' in s.result!, false);
  assert.equal('issuer' in s.result!, false);
});

test('getSession rejects malformed sessions at the trust boundary, naming only the field', async () => {
  const LEAK = 'LEAK-Nguyen-Van-A';
  const withResult = (status: string, result: object) => JSON.stringify(session(status, { result: { ...okResult, ...result } }));
  const failedWith = (result: object) => JSON.stringify(session('failed', { result: { ...revokedResult, ...result } }));
  const cases: [string, string][] = [
    [JSON.stringify({ ...session('pending'), id: undefined }), 'id'],
    [JSON.stringify(session('done')), 'status'],
    [JSON.stringify(session('pending', { verifier: LEAK })), 'verifier'],
    [JSON.stringify(session('pending', { verifier: { name: `A\u202E${LEAK}` } })), 'verifier'],
    [JSON.stringify(session('pending', { expiresAt: LEAK })), 'expiresAt'],
    [JSON.stringify(session('pending', { serverTime: undefined })), 'serverTime'],
    [JSON.stringify(session('verified')), 'result'],
    [JSON.stringify(session('pending', { result: okResult })), 'result'],
    [JSON.stringify(session('pending', { result: null })), 'result'],
    [JSON.stringify(session('expired', { result: okResult })), 'result'],
    // status and ok must agree
    [JSON.stringify(session('failed', { result: okResult })), 'status'],
    [JSON.stringify(session('verified', { result: revokedResult })), 'status'],
    // a failure carries no claims and no issuer, and names a failing check
    [failedWith({ claims: { ho_ten: LEAK } }), 'result.claims'],
    [failedWith({ issuer: { maToChuc: 'VATVN-0100000001', ten: 'x' } }), 'result.issuer'],
    [failedWith({ issuer: null }), 'result.issuer'],
    [failedWith({ checks: okChecks }), 'result.ok'],
    // a success lists every presentation check, each passed, with issuer and string claims
    [withResult('verified', { checks: okChecks.filter((c) => c.id !== 'status') }), 'result.checks'],
    [withResult('verified', { checks: [...okChecks, okChecks[0]] }), 'result.checks'],
    [withResult('verified', { checks: [...okChecks.slice(1), { id: 'structure', ok: false, code: 'MALFORMED' }] }), 'result.ok'],
    [withResult('verified', { checks: [...okChecks.slice(1), { id: 'structure', ok: true, code: 'MALFORMED' }] }), 'result.checks[8].code'],
    [withResult('verified', { issuer: undefined }), 'result.issuer'],
    [withResult('verified', { issuer: { maToChuc: LEAK, ten: 'x' } }), 'result.issuer'],
    // A slug is not an organisation identifier: the trust list uses VATVN-<tax code> (ADR-0015 section 9).
    [withResult('verified', { issuer: { maToChuc: 'truong-mau', ten: 'x' } }), 'result.issuer'],
    [withResult('verified', { issuer: { maToChuc: 'VATVN-0100000001', ten: `x\u200B${LEAK}` } }), 'result.issuer'],
    [withResult('verified', { claims: undefined }), 'result.claims'],
    [withResult('verified', { claims: {} }), 'result.claims'],
    [withResult('verified', { claims: { nam_tot_nghiep: 2026 } }), 'result.claims'],
    [withResult('verified', { claims: { ho_ten: true } }), 'result.claims'],
    [withResult('verified', { claims: { ho_ten: { nested: LEAK } } }), 'result.claims'],
    [withResult('verified', { claims: [LEAK] }), 'result.claims'],
    [withResult('verified', { claims: { 'ho ten': LEAK } }), 'result.claims'],
    [withResult('verified', { claims: { ho_ten: 'x'.repeat(10_001) } }), 'result.claims'],
    [withResult('verified', { claims: { ho_ten: `Nguyễn\u2066${LEAK}` } }), 'result.claims'],
    [withResult('verified', { claims: { ho_ten: `Nguyễn\uFEFF` } }), 'result.claims'],
    [withResult('verified', { claims: Object.fromEntries(Array.from({ length: 51 }, (_, i) => [`k${i}`, 'v'])) }), 'result.claims'],
    [withResult('verified', { claims: { constructor: LEAK } }), 'result.claims'],
    // JSON.parse keeps "__proto__" as an own key, which is how a hostile server would send it.
    [withResult('verified', {}).replace('"ho_ten"', '"__proto__":{"polluted":true},"ho_ten"'), 'result.claims'],
    [withResult('verified', { checks: [{ id: 'Structure', ok: true, code: null }] }), 'result.checks[0].id'],
    [withResult('verified', { checks: [{ id: 'structure', ok: true, code: 'bad code' }] }), 'result.checks[0].code'],
    [withResult('verified', { checks: [{ id: 'structure', ok: 'yes', code: null }] }), 'result.checks[0].ok'],
    [withResult('verified', { checks: [{ id: 'structure', ok: true, code: null, skipped: false }] }), 'result.checks[0].skipped'],
    [withResult('verified', { checks: [] }), 'result.checks'],
    [withResult('verified', { checks: Array.from({ length: 33 }, () => okChecks[0]) }), 'result.checks'],
    [withResult('verified', { verifiedAt: LEAK }), 'result.verifiedAt'],
    [withResult('verified', { ok: 'true' }), 'result.ok'],
    [`<html>${LEAK}</html>`, 'body is not JSON'],
    ['null', 'body'],
  ];
  for (const [body, path] of cases) {
    const f = fakeFetch([res(200, body)]);
    const err = await createVerifierClient({ baseUrl: BASE, fetch: f.fetch }).getSession(ID).then(
      () => assert.fail(`accepted a session with a bad ${path}`),
      (e: unknown) => e,
    );
    assert.ok(err instanceof VerifierClientError, path);
    assert.equal(err.kind, 'malformed', path);
    assert.equal(err.message, `malformed session response: ${path}`);
    assert.ok(!err.message.includes(LEAK));
  }
  assert.equal(({} as Record<string, unknown>)['polluted'], undefined);
});

test('claims and issuer are copied into fresh objects', async () => {
  const f = fakeFetch([verified()]);
  const s = await createVerifierClient({ baseUrl: BASE, fetch: f.fetch }).getSession(ID);
  assert.deepEqual(s.result?.claims, okResult.claims);
  assert.deepEqual(s.result?.issuer, okResult.issuer);
  assert.notEqual(s.result?.claims, okResult.claims);
});

test('HTTP errors carry status, a code from the closed list and Retry-After, never the server message', async () => {
  const secret = 'ho_ten=Nguyen Van A';
  const cases: [Response, string, number, string | undefined, number | undefined][] = [
    [res(404, { statusCode: 404, code: 'NOT_FOUND', message: secret }), 'not_found', 404, 'NOT_FOUND', undefined],
    [res(429, { statusCode: 429, code: 'RATE_LIMITED', message: secret }, { 'Retry-After': '17' }), 'rate_limited', 429, 'RATE_LIMITED', 17],
    [res(429, { statusCode: 429, code: 'RATE_LIMITED', message: secret }, { 'Retry-After': 'soon' }), 'rate_limited', 429, 'RATE_LIMITED', undefined],
    [res(400, { statusCode: 400, code: 'VALIDATION_FAILED', message: secret }), 'http', 400, 'VALIDATION_FAILED', undefined],
    [res(400, { statusCode: 400, code: 'SCENARIO_UNKNOWN', message: secret }), 'http', 400, undefined, undefined],
    [res(503, { statusCode: 503, code: 'UNAVAILABLE', message: secret }), 'http', 503, 'UNAVAILABLE', undefined],
    [res(500, `<html>${secret}</html>`), 'http', 500, undefined, undefined],
  ];
  for (const [response, kind, status, code, retryAfterSeconds] of cases) {
    const f = fakeFetch([response]);
    const err = await createVerifierClient({ baseUrl: BASE, fetch: f.fetch }).createSession({ verifier: 'v', scenario: 's' }).then(
      () => assert.fail('accepted an error status'),
      (e: unknown) => e,
    );
    assert.ok(err instanceof VerifierClientError);
    assert.equal(err.name, 'VerifierClientError');
    assert.equal(err.kind, kind);
    assert.equal(err.status, status);
    assert.equal(err.code, code);
    assert.equal(err.retryAfterSeconds, retryAfterSeconds);
    assert.equal(err.message, `HTTP ${status}`);
  }
});

test('a fetch rejection is a network error; the default fetch is globalThis.fetch, called on globalThis', async () => {
  const realFetch = globalThis.fetch;
  const receivers: unknown[] = [];
  globalThis.fetch = function (this: unknown) {
    receivers.push(this);
    return Promise.reject(new TypeError('getaddrinfo ENOTFOUND secret.example'));
  } as typeof fetch;
  try {
    await assert.rejects(createVerifierClient({ baseUrl: BASE }).getSession(ID), {
      name: 'VerifierClientError',
      kind: 'network',
      message: 'network error',
    });
    assert.deepEqual(receivers, [globalThis]);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('a request that hangs times out after requestTimeoutMs', async () => {
  const f = fakeFetch([hang]);
  const started = Date.now();
  await assert.rejects(createVerifierClient({ baseUrl: BASE, fetch: f.fetch, requestTimeoutMs: 20 }).getSession(ID), {
    name: 'VerifierClientError',
    kind: 'timeout',
  });
  assert.ok(Date.now() - started < 2_000);
});

test('watchSession polls pending -> request_retrieved -> verified and reports each status once', async () => {
  const w = watch([pending(), pending(), res(200, session('request_retrieved')), res(200, session('request_retrieved')), verified()]);
  const s = await w.promise;
  assert.equal(s.status, 'verified');
  assert.deepEqual(s.result?.claims, okResult.claims);
  assert.deepEqual(w.updates.map((u) => u.status), ['pending', 'request_retrieved', 'verified']);
  assert.equal(w.updates[2], s);
  assert.equal(w.calls.length, 5);
  assert.deepEqual(w.errors, []);
  assert.equal(w.recoveries(), 0);
});

test('watchSession resolves with a failed result and its checks', async () => {
  const w = watch([pending(), res(200, session('failed', { result: revokedResult }))]);
  const s = await w.promise;
  assert.equal(s.status, 'failed');
  assert.deepEqual(s.result, revokedResult);
  assert.deepEqual(w.updates.map((u) => u.status), ['pending', 'failed']);
});

test('watchSession backs off on network errors, timeouts, 5xx and 429, reports recovery, then resets', async () => {
  const w = watch([new TypeError('offline'), res(503, ''), res(429, ''), pending(), new TypeError('offline'), verified()], {
    intervalMs: 2,
    maxBackoffMs: 6,
  });
  const s = await w.promise;
  assert.equal(s.status, 'verified');
  assert.deepEqual(w.errors, [
    { kind: 'network', status: undefined, attempt: 1, retryInMs: 4 },
    { kind: 'http', status: 503, attempt: 2, retryInMs: 6 },
    { kind: 'rate_limited', status: 429, attempt: 3, retryInMs: 6 },
    { kind: 'network', status: undefined, attempt: 1, retryInMs: 4 },
  ]);
  assert.equal(w.recoveries(), 2);
  assert.deepEqual(w.updates.map((u) => u.status), ['pending', 'verified']);
  assert.equal(w.calls.length, 6);
});

test('watchSession waits at least Retry-After on a 429', async () => {
  const w = watch([pending(), res(429, { statusCode: 429, code: 'RATE_LIMITED', message: 'x' }, { 'Retry-After': '0' }), verified()], {
    intervalMs: 2,
  });
  await w.promise;
  assert.deepEqual(w.errors, [{ kind: 'rate_limited', status: 429, attempt: 1, retryInMs: 4 }]);

  const ac = new AbortController();
  const slow = watch([pending(), res(429, '', { 'Retry-After': '3' })], { intervalMs: 2, signal: ac.signal });
  // The fake clock does not move, so expiry (5 minutes away) does not cut the 3 s wait.
  await new Promise((r) => setTimeout(r, 30));
  assert.deepEqual(slow.errors, [{ kind: 'rate_limited', status: 429, attempt: 1, retryInMs: 3000 }]);
  assert.equal(slow.calls.length, 2);
  ac.abort();
  await assert.rejects(slow.promise, { name: 'AbortError' });
});

test('watchSession rejects at once on 404, 400 and a malformed session', async () => {
  for (const [response, kind] of [
    [res(404, { statusCode: 404, code: 'NOT_FOUND', message: 'gone' }), 'not_found'],
    [res(400, ''), 'http'],
    [res(200, session('verified')), 'malformed'],
  ] as const) {
    const w = watch([pending(), response]);
    await assert.rejects(w.promise, { name: 'VerifierClientError', kind });
    assert.equal(w.calls.length, 2);
    assert.deepEqual(w.errors, []);
  }
});

test('watchSession never requests at or after expiresAt and synthesizes expired', async () => {
  const expiresAt = new Date(T0 + 25).toISOString();
  // Each request takes 10 ms of the injected clock.
  const step: Step = (_, tick) => (tick(10), res(200, session('pending', { expiresAt })));
  const w = watch([step, step, step, step, step], { intervalMs: 10 });
  const s = await w.promise;
  assert.equal(s.status, 'expired');
  assert.equal(s.expiresAt, expiresAt);
  assert.equal('result' in s, false);
  assert.deepEqual(w.updates.map((u) => u.status), ['pending', 'expired']);
  // After the request at 10 (clock 20) only 5 ms are left: the wait is cut to expiry and the watch ends
  // there, even though this injected clock does not advance while sleeping.
  assert.deepEqual(w.calls.map((c) => c.at - T0), [0, 10]);
});

test('watchSession decides expiry on the server clock, whatever the local clock says', async () => {
  // The session expires 5 minutes after T0 on the server. Local clocks off by -11, +6, +11 and +31 minutes.
  for (const skewMinutes of [-11, 6, 11, 31]) {
    const localAhead = skewMinutes * 60_000;
    // fakeFetch's local clock starts at T0; the server is behind it by the skew.
    const expiresAt = new Date(T0 - localAhead + 5 * 60_000).toISOString();
    const step = (status: string) => res(200, session(status, { expiresAt, ...(status === 'verified' ? { result: okResult } : {}) }));
    const w = watch([step('pending'), step('pending'), step('verified')], {}, -localAhead);
    const s = await w.promise;
    assert.equal(s.status, 'verified', `skew ${skewMinutes} min`);
    assert.equal(w.calls.length, 3, `skew ${skewMinutes} min`);
  }
});

test('watchSession uses the creation serverTime before its first answer, and stops at expiry when that answer hangs', async () => {
  // Local clock 31 minutes ahead; the session has 40 ms left on the server clock.
  const serverNow = T0 - 31 * 60_000;
  const f = fakeFetch([hang]);
  const updates: string[] = [];
  const started = Date.now();
  const s = await createVerifierClient({ baseUrl: BASE, fetch: f.fetch, requestTimeoutMs: 60_000 }).watchSession(ID, {
    expiresAt: new Date(serverNow + 40).toISOString(),
    serverTime: new Date(serverNow).toISOString(),
    onUpdate: (u) => updates.push(u.status),
  });
  assert.equal(s.status, 'expired');
  assert.equal(s.id, ID);
  assert.deepEqual(updates, ['expired']);
  assert.equal(f.calls.length, 1);
  assert.ok(Date.now() - started < 2_000);
});

test('watchSession clamps its wait to expiresAt instead of sleeping a full interval', async () => {
  const expiresAt = new Date(Date.now() + 30).toISOString();
  const f = fakeFetch([res(200, { ...session('request_retrieved', { expiresAt }), serverTime: new Date().toISOString() })]);
  const started = Date.now();
  const s = await createVerifierClient({ baseUrl: BASE, fetch: f.fetch }).watchSession(ID, { intervalMs: 60_000 });
  assert.equal(s.status, 'expired');
  assert.equal(f.calls.length, 1);
  assert.ok(Date.now() - started < 5_000);
});

test('watchSession with expiresAt already past resolves expired after one request', async () => {
  const w = watch([res(200, session('pending', { expiresAt: new Date(T0).toISOString() }))]);
  assert.equal((await w.promise).status, 'expired');
  assert.deepEqual(w.updates.map((u) => u.status), ['pending', 'expired']);
  assert.equal(w.calls.length, 1);
});

test('watchSession aborted before it starts sends nothing', async () => {
  const ac = new AbortController();
  ac.abort();
  const w = watch([pending()], { signal: ac.signal });
  await assert.rejects(w.promise, { name: 'AbortError' });
  assert.equal(w.calls.length, 0);
  assert.deepEqual(w.updates, []);
});

test('watchSession aborted during a wait clears its timers and calls nothing afterwards', async () => {
  const timers = trackTimers();
  try {
    const ac = new AbortController();
    const w = watch([pending(), pending()], {
      intervalMs: 60_000,
      signal: ac.signal,
      onUpdate: () => void Promise.resolve().then(() => ac.abort()),
    });
    await assert.rejects(w.promise, { name: 'AbortError' });
    assert.equal(w.calls.length, 1);
    assert.equal(timers.live.size, 0);
  } finally {
    timers.restore();
  }
});

test('watchSession aborted during a request aborts the fetch and rejects with the reason', async () => {
  const ac = new AbortController();
  const reason = new Error('user left the page');
  let inFlight: AbortSignal | undefined;
  const w = watch(
    [
      pending(),
      (init) => {
        inFlight = init.signal ?? undefined;
        setTimeout(() => ac.abort(reason), 1);
        return hang(init);
      },
    ],
    { signal: ac.signal },
  );
  await assert.rejects(w.promise, (e) => e === reason);
  assert.equal(inFlight?.aborted, true);
  assert.equal(w.calls.length, 2);
  assert.deepEqual(w.updates.map((u) => u.status), ['pending']);
  assert.deepEqual(w.errors, []);
});

test('an abort is never reported as a network error, even by a fetch that answers late', async () => {
  const ac = new AbortController();
  const late = () => new Promise<Response>((resolve) => setTimeout(() => resolve(verified()), 5));
  const w = watch([pending(), late], { signal: ac.signal, onUpdate: () => setTimeout(() => ac.abort(), 2) });
  await assert.rejects(w.promise, { name: 'AbortError' });
  await new Promise((r) => setTimeout(r, 10));
  assert.deepEqual(w.updates.map((u) => u.status), ['pending']);
  assert.deepEqual(w.errors, []);
});

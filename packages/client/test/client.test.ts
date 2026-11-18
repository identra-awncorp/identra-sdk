// Verifier-session client against a fake fetch: requests, validation, polling, backoff, expiry, abort.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createVerifierClient,
  isTerminalStatus,
  VerifierClientError,
  type VerificationSession,
  type WatchSessionOptions,
} from '@identra/sdk-client';

type Step = Response | Error | ((init: RequestInit, tick: (ms: number) => void) => Promise<Response> | Response);

const BASE = 'https://api.example';
const T0 = Date.parse('2026-11-19T10:00:00.000Z');
const FAR = '2026-11-19T10:05:00.000Z';

const res = (status: number, body: unknown) =>
  new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });

/** Answers requests from a queue and records them; an unexpected request gets a 400 so a watch cannot loop. */
function fakeFetch(steps: Step[]) {
  const calls: { url: string; init: RequestInit; at: number }[] = [];
  let clock = T0;
  const tick = (ms: number) => void (clock += ms);
  const fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    calls.push({ url: String(input), init, at: clock });
    const step = steps.shift();
    if (step === undefined) return res(400, { statusCode: 400, error: 'Bad Request', message: 'unexpected request', code: 'UNEXPECTED' });
    if (step instanceof Error) throw step;
    return typeof step === 'function' ? step(init, tick) : step;
  }) as typeof globalThis.fetch;
  return {
    fetch,
    calls,
    now: () => clock,
  };
}

/** A request that only ends when its signal aborts, like a real fetch. */
const hang = (init: RequestInit) =>
  new Promise<Response>((_, reject) => init.signal?.addEventListener('abort', () => reject(init.signal?.reason)));

const session = (status: string, extra: object = {}) => ({ id: 's1', status, verifier: { name: 'Nhà tuyển dụng mẫu' }, expiresAt: FAR, ...extra });
const okChecks = [
  { id: 'structure', ok: true, code: null },
  { id: 'signature', ok: true, code: null },
];
const okResult = {
  ok: true,
  checks: okChecks,
  claims: { ho_ten: 'Nguyễn Văn A', nganh: 'CNTT', nam_tot_nghiep: 2024, co_bang: true },
  issuer: { maToChuc: 'DH-MAU', ten: 'Đại học Mẫu' },
  verifiedAt: '2026-11-19T10:01:00.000Z',
};
const verified = () => res(200, session('verified', { result: okResult }));
const pending = () => res(200, session('pending'));

function watch(steps: Step[], options: WatchSessionOptions = {}) {
  const f = fakeFetch(steps);
  const updates: VerificationSession[] = [];
  const errors: { kind: string; status: number | undefined; attempt: number; retryInMs: number }[] = [];
  const client = createVerifierClient({ baseUrl: BASE, fetch: f.fetch, now: f.now });
  const promise = client.watchSession('s1', {
    intervalMs: 1,
    ...options,
    onUpdate: (s) => {
      updates.push(s);
      options.onUpdate?.(s);
    },
    onError: (e, info) => errors.push({ kind: e.kind, status: e.status, ...info }),
  });
  return { ...f, promise, updates, errors };
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

test('createSession posts JSON to the sessions route, without cookies, and accepts any 2xx', async () => {
  const f = fakeFetch([res(201, { id: 'abc', qr: 'openid4vp://?client_id=x&request_uri=y', expiresAt: FAR, extra: 1 })]);
  const client = createVerifierClient({ baseUrl: `${BASE}///`, fetch: f.fetch });
  const created = await client.createSession({ verifier: 'nha-tuyen-dung-mau', scenario: 'ung-tuyen' });
  assert.deepEqual(created, { id: 'abc', qr: 'openid4vp://?client_id=x&request_uri=y', expiresAt: FAR });
  assert.equal(f.calls.length, 1);
  const { url, init } = f.calls[0]!;
  assert.equal(url, `${BASE}/v1/verification/sessions`);
  assert.equal(init.method, 'POST');
  assert.equal(init.credentials, 'omit');
  assert.deepEqual(init.headers, { Accept: 'application/json', 'Content-Type': 'application/json' });
  assert.deepEqual(JSON.parse(String(init.body)), { verifier: 'nha-tuyen-dung-mau', scenario: 'ung-tuyen' });
});

test('createSession rejects a malformed answer', async () => {
  const good = { id: 'abc', qr: 'openid4vp://?x', expiresAt: FAR };
  const cases: [unknown, string][] = [
    [{ ...good, qr: 'https://evil.example/?x' }, 'qr'],
    [{ ...good, qr: `openid4vp://${'a'.repeat(4096)}` }, 'qr'],
    [{ ...good, id: '' }, 'id'],
    [{ ...good, id: 'a'.repeat(257) }, 'id'],
    [{ ...good, expiresAt: 'soon' }, 'expiresAt'],
    [[good], 'body'],
  ];
  for (const [body, path] of cases) {
    const f = fakeFetch([res(200, body)]);
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
    issuer: null,
    verifiedAt: '2026-11-19T10:01:00.000Z',
  };
  const f = fakeFetch([res(200, session('failed', { result: failing }))]);
  const client = createVerifierClient({ baseUrl: `${BASE}/`, fetch: f.fetch });
  const s = await client.getSession('a/b?c');
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
    issuer: null,
    verifiedAt: '2026-11-19T10:01:00.000Z',
  });
  assert.equal('claims' in s.result!, false);
});

test('getSession rejects malformed sessions at the trust boundary, naming only the field', async () => {
  const LEAK = 'LEAK-Nguyen-Van-A';
  const withResult = (status: string, result: object) => JSON.stringify(session(status, { result: { ...okResult, ...result } }));
  const cases: [string, string][] = [
    [JSON.stringify({ status: 'pending', verifier: { name: 'v' }, expiresAt: FAR }), 'id'],
    [JSON.stringify(session('done')), 'status'],
    [JSON.stringify(session('pending', { verifier: LEAK })), 'verifier'],
    [JSON.stringify(session('pending', { expiresAt: LEAK })), 'expiresAt'],
    [JSON.stringify(session('verified')), 'result'],
    [JSON.stringify(session('pending', { result: okResult })), 'result'],
    [JSON.stringify(session('expired', { result: okResult })), 'result'],
    [withResult('failed', { ok: false }), 'result.claims'],
    [withResult('verified', { claims: { ho_ten: { nested: LEAK } } }), 'result.claims'],
    [withResult('verified', { claims: [LEAK] }), 'result.claims'],
    [withResult('verified', { claims: { 'ho ten': LEAK } }), 'result.claims'],
    [withResult('verified', { claims: { ho_ten: 'x'.repeat(10_001) } }), 'result.claims'],
    [withResult('verified', { claims: Object.fromEntries(Array.from({ length: 51 }, (_, i) => [`k${i}`, 1])) }), 'result.claims'],
    [withResult('verified', { claims: { constructor: LEAK } }), 'result.claims'],
    // JSON.parse keeps "__proto__" as an own key, which is how a hostile server would send it.
    [withResult('verified', {}).replace('"ho_ten"', '"__proto__":{"polluted":true},"ho_ten"'), 'result.claims'],
    [withResult('verified', { checks: [...okChecks, { id: 'status', ok: false, code: 'REVOKED' }] }), 'result.ok'],
    [withResult('verified', { checks: [{ id: 'Structure', ok: true, code: null }] }), 'result.checks[0].id'],
    [withResult('verified', { checks: [{ id: 'structure', ok: true, code: 'bad code' }] }), 'result.checks[0].code'],
    [withResult('verified', { checks: [{ id: 'structure', ok: 'yes', code: null }] }), 'result.checks[0].ok'],
    [withResult('verified', { checks: [{ id: 'structure', ok: true, code: null, skipped: false }] }), 'result.checks[0].skipped'],
    [withResult('verified', { checks: Array.from({ length: 33 }, () => okChecks[0]) }), 'result.checks'],
    [withResult('verified', { issuer: { maToChuc: LEAK } }), 'result.issuer'],
    [withResult('verified', { verifiedAt: LEAK }), 'result.verifiedAt'],
    [withResult('verified', { ok: 'true' }), 'result.ok'],
    [`<html>${LEAK}</html>`, 'body is not JSON'],
    ['null', 'body'],
  ];
  for (const [body, path] of cases) {
    const f = fakeFetch([res(200, body)]);
    const err = await createVerifierClient({ baseUrl: BASE, fetch: f.fetch }).getSession('s1').then(
      () => assert.fail(`accepted a session with a bad ${path}`),
      (e: unknown) => e,
    );
    assert.ok(err instanceof VerifierClientError, path);
    assert.equal(err.kind, 'malformed', path);
    assert.equal(err.message, `malformed session response: ${path}`);
  }
  assert.equal(({} as Record<string, unknown>)['polluted'], undefined);
});

test('claims are copied into a fresh object with only well-formed keys and values', async () => {
  const f = fakeFetch([verified()]);
  const s = await createVerifierClient({ baseUrl: BASE, fetch: f.fetch }).getSession('s1');
  assert.deepEqual(s.result?.claims, okResult.claims);
  assert.deepEqual(s.result?.issuer, okResult.issuer);
  assert.notEqual(s.result?.claims, okResult.claims);
});

test('HTTP errors carry status and a well-formed code, never the server message', async () => {
  const secret = 'ho_ten=Nguyen Van A';
  const cases: [Response, string, number, string | undefined][] = [
    [res(404, { statusCode: 404, error: 'Not Found', message: secret, code: 'SESSION_NOT_FOUND' }), 'not_found', 404, 'SESSION_NOT_FOUND'],
    [res(429, { statusCode: 429, error: 'Too Many Requests', message: secret }), 'rate_limited', 429, undefined],
    [res(400, { statusCode: 400, error: 'Bad Request', message: secret, code: 'SCENARIO_UNKNOWN' }), 'http', 400, 'SCENARIO_UNKNOWN'],
    [res(400, { statusCode: 400, error: 'Bad Request', message: secret, code: `bad ${secret}` }), 'http', 400, undefined],
    [res(500, `<html>${secret}</html>`), 'http', 500, undefined],
  ];
  for (const [response, kind, status, code] of cases) {
    const f = fakeFetch([response]);
    const err = await createVerifierClient({ baseUrl: BASE, fetch: f.fetch }).createSession({ verifier: 'v', scenario: 's' }).then(
      () => assert.fail('accepted an error status'),
      (e: unknown) => e,
    );
    assert.ok(err instanceof VerifierClientError);
    assert.ok(err instanceof Error);
    assert.equal(err.name, 'VerifierClientError');
    assert.equal(err.kind, kind);
    assert.equal(err.status, status);
    assert.equal(err.code, code);
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
    await assert.rejects(createVerifierClient({ baseUrl: BASE }).getSession('s1'), {
      name: 'VerifierClientError',
      kind: 'network',
      message: 'network error',
    });
    assert.deepEqual(receivers, [globalThis]);
  } finally {
    globalThis.fetch = realFetch;
  }
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
});

test('watchSession resolves with a failed result and its checks', async () => {
  const failed = { ok: false, checks: [{ id: 'signature', ok: false, code: 'SIGNATURE_INVALID' }], issuer: null, verifiedAt: okResult.verifiedAt };
  const w = watch([pending(), res(200, session('failed', { result: failed }))]);
  const s = await w.promise;
  assert.equal(s.status, 'failed');
  assert.deepEqual(s.result, failed);
  assert.deepEqual(w.updates.map((u) => u.status), ['pending', 'failed']);
});

test('watchSession backs off on network errors, 5xx and 429, then resets after a success', async () => {
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
  assert.deepEqual(w.updates.map((u) => u.status), ['pending', 'verified']);
  assert.equal(w.calls.length, 6);
});

test('watchSession rejects at once on 404, 400 and a malformed session', async () => {
  for (const [response, kind] of [
    [res(404, ''), 'not_found'],
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
  assert.deepEqual(s, { id: 's1', status: 'expired', verifier: { name: 'Nhà tuyển dụng mẫu' }, expiresAt });
  assert.deepEqual(w.updates.map((u) => u.status), ['pending', 'expired']);
  // After the request at 10 (clock 20) only 5 ms are left: the wait is cut to expiry and the watch ends
  // there, even though this injected clock does not advance while sleeping.
  assert.deepEqual(w.calls.map((c) => c.at - T0), [0, 10]);
});

test('watchSession clamps its wait to expiresAt instead of sleeping a full interval', async () => {
  const expiresAt = new Date(Date.now() + 30).toISOString();
  const f = fakeFetch([res(200, session('request_retrieved', { expiresAt }))]);
  const started = Date.now();
  const s = await createVerifierClient({ baseUrl: BASE, fetch: f.fetch }).watchSession('s1', { intervalMs: 60_000 });
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

test('watchSession aborted during a wait clears its timer and calls nothing afterwards', async () => {
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

# @identra/sdk-client

Browser client for Identra verifier sessions (identra-server `docs/vc-api.md` sections 2 and 6): create a
session, show its QR payload, follow it to the validated result. No runtime dependencies; `Check`,
`CheckId` and `ErrorCode` are type-only imports from `@identra/sdk-core`.

```ts
import { createVerifierClient, isValidVerifierQr } from '@identra/sdk-client';

const client = createVerifierClient({ baseUrl: 'https://api-identra.awncorp.vn' });
const created = await client.createSession({ verifier: 'nha-tuyen-dung-mau', scenario: 'ung-tuyen' });
// created.qr is already checked to be openid4vp://?client_id=x509_hash:…&request_uri=<api>/oid4vp/request/<id>
const final = await client.watchSession(created.id, {
  signal,                                 // abort on unmount: no request and no callback afterwards
  expiresAt: created.expiresAt,           // with serverTime, lets the watch stop at expiry even if
  serverTime: created.serverTime,         //   its first request hangs
  onUpdate: (session) => render(session), // first answer and every status change
  onError: (error, { retryInMs }) => showReconnecting(),
  onRecover: () => hideReconnecting(),
});
```

- **Server clock.** Every response carries `serverTime`; expiry decisions use the server's clock
  (`serverClockOffset(serverTime, Date.now())` gives the offset for a page's own countdown).
- **Timeouts and retries.** Each request times out after 10 s (`requestTimeoutMs`). Network errors,
  timeouts, 5xx and 429 are retried with backoff, never sooner than a 429's `Retry-After` and never after
  expiry; 404 and other 4xx reject (`not_found` means the session is gone: show it as expired).
- **Validation.** Responses are validated before use: the closed status list; `result` only when final
  and `verified` ⇔ `result.ok`; a success lists all nine presentation checks, passed, with an issuer and
  string claims; a failure has neither. Text with control, bidirectional-override or zero-width characters
  is rejected. Errors carry `kind`, `status`, the section 2 `code` and `retryAfterSeconds`; messages never
  carry response text.

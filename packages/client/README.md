# @identra/sdk-client

Browser client for Identra verifier sessions (identra-server `docs/vc-api.md` sections 2 and 6): create a
session, show its QR payload, follow it to the validated result. The only runtime import is
`UNSAFE_DISPLAY_TEXT` from `@identra/sdk-core/text` (a one-line module); `Check`, `CheckId` and
`ErrorCode` are type-only imports from `@identra/sdk-core`.

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
- **Validation.** Responses are validated before use: the session `id` is the one requested; the closed status list; `result` only when final
  and `verified` ⇔ `result.ok`; a success lists all nine presentation checks of its trust path
  (`PRESENTATION_CHECK_IDS`, or `DID_PRESENTATION_CHECK_IDS` with `did_resolution` in place of
  `certificate_chain`), passed, and string claims, with `trustPath: 'x509'` and an `issuer`
  `{ maToChuc, ten }` (a result without `trustPath` reads as `x509`), or `trustPath: 'did'` and an
  `issuerDid` that is a `did:certnet` DID, with no `issuer` (ADR-0020: that path has no name; show the
  shortened DID); a failure has none of these. Text with any character of `UNSAFE_DISPLAY_TEXT` (controls,
  bidirectional marks, overrides and isolates, zero-width characters, line and paragraph separators, the
  BOM, the soft hyphen, tag characters) is rejected. Errors carry `kind`, `status`, the section 2 `code` and `retryAfterSeconds`; messages never
  carry response text.

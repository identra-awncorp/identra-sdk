// What every protocol operation of sdk-server returns: a response ready to send. A controller
// writes `status`, `headers` and `body` unchanged.

export interface HttpRequest {
  /** Header names in lower case, as Node delivers them. */
  headers: Record<string, string | undefined>;
  /** The raw body text, not parsed by the framework. */
  body: string;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export function jsonResponse(status: number, value: unknown, headers: Record<string, string> = {}): HttpResponse {
  return { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers }, body: JSON.stringify(value) };
}

/**
 * OAuth 2.0 error response (RFC 6749 section 5.2, RFC 6750 section 3.1). The description is a
 * fixed text of ours: never a library message, never a value from the request.
 */
export function oauthError(status: number, error: string, description: string): HttpResponse {
  const extra: Record<string, string> = status === 401 ? { 'WWW-Authenticate': `Bearer error="${error}"` } : {};
  return jsonResponse(status, { error, error_description: description }, extra);
}

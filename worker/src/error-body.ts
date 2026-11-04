/**
 * A constant error body for one failure class, with the exception's detail
 * logged server-side and never returned (notme-b567c9).
 *
 * An exception's message is written for an operator: a verifier's "wrong
 * audience: <expected>", a Durable Object's SQLite error, a key-import
 * library's parse failure. Concatenated into a response it reaches whoever
 * sent the request — the shape of the challenge leak fixed in review M1 of
 * notme-3dfe15, where @simplewebauthn named the expected challenge. Each
 * route says WHICH class failed with `message`, a fixed string; what went
 * wrong inside is in the log.
 *
 * 5xx is logged as an error (the server failed); 4xx as a warning (the
 * request did). src/__tests__/error-body-guard.test.ts fails on any response
 * built from an exception's message, so this is the one place to put one.
 */
export function opaqueError(
  tag: string,
  message: string,
  status: number,
  e: unknown,
): Response {
  const detail = e instanceof Error ? e.message : String(e);
  (status >= 500 ? console.error : console.warn)(`[${tag}] ${message}:`, detail);
  return Response.json({ error: message }, { status });
}

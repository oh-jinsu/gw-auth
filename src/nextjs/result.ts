import type { AuthError, AuthResult } from "gw-auth/core";

/** Authentication error safe to serialize across a Next.js boundary. */
export type NextAuthError = Pick<AuthError, "kind" | "code" | "message">;

/** JSON-safe success or failure envelope shared by Next.js adapters. */
export type NextAuthResponse<TValue> =
  | { ok: true; value?: TValue }
  | { ok: false; error: NextAuthError };

/** Removes internal causes before an authentication error crosses an HTTP boundary. */
export function publicAuthError(error: AuthError): NextAuthError {
  return {
    kind: error.kind,
    code: error.code,
    message: error.message,
  };
}

/** Converts a core result to the serializable Next.js adapter contract. */
export function nextAuthResponse<TValue>(
  result: AuthResult<TValue>,
): NextAuthResponse<TValue> {
  if (result.isErr) {
    return { ok: false, error: publicAuthError(result.error) };
  }

  return result.value === undefined
    ? { ok: true }
    : { ok: true, value: result.value };
}

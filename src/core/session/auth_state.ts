import type { AuthState, SessionAccessPayload } from "../jwt_payload";

const managedAuthClaims = [
  "aud",
  "exp",
  "iat",
  "iss",
  "jti",
  "nbf",
  "sessionId",
  "sub",
  "tokenUse",
  "userId",
] as const;

/** Builds browser-safe authentication state while removing every core-managed claim. */
export function createAuthenticationState<TClaims extends Record<string, unknown>>(
  claims: Record<string, unknown>,
  userId: string,
  sessionId: string,
): AuthState<TClaims> {
  const publicClaims = { ...claims };

  for (const claim of managedAuthClaims) {
    delete publicClaims[claim];
  }

  return { ...publicClaims, userId, sessionId } as AuthState<TClaims>;
}

/** Removes JWT transport metadata from a verified access-token payload. */
export function authStateFromAccessPayload<TClaims extends Record<string, unknown>>(
  payload: SessionAccessPayload<TClaims>,
): AuthState<TClaims> {
  return createAuthenticationState<TClaims>(payload, payload.userId, payload.sessionId);
}

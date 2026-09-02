import type { AuthState, SessionAccessPayload } from "gw-auth/core";

/** Removes JWT metadata before verified access claims cross a browser boundary. */
export function publicAuthState<TClaims extends Record<string, unknown>>(
  payload: SessionAccessPayload<TClaims>,
): AuthState<TClaims> {
  const {
    aud,
    exp,
    iat,
    iss,
    jti,
    nbf,
    sub,
    tokenUse,
    userId,
    sessionId,
    ...claims
  } = payload;

  return { ...claims, userId, sessionId } as unknown as AuthState<TClaims>;
}

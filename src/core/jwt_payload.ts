import type { JWTPayload } from "jose";

/** Browser-safe authentication state returned without either bearer token. */
export type AuthState<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> = TClaims & { userId: string; sessionId: string };

/** Verified short-lived access-token claims. */
export type SessionAccessPayload<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> = JWTPayload & AuthState<TClaims> & {
  tokenUse: "access";
};

/** Verified rotating refresh-token claims. */
export type SessionRefreshPayload<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> = JWTPayload & AuthState<TClaims> & {
  tokenUse: "refresh";
  jti: string;
};

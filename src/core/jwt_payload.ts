import type { JWTPayload } from "jose";

type ManagedAuthClaim =
  | "aud"
  | "exp"
  | "iat"
  | "iss"
  | "jti"
  | "nbf"
  | "sessionId"
  | "sub"
  | "tokenUse"
  | "userId";

/** Browser-safe authentication state returned without either bearer token. */
export type AuthState<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> = Omit<TClaims, ManagedAuthClaim> & { userId: string; sessionId: string };

/** Verified short-lived access-token claims. */
export type SessionAccessPayload<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> = JWTPayload & AuthState<TClaims> & {
  tokenUse: "access";
};

/** Verified rotating refresh-token claims. */
export type SessionRefreshPayload<
  _TClaims extends Record<string, unknown> = Record<string, unknown>,
> = JWTPayload & {
  userId: string;
  sessionId: string;
  tokenUse: "refresh";
  jti: string;
};

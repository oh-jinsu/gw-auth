import { ok, resultFrom } from "gw-result";
import { decodeJwt } from "jose";

import { authSystemError } from "../auth_error";
import { hashCredential } from "../credential";
import type { SessionRefreshPayload } from "../jwt_payload";
import { JWTManager, type JwtSignPayload } from "../jwt_manager";
import type { RefreshSession, RefreshTokenState } from "./session_repository";

/** Newly signed refresh bearer and the non-secret state needed to persist it. */
export type IssuedRefreshToken = {
  token: string;
  state: RefreshTokenState;
};

/** Signs a claim-minimal refresh token and derives its persisted state. */
export async function issueRefreshToken(
  manager: JWTManager<SessionRefreshPayload>,
  userId: string,
  sessionId: string,
) {
  const tokenId = crypto.randomUUID();
  const signed = await manager.sign(refreshClaims(userId, sessionId, tokenId));

  return signed.isErr ? signed : createIssuedRefreshToken(signed.value, tokenId);
}

/** Recreates the exact current bearer after an accepted concurrent refresh. */
export async function recreateRefreshToken(
  manager: JWTManager<SessionRefreshPayload>,
  session: RefreshSession,
) {
  const claims = refreshClaims(session.userId, session.id, session.tokenId);
  const signed = await manager.signAt(claims, session.issuedAt, session.expiresAt);

  if (signed.isErr) {
    return authSystemError("recreate_refresh_token", signed.error);
  }

  const hash = await hashCredential(signed.value);

  return hash.isErr || hash.value !== session.tokenHash
    ? authSystemError("recreate_refresh_token", hash.isErr ? hash.error : undefined)
    : signed;
}

/** Builds the only application claims carried by a refresh token. */
function refreshClaims(userId: string, sessionId: string, tokenId: string) {
  return { userId, sessionId, jti: tokenId } as JwtSignPayload<SessionRefreshPayload>;
}

/** Hashes a freshly signed bearer and records its exact JWT timestamps. */
async function createIssuedRefreshToken(token: string, tokenId: string) {
  const hash = await hashCredential(token);
  const decoded = resultFrom(() => decodeJwt(token));

  if (hash.isErr) {
    return authSystemError("read_issued_refresh_token", hash.error);
  }

  if (decoded.isErr) {
    return authSystemError("read_issued_refresh_token", decoded.error);
  }

  const { iat, exp } = decoded.value;

  return typeof iat !== "number" || typeof exp !== "number"
    ? authSystemError("read_issued_refresh_token_timestamps", undefined)
    : ok({ token, state: refreshTokenState(hash.value, tokenId, iat, exp) });
}

/** Converts decoded JWT metadata to the persistence contract. */
function refreshTokenState(
  tokenHash: string,
  tokenId: string,
  issuedAt: number,
  expiresAt: number,
): RefreshTokenState {
  return {
    tokenHash,
    tokenId,
    issuedAt: new Date(issuedAt * 1000),
    expiresAt: new Date(expiresAt * 1000),
  };
}

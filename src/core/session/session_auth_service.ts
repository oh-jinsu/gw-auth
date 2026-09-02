import { ok, resultFrom } from "gw-result";

import type {
  AuthState,
  SessionAccessPayload,
  SessionRefreshPayload,
} from "../jwt_payload";
import { authError, authSystemError } from "../auth_error";
import { hashCredential } from "../credential";
import { JWTManager, type JwtSignPayload } from "../jwt_manager";
import type {
  RefreshSession,
  SessionRepository,
  SessionUser,
  SessionUserRepository,
} from "./session_repository";

/** Access and refresh credentials plus browser-safe authentication state. */
export type SessionTokenPair<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> = {
  accessToken: string;
  refreshToken: string;
  auth: AuthState<TClaims>;
};

/** Coordinates purpose-bound JWTs with rotating, server-side refresh sessions. */
export class SessionAuthService<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> {
  /** Creates a session service and rejects token managers with the wrong purposes. */
  constructor(
    private readonly repository: SessionRepository,
    private readonly users: SessionUserRepository<TClaims>,
    private readonly accessTokens: JWTManager<SessionAccessPayload<TClaims>>,
    private readonly refreshTokens: JWTManager<SessionRefreshPayload<TClaims>>,
  ) {
    if (accessTokens.tokenUse !== "access" || refreshTokens.tokenUse !== "refresh") {
      throw new TypeError("Session token managers must use access and refresh purposes.");
    }
  }

  /** Verifies an access token and translates generic token failures for callers. */
  async verifyAccessToken(token: string) {
    const verified = await this.accessTokens.verify(token);

    return verified.isErr
      ? authError("INVALID_ACCESS_TOKEN", "액세스 토큰이 유효하지 않습니다.", verified.error)
      : verified;
  }

  /** Creates an independent session and returns a newly signed token pair. */
  async issueTokenPair(user: SessionUser<TClaims>) {
    const sessionId = crypto.randomUUID();
    const signed = await this.signTokenPair(user, sessionId);

    if (signed.isErr) {
      return signed;
    }

    const session = await this.newSession(user.id, sessionId, signed.value.refreshToken);

    if (session.isErr) {
      return session;
    }

    const created = await resultFrom(() => this.repository.createRefreshSession(session.value));

    return created.isErr
      ? authSystemError("create_refresh_session", created.error)
      : ok(signed.value);
  }

  /** Rotates both tokens and revokes the session if an old token is replayed. */
  async refreshTokenPair(refreshToken: string) {
    const found = await this.validSession(refreshToken, true);

    return found.isErr ? found : this.rotateSession(found.value);
  }

  /** Revokes only the session represented by the current refresh token. */
  async revokeSession(refreshToken: string) {
    const found = await this.validSession(refreshToken, false);

    if (found.isErr) {
      return found;
    }

    const deleted = await resultFrom(() => this.repository.deleteRefreshSession(found.value.id));

    return deleted.isErr
      ? authSystemError("delete_refresh_session", deleted.error)
      : ok();
  }

  /** Removes expired refresh-session rows through an explicit maintenance operation. */
  async deleteExpiredSessions(before = new Date()) {
    const deleted = await resultFrom(() => this.repository.deleteExpiredRefreshSessions(before));

    return deleted.isErr
      ? authSystemError("delete_expired_refresh_sessions", deleted.error)
      : deleted;
  }

  /** Loads current user claims, signs replacements, and performs compare-and-swap rotation. */
  private async rotateSession(session: RefreshSession) {
    const loaded = await resultFrom(() => this.users.findSessionUser(session.userId));

    if (loaded.isErr) {
      return authSystemError("find_session_user", loaded.error);
    }

    if (!loaded.value) {
      return authError("SESSION_USER_NOT_FOUND", "세션 사용자를 찾을 수 없습니다.");
    }

    const signed = await this.signTokenPair(loaded.value, session.id);

    if (signed.isErr) {
      return signed;
    }

    const next = await this.newSession(loaded.value.id, session.id, signed.value.refreshToken);

    if (next.isErr) {
      return next;
    }

    const rotated = await resultFrom(() => this.repository.rotateRefreshSession(
      session.id,
      session.tokenHash,
      next.value.tokenHash,
      next.value.expiresAt,
    ));

    if (rotated.isErr) {
      return authSystemError("rotate_refresh_session", rotated.error);
    }

    if (!rotated.value) {
      return this.revokeReusedSession(session.id);
    }

    return ok(signed.value);
  }

  /** Verifies the token, persisted hash, expiry, and user/session binding. */
  private async validSession(refreshToken: string, revokeOnReuse: boolean) {
    const verified = await this.refreshTokens.verify(refreshToken);

    if (verified.isErr) {
      return invalidRefreshToken(verified.error);
    }

    const loaded = await resultFrom(() =>
      this.repository.findRefreshSession(verified.value.sessionId),
    );

    if (loaded.isErr) {
      return authSystemError("find_refresh_session", loaded.error);
    }

    if (!loaded.value || loaded.value.expiresAt <= new Date()) {
      return invalidRefreshToken();
    }

    if (loaded.value.userId !== verified.value.userId) {
      return authError(
        "SESSION_USER_MISMATCH",
        "세션과 토큰의 사용자 정보가 일치하지 않습니다.",
      );
    }

    const hash = await hashCredential(refreshToken);

    if (hash.isErr) {
      return hash;
    }

    if (hash.value !== loaded.value.tokenHash) {
      return revokeOnReuse
        ? this.revokeReusedSession(loaded.value.id)
        : invalidRefreshToken();
    }

    return ok(loaded.value);
  }

  /** Revokes a compromised token family after stale-token reuse or a lost CAS race. */
  private async revokeReusedSession(sessionId: string) {
    const deleted = await resultFrom(() => this.repository.deleteRefreshSession(sessionId));

    return deleted.isErr
      ? authSystemError("revoke_reused_refresh_session", deleted.error)
      : authError("REFRESH_TOKEN_REUSED", "재사용된 리프레시 토큰입니다.");
  }

  /** Signs access and refresh tokens from one immutable authentication state. */
  private async signTokenPair(user: SessionUser<TClaims>, sessionId: string) {
    const auth = authenticationState(user, sessionId);
    const accessClaims = auth as unknown as JwtSignPayload<SessionAccessPayload<TClaims>>;
    const accessToken = await this.accessTokens.sign(accessClaims);

    if (accessToken.isErr) {
      return accessToken;
    }

    const refreshClaims = {
      ...auth,
      jti: crypto.randomUUID(),
    } as unknown as JwtSignPayload<SessionRefreshPayload<TClaims>>;
    const refreshToken = await this.refreshTokens.sign(refreshClaims);

    return refreshToken.isErr
      ? refreshToken
      : ok({ accessToken: accessToken.value, refreshToken: refreshToken.value, auth });
  }

  /** Creates the persisted hash and expiry for a freshly signed refresh token. */
  private async newSession(userId: string, id: string, refreshToken: string) {
    const hash = await hashCredential(refreshToken);

    if (hash.isErr) {
      return hash;
    }

    const expiration = JWTManager.getExpirationTime(refreshToken);

    return expiration.isErr
      ? expiration
      : ok({ id, userId, tokenHash: hash.value, expiresAt: expiration.value });
  }
}

/** Builds browser-safe state while preventing custom claims from overriding identifiers. */
function authenticationState<
  TClaims extends Record<string, unknown>,
>(user: SessionUser<TClaims>, sessionId: string): AuthState<TClaims> {
  return { ...user.claims, userId: user.id, sessionId };
}

/** Creates the public refresh-token rejection while preserving a verification cause. */
function invalidRefreshToken(cause?: unknown) {
  return authError(
    "INVALID_REFRESH_TOKEN",
    "리프레시 토큰이 유효하지 않습니다.",
    cause,
  );
}

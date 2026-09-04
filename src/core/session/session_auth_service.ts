import { ok, resultFrom } from "gw-result";

import type { AuthState, SessionAccessPayload, SessionRefreshPayload } from "../jwt_payload";
import { authError, authSystemError } from "../auth_error";
import { hashCredential } from "../credential";
import { JWTManager, type JwtSignPayload } from "../jwt_manager";
import { createAuthenticationState } from "./auth_state";
import { issueRefreshToken, recreateRefreshToken } from "./refresh_token";
import type {
  NewRefreshSession,
  RefreshSession,
  SessionRepository,
  SessionUser,
  SessionUserRepository,
} from "./session_repository";

const concurrentRefreshWindowMs = 10_000;

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
    private readonly refreshTokens: JWTManager<SessionRefreshPayload>,
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

    const session: NewRefreshSession = {
      id: sessionId,
      userId: user.id,
      previousTokenHash: null,
      rotatedAt: signed.value.refresh.issuedAt,
      ...signed.value.refresh,
    };
    const created = await resultFrom(() => this.repository.createRefreshSession(session));

    return created.isErr
      ? authSystemError("create_refresh_session", created.error)
      : ok(signed.value.tokens);
  }

  /** Rotates tokens, tolerating prior-token overlap for at most ten seconds. */
  async refreshTokenPair(refreshToken: string) {
    const candidate = await this.refreshCandidate(refreshToken);

    return candidate.isErr ? candidate : this.rotateSession(candidate.value);
  }

  /** Revokes only the session represented by the current refresh token. */
  async revokeSession(refreshToken: string) {
    const found = await this.currentSession(refreshToken);

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

  /** Loads current claims, signs replacements, and requests one atomic rotation. */
  private async rotateSession(candidate: RefreshCandidate) {
    const loaded = await resultFrom(() => this.users.findSessionUser(candidate.userId));

    if (loaded.isErr) {
      return authSystemError("find_session_user", loaded.error);
    }

    if (!loaded.value) {
      return authError("SESSION_USER_NOT_FOUND", "세션 사용자를 찾을 수 없습니다.");
    }

    const signed = await this.signTokenPair(loaded.value, candidate.sessionId);

    if (signed.isErr) {
      return signed;
    }

    const now = new Date();
    const rotated = await resultFrom(() => this.repository.rotateRefreshSession({
      sessionId: candidate.sessionId,
      userId: candidate.userId,
      expectedTokenHash: candidate.tokenHash,
      next: signed.value.refresh,
      now,
      reuseWindowStart: new Date(now.getTime() - concurrentRefreshWindowMs),
    }));

    if (rotated.isErr) {
      return authSystemError("rotate_refresh_session", rotated.error);
    }

    if (rotated.value.status === "rotated") {
      return ok(signed.value.tokens);
    }

    if (rotated.value.status === "concurrent") {
      if (rotated.value.session.id !== candidate.sessionId
        || rotated.value.session.userId !== candidate.userId) {
        return authSystemError("rotate_refresh_session_result", undefined);
      }

      return this.concurrentTokenPair(loaded.value, rotated.value.session);
    }

    return rotated.value.status === "reused"
      ? authError("REFRESH_TOKEN_REUSED", "재사용된 리프레시 토큰입니다.")
      : invalidRefreshToken();
  }

  /** Returns the persisted winner to a request that lost a valid refresh race. */
  private async concurrentTokenPair(user: SessionUser<TClaims>, session: RefreshSession) {
    const refreshToken = await recreateRefreshToken(this.refreshTokens, session);

    return refreshToken.isErr
      ? refreshToken
      : this.signAccessPair(user, session.id, refreshToken.value);
  }

  /** Verifies and hashes a refresh bearer without making a reuse decision. */
  private async refreshCandidate(refreshToken: string) {
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

    return hash.isErr
      ? hash
      : ok({
        sessionId: verified.value.sessionId,
        userId: verified.value.userId,
        tokenHash: hash.value,
        session: loaded.value,
      });
  }

  /** Requires the presented bearer to match the current persisted token. */
  private async currentSession(refreshToken: string) {
    const candidate = await this.refreshCandidate(refreshToken);

    if (candidate.isErr) {
      return candidate;
    }

    return candidate.value.session.tokenHash !== candidate.value.tokenHash
      ? invalidRefreshToken()
      : ok(candidate.value.session);
  }

  /** Signs a refresh token and its matching access pair. */
  private async signTokenPair(user: SessionUser<TClaims>, sessionId: string) {
    const refresh = await issueRefreshToken(this.refreshTokens, user.id, sessionId);

    if (refresh.isErr) {
      return authSystemError("sign_refresh_token", refresh.error);
    }

    const tokens = await this.signAccessPair(user, sessionId, refresh.value.token);

    return tokens.isErr ? tokens : ok({ tokens: tokens.value, refresh: refresh.value.state });
  }

  /** Signs an access token around one supplied current refresh bearer. */
  private async signAccessPair(
    user: SessionUser<TClaims>,
    sessionId: string,
    refreshToken: string,
  ) {
    const auth = createAuthenticationState<TClaims>(user.claims, user.id, sessionId);
    const claims = auth as unknown as JwtSignPayload<SessionAccessPayload<TClaims>>;
    const accessToken = await this.accessTokens.sign(claims);

    return accessToken.isErr
      ? authSystemError("sign_access_token", accessToken.error)
      : ok({ accessToken: accessToken.value, refreshToken, auth });
  }
}

/** Verified identifiers and bearer hash submitted for one refresh attempt. */
type RefreshCandidate = {
  sessionId: string;
  userId: string;
  tokenHash: string;
  session: RefreshSession;
};

/** Creates the public refresh-token rejection while preserving a verification cause. */
function invalidRefreshToken(cause?: unknown) {
  return authError(
    "INVALID_REFRESH_TOKEN",
    "리프레시 토큰이 유효하지 않습니다.",
    cause,
  );
}

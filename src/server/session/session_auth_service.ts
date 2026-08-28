import { exception, ok, resultFrom } from "gw-result";

import { JWTManager } from "../jwt_manager";
import type { SessionAccessPayload, SessionRefreshPayload } from "./session_payload";
import type { RefreshSession, SessionRepository, SessionUser } from "./session_repository";

export type SessionTokenPair = {
  accessToken: string;
  refreshToken: string;
};

export class SessionAuthService {
  constructor(
    private readonly repository: SessionRepository,
    private readonly accessTokens: JWTManager<SessionAccessPayload>,
    private readonly refreshTokens: JWTManager<SessionRefreshPayload>,
  ) {}

  verifyAccessToken(token: string) {
    return this.accessTokens.verify(token);
  }

  async issueTokenPair(user: SessionUser) {
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

    return created.isErr ? created : ok(signed.value);
  }

  async refreshTokenPair(refreshToken: string) {
    const session = await this.validSession(refreshToken);

    return session.isErr ? session : this.rotateSession(session.value);
  }

  async revokeSession(refreshToken: string) {
    const session = await this.validSession(refreshToken);

    if (session.isErr) {
      return session;
    }

    return resultFrom(() => this.repository.deleteRefreshSession(session.value.id));
  }

  revokeUserSessions(userId: string) {
    return resultFrom(() => this.repository.deleteUserRefreshSessions(userId));
  }

  private async rotateSession(session: RefreshSession) {
    const user = await resultFrom(() => this.repository.findSessionUser(session.userId));

    if (user.isErr || !user.value) {
      return exception("USER_NOT_FOUND", "사용자를 찾을 수 없습니다.");
    }

    const signed = await this.signTokenPair(user.value, session.id);

    if (signed.isErr) {
      return signed;
    }

    const next = await this.newSession(user.value.id, session.id, signed.value.refreshToken);

    if (next.isErr) {
      return next;
    }

    const rotated = await resultFrom(() => this.repository.rotateRefreshSession(
      session.id,
      session.tokenHash,
      next.value.tokenHash,
      next.value.expiresAt,
    ));

    return rotated.isOk && rotated.value
      ? ok(signed.value)
      : exception("INVALID_REFRESH_TOKEN", "인증 정보가 유효하지 않습니다.");
  }

  private async validSession(refreshToken: string) {
    const verified = await this.refreshTokens.verify(refreshToken);

    if (verified.isErr || !validRefreshPayload(verified.value)) {
      return invalidRefreshToken();
    }

    const found = await resultFrom(() => this.repository.findRefreshSession(verified.value.sessionId));

    if (found.isErr || !found.value || found.value.expiresAt <= new Date()) {
      return invalidRefreshToken();
    }

    const hash = await resultFrom(() => hashToken(refreshToken));

    return hash.isOk && hash.value === found.value.tokenHash
      ? ok(found.value)
      : invalidRefreshToken();
  }

  private async signTokenPair(user: SessionUser, sessionId: string) {
    const payload = tokenPayload(user);
    const accessToken = await this.accessTokens.sign(payload);

    if (accessToken.isErr) {
      return accessToken;
    }

    const refreshToken = await this.refreshTokens.sign({
      ...payload,
      sessionId,
      jti: crypto.randomUUID(),
    });

    return refreshToken.isErr
      ? refreshToken
      : ok({ accessToken: accessToken.value, refreshToken: refreshToken.value });
  }

  private async newSession(userId: string, id: string, refreshToken: string) {
    const hash = await resultFrom(() => hashToken(refreshToken));

    return hash.isErr
      ? hash
      : ok({ id, userId, tokenHash: hash.value, expiresAt: JWTManager.getExpirationTime(refreshToken) });
  }
}

function tokenPayload(user: SessionUser) {
  return { userId: user.id, role: user.role, name: user.name };
}

async function hashToken(token: string) {
  // Refresh JWTs are high-entropy credentials; hash every byte instead of bcrypt's 72-byte prefix.
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));

  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function validRefreshPayload(payload: SessionRefreshPayload) {
  return typeof payload.userId === "string"
    && typeof payload.sessionId === "string"
    && typeof payload.jti === "string";
}

function invalidRefreshToken() {
  return exception("INVALID_REFRESH_TOKEN", "인증 정보가 유효하지 않습니다.");
}

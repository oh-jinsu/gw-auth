import assert from "node:assert/strict";
import test from "node:test";

import bcryptjs from "bcryptjs";
import {
  AuthService,
  CookieManager,
  JWTManager,
  logoutHandler,
  refreshHandler,
} from "../dist/server/index.mjs";

test("uses independent rotating sessions for browser logins", async () => {
  const { service, sessions } = await authService();
  const first = await service.login({ id: "member", password: "secret" });
  const second = await service.login({ id: "member", password: "secret" });

  assert.equal(first.isOk, true);
  assert.equal(second.isOk, true);
  assert.equal(sessions.sessions.size, 2);

  const rotated = await service.refreshTokenPair(first.value.refreshToken);

  assert.equal(rotated.isOk, true);
  assert.equal((await service.refreshTokenPair(first.value.refreshToken)).isErr, true);
  assert.equal((await service.refreshTokenPair(second.value.refreshToken)).isOk, true);
});

test("rotates both browser cookies and revokes the current session", async () => {
  const { service } = await authService();
  const login = await service.login({ id: "member", password: "secret" });
  const request = requestWithRefreshToken(login.value.refreshToken);
  const refreshed = await refreshHandler(request, { authService: service });
  const body = await refreshed.json();

  assert.equal(refreshed.status, 201);
  assert.equal(typeof body.accessToken, "string");
  assert.equal(typeof body.refreshToken, "string");
  assert.equal(refreshed.headers.getSetCookie().length, 2);

  const response = await logoutHandler(
    requestWithRefreshToken(body.refreshToken),
    { authService: service },
  );

  assert.equal(response.status, 204);
  assert.equal((await service.refreshTokenPair(body.refreshToken)).isErr, true);
});

async function authService() {
  const user = { id: crypto.randomUUID(), role: "user", name: "Member" };
  const password = await bcryptjs.hash("secret", 10);
  const sessions = new MemorySessionRepository(user);
  const repository = {
    async findCredentialById(id) {
      return id === "member" ? { id, password, userId: user.id } : undefined;
    },
    async findUserById(id) {
      return id === user.id ? user : undefined;
    },
  };
  const accessTokenManager = new JWTManager({
    secret: "access-secret",
    expiresIn: "30m",
    issuer: "browser",
  });
  const refreshTokenManager = new JWTManager({
    secret: "refresh-secret",
    expiresIn: "30d",
    issuer: "browser",
  });
  const service = new AuthService({
    authRepository: repository,
    sessionRepository: sessions,
    accessTokenManager,
    accessTokenCookieStore: new CookieManager("access"),
    refreshTokenManager,
    refreshTokenCookieStore: new CookieManager("refresh"),
  });

  return { service, sessions };
}

function requestWithRefreshToken(token) {
  return new Request("https://example.com/api/auth/refresh", {
    headers: { cookie: `refresh=${encodeURIComponent(token)}` },
  });
}

class MemorySessionRepository {
  constructor(user) {
    this.user = user;
  }

  sessions = new Map();

  async findSessionUser(userId) {
    return userId === this.user.id ? this.user : undefined;
  }

  async createRefreshSession(session) {
    this.sessions.set(session.id, session);
  }

  async findRefreshSession(sessionId) {
    return this.sessions.get(sessionId);
  }

  async rotateRefreshSession(sessionId, expectedHash, nextHash, expiresAt) {
    const current = this.sessions.get(sessionId);

    if (!current || current.tokenHash !== expectedHash) {
      return false;
    }

    this.sessions.set(sessionId, {
      ...current,
      tokenHash: nextHash,
      expiresAt,
    });

    return true;
  }

  async deleteRefreshSession(sessionId) {
    this.sessions.delete(sessionId);
  }

  async deleteUserRefreshSessions(userId) {
    for (const [id, session] of this.sessions) {
      if (session.userId === userId) {
        this.sessions.delete(id);
      }
    }
  }
}

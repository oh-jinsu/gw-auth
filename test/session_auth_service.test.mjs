import assert from "node:assert/strict";
import test from "node:test";

import {
  JWTManager,
  SessionAuthService,
} from "../dist/server/index.mjs";

test("keeps device sessions independent and rotates refresh tokens", async () => {
  const repository = new MemorySessionRepository();
  const service = sessionService(repository);
  const first = await service.issueTokenPair(repository.user);
  const second = await service.issueTokenPair(repository.user);

  assert.equal(first.isOk, true);
  assert.equal(second.isOk, true);
  assert.equal(repository.sessions.size, 2);

  const rotated = await service.refreshTokenPair(first.value.refreshToken);

  assert.equal(rotated.isOk, true);
  assert.equal((await service.refreshTokenPair(first.value.refreshToken)).isErr, true);
  assert.equal((await service.refreshTokenPair(second.value.refreshToken)).isOk, true);
});

test("revokes only the session represented by a refresh token", async () => {
  const repository = new MemorySessionRepository();
  const service = sessionService(repository);
  const first = await service.issueTokenPair(repository.user);
  const second = await service.issueTokenPair(repository.user);

  await service.revokeSession(first.value.refreshToken);

  assert.equal((await service.refreshTokenPair(first.value.refreshToken)).isErr, true);
  assert.equal((await service.refreshTokenPair(second.value.refreshToken)).isOk, true);
});

test("does not revoke the current session with a previously rotated token", async () => {
  const repository = new MemorySessionRepository();
  const service = sessionService(repository);
  const issued = await service.issueTokenPair(repository.user);
  const rotated = await service.refreshTokenPair(issued.value.refreshToken);

  assert.equal((await service.revokeSession(issued.value.refreshToken)).isErr, true);
  assert.equal((await service.refreshTokenPair(rotated.value.refreshToken)).isOk, true);
});

test("validates the configured token issuer", async () => {
  const repository = new MemorySessionRepository();
  const service = sessionService(repository);
  const foreign = new JWTManager({ secret: "access-secret", expiresIn: "30m", issuer: "foreign" });
  const token = await foreign.sign({ userId: repository.user.id, role: "user", name: "하루" });

  assert.equal(token.isOk, true);
  assert.equal((await service.verifyAccessToken(token.value)).isErr, true);
});

function sessionService(repository) {
  const access = new JWTManager({ secret: "access-secret", expiresIn: "30m", issuer: "oneqaday" });
  const refresh = new JWTManager({ secret: "refresh-secret", expiresIn: "30d", issuer: "oneqaday" });

  return new SessionAuthService(repository, access, refresh);
}

class MemorySessionRepository {
  user = { id: crypto.randomUUID(), role: "user", name: "하루" };
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

    this.sessions.set(sessionId, { ...current, tokenHash: nextHash, expiresAt });

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

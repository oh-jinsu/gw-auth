import assert from "node:assert/strict";
import test from "node:test";

import bcryptjs from "bcryptjs";
import { decodeJwt } from "jose";

import { createAuth } from "../dist/core/index.mjs";

test("keeps sessions independent and revokes a family after replay", async () => {
  const { auth, password, sessions } = await fixture();
  const login = auth.password({ repository: password }).mobile();
  const first = await login.login({ id: "member", password: "secret" });
  const second = await login.login({ id: "member", password: "secret" });
  const mobile = auth.session.mobile();
  const rotated = await mobile.refresh({ refreshToken: first.value.refreshToken });

  assert.equal(sessions.records.size, 2);
  assert.equal(rotated.isOk, true);

  for (const [id, session] of sessions.records) {
    if (session.previousTokenHash) {
      sessions.records.set(id, { ...session, rotatedAt: new Date(Date.now() - 20_000) });
    }
  }

  assert.equal((await mobile.refresh({
    refreshToken: first.value.refreshToken,
  })).error.code, "REFRESH_TOKEN_REUSED");
  assert.equal((await mobile.refresh({ refreshToken: rotated.value.refreshToken })).isErr, true);
  assert.equal((await mobile.refresh({ refreshToken: second.value.refreshToken })).isOk, true);
});

test("returns one persisted refresh token to requests racing within ten seconds", async () => {
  const { auth, password, sessions } = await fixture();
  const login = await auth.password({ repository: password }).mobile().login({
    id: "member",
    password: "secret",
  });
  const mobile = auth.session.mobile();
  const results = await Promise.all(Array.from({ length: 10 }, () => mobile.refresh({
    refreshToken: login.value.refreshToken,
  })));

  assert.equal(results.every(({ isOk }) => isOk), true);
  assert.equal(new Set(results.map(({ value }) => value.refreshToken)).size, 1);
  assert.equal(sessions.records.size, 1);
  assert.equal((await mobile.refresh({ refreshToken: results[0].value.refreshToken })).isOk, true);
});

test("revokes only the session represented by a refresh token", async () => {
  const { auth, password } = await fixture();
  const login = auth.password({ repository: password }).mobile();
  const first = await login.login({ id: "member", password: "secret" });
  const second = await login.login({ id: "member", password: "secret" });
  const session = auth.session.mobile();

  await session.logout({ refreshToken: first.value.refreshToken });

  assert.equal((await session.refresh({ refreshToken: first.value.refreshToken })).isErr, true);
  assert.equal((await session.refresh({ refreshToken: second.value.refreshToken })).isOk, true);
});

test("preserves an active token when logout receives a stale rotated token", async () => {
  const { auth, password } = await fixture();
  const login = await auth.password({ repository: password }).mobile().login({
    id: "member",
    password: "secret",
  });
  const session = auth.session.mobile();
  const rotated = await session.refresh({ refreshToken: login.value.refreshToken });

  assert.equal((await session.logout({ refreshToken: login.value.refreshToken })).isErr, true);
  assert.equal((await session.refresh({ refreshToken: rotated.value.refreshToken })).isOk, true);
});

test("derives issuer and audience from the service name and rejects wrong token purposes", async () => {
  const current = await fixture();
  const foreign = await fixture({ serviceName: "foreign" });
  const foreignLogin = await foreign.auth.password({
    repository: foreign.password,
  }).mobile().login({ id: "member", password: "secret" });
  const currentLogin = await current.auth.password({
    repository: current.password,
  }).mobile().login({ id: "member", password: "secret" });
  const session = current.auth.session.mobile();

  assert.equal((await session.verify({ accessToken: foreignLogin.value.accessToken })).isErr, true);
  assert.equal((await session.verify({ accessToken: currentLogin.value.refreshToken })).isErr, true);
  assert.equal((await session.verify({ accessToken: "malformed" })).isErr, true);
});

test("preserves session repository failures as system errors", async () => {
  const { auth, password, sessions } = await fixture();
  const login = await auth.password({ repository: password }).mobile().login({
    id: "member",
    password: "secret",
  });

  sessions.failFind = true;

  const refreshed = await auth.session.mobile().refresh({
    refreshToken: login.value.refreshToken,
  });

  assert.equal(refreshed.error.code, "AUTH_SYSTEM_FAILURE");
  assert.equal(refreshed.error.message, "인증 처리 중 시스템 오류가 발생했습니다.");
  assert.equal(refreshed.error.cause.operation, "find_refresh_session");
});

test("removes JWT-managed claims supplied by the application", async () => {
  const { auth, password } = await fixture({
    claims: {
      aud: "attacker",
      exp: 1,
      iat: 1,
      iss: "attacker",
      jti: "attacker",
      nbf: Math.floor(Date.now() / 1000) + 3_600,
      role: "user",
      sessionId: "attacker",
      sub: "attacker",
      tokenUse: "refresh",
      userId: "attacker",
    },
  });
  const login = await auth.password({ repository: password }).mobile().login({
    id: "member",
    password: "secret",
  });
  const verified = await auth.session.mobile().verify({
    accessToken: login.value.accessToken,
  });
  const refreshClaims = decodeJwt(login.value.refreshToken);

  assert.equal(login.isOk, true);
  assert.equal(verified.isOk, true);
  assert.equal(login.value.auth.role, "user");
  assert.equal("nbf" in login.value.auth, false);
  assert.equal("role" in refreshClaims, false);
  assert.equal("name" in refreshClaims, false);
  assert.notEqual(login.value.auth.userId, "attacker");
  assert.notEqual(login.value.auth.sessionId, "attacker");
});

test("rejects one secret shared by access and refresh tokens", () => {
  const sharedSecret = "0123456789abcdef0123456789abcdef";

  assert.throws(() => createAuth({
    serviceName: "test-suite",
    sessions: {},
    tokens: {
      access: { secret: sharedSecret, expiresIn: "30m" },
      refresh: { secret: sharedSecret, expiresIn: "30d" },
    },
  }), /different secrets/);
});

/** Creates a public auth facade suitable for session behavior tests. */
async function fixture(overrides = {}) {
  const user = {
    id: crypto.randomUUID(),
    claims: overrides.claims ?? { role: "user", name: "하루" },
  };
  const sessions = new SessionStore(user);
  const password = new PasswordStore(user, await bcryptjs.hash("secret", 4));
  const auth = createAuth({
    serviceName: overrides.serviceName ?? "test-suite",
    sessions,
    tokens: {
      access: tokenOptions("30m"),
      refresh: tokenOptions("30d"),
    },
  });

  return { auth, password, sessions };
}

/** Creates one purpose-independent token configuration for `createAuth`. */
function tokenOptions(expiresIn) {
  return {
    secret: expiresIn === "30m"
      ? "0123456789abcdef0123456789abcdef"
      : "fedcba9876543210fedcba9876543210",
    expiresIn,
  };
}

/** Minimal password repository for issuing test sessions. */
class PasswordStore {
  /** Creates the store around one credential. */
  constructor(user, passwordHash) {
    this.user = user;
    this.passwordHash = passwordHash;
  }

  /** Finds the only configured credential. */
  async findCredentialById(id) {
    return id === "member"
      ? { id, passwordHash: this.passwordHash, userId: this.user.id }
      : undefined;
  }

  /** Creates no accounts in session-only tests. */
  async createPasswordAccount() {
    return { status: "credential_exists" };
  }
}

/** In-memory user and rotating-session store. */
class SessionStore {
  records = new Map();

  failFind = false;

  /** Creates the store around one current user. */
  constructor(user) {
    this.user = user;
  }

  /** Loads the current user claims. */
  async findSessionUser(userId) {
    return userId === this.user.id ? this.user : undefined;
  }

  /** Persists one session. */
  async createRefreshSession(session) {
    this.records.set(session.id, session);
  }

  /** Loads one session or simulates infrastructure failure. */
  async findRefreshSession(id) {
    if (this.failFind) {
      throw new Error("database unavailable");
    }

    return this.records.get(id);
  }

  /** Atomically rotates, accepts immediate overlap, or revokes stale reuse. */
  async rotateRefreshSession(input) {
    const current = this.records.get(input.sessionId);

    if (!current || current.userId !== input.userId || current.expiresAt <= input.now) {
      return { status: "invalid" };
    }

    if (current.tokenHash === input.expectedTokenHash) {
      this.records.set(input.sessionId, {
        id: current.id,
        userId: current.userId,
        previousTokenHash: current.tokenHash,
        rotatedAt: input.now,
        ...input.next,
      });

      return { status: "rotated" };
    }

    if (current.previousTokenHash === input.expectedTokenHash
      && current.rotatedAt >= input.reuseWindowStart) {
      return { status: "concurrent", session: current };
    }

    this.records.delete(input.sessionId);

    return { status: "reused" };
  }

  /** Deletes one session. */
  async deleteRefreshSession(id) {
    this.records.delete(id);
  }

  /** Deletes expired sessions. */
  async deleteExpiredRefreshSessions(before) {
    let deleted = 0;

    for (const [id, session] of this.records) {
      if (session.expiresAt <= before) {
        this.records.delete(id);
        deleted += 1;
      }
    }

    return deleted;
  }
}

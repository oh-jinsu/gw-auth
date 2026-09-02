import assert from "node:assert/strict";
import test from "node:test";

import bcryptjs from "bcryptjs";

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
  assert.equal((await mobile.refresh({
    refreshToken: first.value.refreshToken,
  })).error.code, "REFRESH_TOKEN_REUSED");
  assert.equal((await mobile.refresh({ refreshToken: rotated.value.refreshToken })).isErr, true);
  assert.equal((await mobile.refresh({ refreshToken: second.value.refreshToken })).isOk, true);
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
  assert.match(refreshed.error.message, /find_refresh_session/);
});

/** Creates a public auth facade suitable for session behavior tests. */
async function fixture(overrides = {}) {
  const user = { id: crypto.randomUUID(), claims: { role: "user", name: "하루" } };
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

  /** Rotates one current hash with compare-and-swap. */
  async rotateRefreshSession(id, expected, next, expiresAt) {
    const current = this.records.get(id);

    if (!current || current.tokenHash !== expected) {
      return false;
    }

    this.records.set(id, { ...current, tokenHash: next, expiresAt });

    return true;
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

import assert from "node:assert/strict";
import test from "node:test";

import bcryptjs from "bcryptjs";

import { createAuth } from "../dist/core/index.mjs";

test("keeps independent password login sessions", async () => {
  const { auth, password, sessions } = await testAuth();
  const mobile = auth.password({ repository: password }).mobile();
  const first = await mobile.login({ id: "member", password: "secret" });
  const second = await mobile.login({ id: "member", password: "secret" });

  assert.equal(first.isOk, true);
  assert.equal(second.isOk, true);
  assert.equal(sessions.records.size, 2);
  assert.equal((await auth.session.mobile().refresh({
    refreshToken: first.value.refreshToken,
  })).isOk, true);
});

test("returns browser-safe state and structured HttpOnly cookie effects", async () => {
  const { auth, password } = await testAuth();
  const browser = auth.password({ repository: password }).browser();
  const operation = await browser.login({ id: "member", password: "secret" });

  assert.equal(operation.result.isOk, true);
  assert.equal(operation.result.value.role, "user");
  assert.equal("accessToken" in operation.result.value, false);
  assert.equal("refreshToken" in operation.result.value, false);
  assert.deepEqual(operation.cookies.map(({ name, operation }) => ({ name, operation })), [
    { name: "auth_access", operation: "set" },
    { name: "auth_refresh", operation: "set" },
  ]);
  assert.equal(operation.cookies.every((cookie) => cookie.httpOnly), true);
});

test("returns bearer tokens only from the mobile projection", async () => {
  const { auth, password } = await testAuth();
  const mobile = auth.password({ repository: password }).mobile();
  const result = await mobile.login({ id: "member", password: "secret" });

  assert.equal(result.isOk, true);
  assert.equal(typeof result.value.accessToken, "string");
  assert.equal(typeof result.value.refreshToken, "string");
});

test("revokes a browser session and always returns matching deletion effects", async () => {
  const { auth, password } = await testAuth();
  const mobile = auth.password({ repository: password }).mobile();
  const login = await mobile.login({ id: "member", password: "secret" });
  const logout = await auth.session.browser().logout({
    cookies: { auth_refresh: login.value.refreshToken },
  });

  assert.equal(logout.result.isOk, true);
  assert.deepEqual(logout.cookies.map(({ name, operation, path }) => ({
    name,
    operation,
    path,
  })), [
    { name: "auth_access", operation: "delete", path: "/" },
    { name: "auth_refresh", operation: "delete", path: "/" },
  ]);
  assert.equal((await auth.session.mobile().refresh({
    refreshToken: login.value.refreshToken,
  })).isErr, true);
});

test("clears browser cookies after a terminal refresh failure", async () => {
  const { auth } = await testAuth();
  const refreshed = await auth.session.browser().refresh({
    cookies: { auth_refresh: "invalid-refresh-token" },
  });

  assert.equal(refreshed.result.error.code, "INVALID_REFRESH_TOKEN");
  assert.deepEqual(refreshed.cookies.map(({ name, operation }) => ({ name, operation })), [
    { name: "auth_access", operation: "delete" },
    { name: "auth_refresh", operation: "delete" },
  ]);
});

test("uses one atomic repository operation for password signup", async () => {
  const { auth, password } = await testAuth();
  const result = await auth.password({ repository: password }).mobile().signup({
    id: "new-member",
    password: "new-secret",
    passwordConfirm: "new-secret",
    registration: { displayName: "새 사용자" },
  });

  assert.equal(result.isOk, true);
  assert.equal(password.createdAccounts.length, 1);
  assert.equal(password.createdAccounts[0].credentialId, "new-member");
  assert.equal(password.createdAccounts[0].registration.displayName, "새 사용자");
  assert.equal(await bcryptjs.compare(
    "new-secret",
    password.createdAccounts[0].passwordHash,
  ), true);
});

test("preserves expected and infrastructure failures as AuthError results", async () => {
  const { auth, password } = await testAuth();
  const mobile = auth.password({ repository: password }).mobile();
  const invalid = await mobile.login({ id: "member", password: "wrong" });

  password.failFindCredential = true;

  const unavailable = await mobile.login({ id: "member", password: "secret" });

  assert.equal(invalid.error.code, "INVALID_CREDENTIAL");
  assert.equal(unavailable.error.code, "AUTH_SYSTEM_FAILURE");
});

test("rejects passwords that bcrypt would truncate", async () => {
  const acceptedPrefix = "a".repeat(72);
  const truncatedPassword = `${acceptedPrefix}b`;
  const { auth, password } = await testAuth(acceptedPrefix);
  const mobile = auth.password({ repository: password }).mobile();
  const login = await mobile.login({ id: "member", password: truncatedPassword });
  const signup = await mobile.signup({
    id: "long-password",
    password: "가".repeat(25),
    passwordConfirm: "가".repeat(25),
    registration: { displayName: "Long Password" },
  });

  assert.equal(login.error.code, "INVALID_CREDENTIAL");
  assert.equal(signup.error.code, "INVALID_PASSWORD");
  assert.equal(password.createdAccounts.length, 0);
});

/** Creates the public facade with in-memory password and session repositories. */
async function testAuth(existingPassword = "secret") {
  const user = {
    id: crypto.randomUUID(),
    claims: { role: "user", name: "Member" },
  };
  const passwordHash = await bcryptjs.hash(existingPassword, 4);
  const password = new MemoryPasswordRepository(user, passwordHash);
  const sessions = new MemorySessionRepository(user);
  const auth = createAuth({
    serviceName: "test-suite",
    sessions,
    tokens: tokenOptions(),
    browser: {
      cookies: {
        accessToken: { name: "auth_access" },
        refreshToken: { name: "auth_refresh" },
      },
    },
  });

  return { auth, password, sessions };
}

/** Creates independent access and refresh token policies. */
function tokenOptions() {
  return {
    access: {
      secret: "0123456789abcdef0123456789abcdef",
      expiresIn: "30m",
    },
    refresh: {
      secret: "fedcba9876543210fedcba9876543210",
      expiresIn: "30d",
    },
  };
}

/** In-memory password account repository with an atomic creation spy. */
class MemoryPasswordRepository {
  createdAccounts = [];

  failFindCredential = false;

  /** Creates the repository around one existing password account. */
  constructor(user, passwordHash) {
    this.user = user;
    this.passwordHash = passwordHash;
  }

  /** Finds the existing password credential or simulates storage failure. */
  async findCredentialById(id) {
    if (this.failFindCredential) {
      throw new Error("database unavailable");
    }

    return id === "member"
      ? { id, passwordHash: this.passwordHash, userId: this.user.id }
      : undefined;
  }

  /** Simulates an atomic user and credential transaction. */
  async createPasswordAccount(params) {
    this.createdAccounts.push(params);

    return {
      status: "created",
      user: {
        id: crypto.randomUUID(),
        claims: { role: "user", name: params.registration.displayName },
      },
    };
  }
}

/** In-memory session store implementing user lookup and refresh rotation. */
class MemorySessionRepository {
  records = new Map();

  /** Creates a store around one known user. */
  constructor(user) {
    this.user = user;
  }

  /** Returns current claims for login and refresh. */
  async findSessionUser(userId) {
    return userId === this.user.id ? this.user : undefined;
  }

  /** Persists one refresh session. */
  async createRefreshSession(session) {
    this.records.set(session.id, session);
  }

  /** Finds one refresh session. */
  async findRefreshSession(sessionId) {
    return this.records.get(sessionId);
  }

  /** Rotates a token hash using compare-and-swap semantics. */
  async rotateRefreshSession(sessionId, expectedHash, nextHash, expiresAt) {
    const current = this.records.get(sessionId);

    if (!current || current.tokenHash !== expectedHash) {
      return false;
    }

    this.records.set(sessionId, { ...current, tokenHash: nextHash, expiresAt });

    return true;
  }

  /** Deletes one refresh session. */
  async deleteRefreshSession(sessionId) {
    this.records.delete(sessionId);
  }

  /** Deletes expired sessions and returns the count. */
  async deleteExpiredRefreshSessions(before) {
    let count = 0;

    for (const [id, session] of this.records) {
      if (session.expiresAt <= before) {
        this.records.delete(id);
        count += 1;
      }
    }

    return count;
  }
}

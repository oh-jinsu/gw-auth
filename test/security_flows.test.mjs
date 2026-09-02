import assert from "node:assert/strict";
import test from "node:test";

import { createAuth } from "../dist/core/index.mjs";

test("stages and atomically completes an unknown mobile social identity", async () => {
  const { auth, socialRepository } = fixture();
  const social = auth.social({ repository: socialRepository });
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async () => Response.json({
    id: 12345,
    kakao_account: { profile: { nickname: "Kakao User" } },
  });

  try {
    const login = await social.kakao().mobile().login({ accessToken: "provider-token" });

    assert.equal(login.value.status, "signup_required");
    assert.equal(login.value.signupToken.length, 43);
    assert.notEqual(socialRepository.attempt.tokenHash, login.value.signupToken);

    const completed = await social.signup.mobile().complete({
      signupToken: login.value.signupToken,
      registration: { gender: "female" },
    });
    const replayed = await social.signup.mobile().complete({
      signupToken: login.value.signupToken,
      registration: { gender: "female" },
    });

    assert.equal(completed.isOk, true);
    assert.equal(replayed.error.code, "INVALID_SOCIAL_SIGNUP_TOKEN");
    assert.deepEqual(socialRepository.completedRegistration, { gender: "female" });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("creates hashed OAuth state with PKCE and nonce without Request or Response", async () => {
  const { auth, socialRepository } = fixture();
  const google = auth.social({ repository: socialRepository }).google({
    clientId: "google-client",
    clientSecret: "google-secret",
  }).browser({ redirectUri: "https://example.test/auth/google/callback" });
  const started = await google.start({ redirectPath: "/settings?source=oauth" });

  assert.equal(started.result.isOk, true);

  const authorizationUrl = new URL(started.result.value.authorizationUrl);
  const state = authorizationUrl.searchParams.get("state");

  assert.notEqual(socialRepository.transaction.stateHash, state);
  assert.equal(typeof authorizationUrl.searchParams.get("code_challenge"), "string");
  assert.equal(typeof authorizationUrl.searchParams.get("nonce"), "string");
  assert.deepEqual(started.cookies.map(({ name, operation }) => ({ name, operation })), [
    { name: "security-tests_oauth_state", operation: "set" },
  ]);
});

test("clears browser state after a mismatched OAuth callback without consuming it", async () => {
  const { auth, socialRepository } = fixture();
  const google = auth.social({ repository: socialRepository }).google({
    clientId: "google-client",
    clientSecret: "google-secret",
  }).browser({ redirectUri: "https://example.test/auth/google/callback" });
  const started = await google.start();
  const state = new URL(started.result.value.authorizationUrl).searchParams.get("state");
  const completed = await google.complete({
    code: "provider-code",
    state,
    cookies: {
      "security-tests_oauth_state": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    },
  });

  assert.equal(completed.result.error.code, "INVALID_OAUTH_STATE");
  assert.deepEqual(completed.cookies.map(({ name, operation }) => ({ name, operation })), [
    { name: "security-tests_oauth_state", operation: "delete" },
  ]);
  assert.notEqual(socialRepository.transaction, undefined);
});

test("returns portable signup state and cookie effects from an OAuth callback", async () => {
  const { auth, socialRepository } = fixture();
  const kakao = auth.social({ repository: socialRepository }).kakao({
    clientId: "kakao-client",
    clientSecret: "kakao-secret",
  }).browser({ redirectUri: "https://example.test/auth/kakao/callback" });
  const started = await kakao.start({ redirectPath: "/account" });
  const state = cookieValue(started.cookies, "security-tests_oauth_state");
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (input) => String(input).includes("/oauth/token")
    ? Response.json({ access_token: "kakao-access" })
    : Response.json({ id: "provider-user", kakao_account: {} });

  try {
    const completed = await kakao.complete({
      code: "provider-code",
      state,
      cookies: { "security-tests_oauth_state": state },
    });

    assert.equal(completed.result.value.status, "signup_required");
    assert.equal(completed.result.value.redirectPath, "/account");
    assert.deepEqual(completed.cookies.map(({ name, operation }) => ({ name, operation })), [
      { name: "security-tests_oauth_state", operation: "delete" },
      { name: "security-tests_social_signup", operation: "set" },
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects cross-origin OAuth redirects before storing a transaction", async () => {
  const { auth, socialRepository } = fixture();
  const google = auth.social({ repository: socialRepository }).google({
    clientId: "google-client",
    clientSecret: "google-secret",
  }).browser({ redirectUri: "https://example.test/auth/google/callback" });
  const result = await google.start({ redirectPath: "https://attacker.example" });

  assert.equal(result.result.error.code, "INVALID_REDIRECT_PATH");
  assert.equal(socialRepository.transaction, undefined);
});

test("uses rotating server-issued credentials for browser guests", async () => {
  const { auth } = fixture();
  const repository = new MemoryGuestRepository();
  const guest = auth.guest({ repository }).browser();
  const created = await guest.authenticate({ cookies: {} });
  const credential = cookieValue(created.cookies, "security-tests_guest_credential");
  const rotated = await guest.authenticate({
    cookies: { "security-tests_guest_credential": credential },
  });
  const replayed = await guest.authenticate({
    cookies: { "security-tests_guest_credential": credential },
  });

  assert.equal(created.result.isOk, true);
  assert.deepEqual(created.cookies.map(({ name, operation }) => ({ name, operation })), [
    { name: "security-tests_access_token", operation: "set" },
    { name: "security-tests_refresh_token", operation: "set" },
    { name: "security-tests_guest_credential", operation: "set" },
  ]);
  assert.notEqual(repository.currentHash, credential);
  assert.equal(rotated.result.isOk, true);
  assert.equal(replayed.result.error.code, "INVALID_GUEST_CREDENTIAL");
});

test("keeps password-reset discovery uniform and consumes attempts once", async () => {
  const { auth } = fixture();
  const repository = new MemoryPasswordResetRepository();
  const mailer = new MemoryPasswordResetMailer();
  const recovery = auth.passwordRecovery({
    siteOrigin: "https://example.test",
    repository,
    mailer,
  });

  assert.equal((await recovery.request({ credentialId: "unknown" })).isOk, true);
  assert.equal((await recovery.request({ credentialId: "member" })).isOk, true);
  assert.equal(mailer.messages.length, 1);

  const token = new URL(mailer.messages[0].resetUrl).searchParams.get("token");
  const completed = await recovery.reset({
    token,
    password: "new-secret",
    passwordConfirm: "new-secret",
  });
  const replayed = await recovery.reset({
    token,
    password: "new-secret",
    passwordConfirm: "new-secret",
  });

  assert.equal(completed.isOk, true);
  assert.equal(replayed.error.code, "INVALID_PASSWORD_RESET_TOKEN");
});

/** Creates the common facade and combined in-memory social repository. */
function fixture() {
  const sessions = new MemorySessionRepository();

  return {
    auth: createAuth({ serviceName: "security-tests", sessions, tokens: tokenOptions() }),
    socialRepository: new MemorySocialRepository(),
  };
}

/** Creates token policy used by non-password security workflows. */
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

/** Reads the value of one cookie-set instruction. */
function cookieValue(cookies, name) {
  const mutation = cookies.find((cookie) => {
    return cookie.operation === "set" && cookie.name === name;
  });

  assert.notEqual(mutation, undefined);

  return mutation.value;
}

/** Combined social identity, signup-attempt, and OAuth transaction store. */
class MemorySocialRepository {
  attempt = undefined;

  transaction = undefined;

  completedRegistration = undefined;

  /** Reports no existing linked user. */
  async findUserBySocialIdentity() {
    return undefined;
  }

  /** Stores one social signup attempt. */
  async createSocialSignupAttempt(attempt) {
    this.attempt = attempt;
  }

  /** Returns public profile hints for a current attempt. */
  async findSocialSignupProfile(tokenHash, now) {
    if (!this.validAttempt(tokenHash, now)) {
      return undefined;
    }

    const { provider, email, name, picture } = this.attempt.identity;

    return { provider, email, name, picture };
  }

  /** Atomically consumes an attempt and creates its linked user. */
  async completeSocialSignup({ tokenHash, registration, now }) {
    if (!this.validAttempt(tokenHash, now)) {
      return { status: "invalid_attempt" };
    }

    this.completedRegistration = registration;
    this.attempt = undefined;

    return {
      status: "created",
      user: { id: crypto.randomUUID(), claims: { role: "user", name: "Social User" } },
    };
  }

  /** Deletes expired signup attempts. */
  async deleteExpiredSocialSignupAttempts() {
    return 0;
  }

  /** Stores one hashed OAuth transaction. */
  async createOAuthTransaction(transaction) {
    this.transaction = transaction;
  }

  /** Atomically consumes a current OAuth transaction. */
  async consumeOAuthTransaction(stateHash, now) {
    if (this.transaction?.stateHash !== stateHash || this.transaction.expiresAt <= now) {
      return undefined;
    }

    const transaction = this.transaction;

    this.transaction = undefined;

    return transaction;
  }

  /** Deletes expired OAuth transactions. */
  async deleteExpiredOAuthTransactions() {
    return 0;
  }

  /** Reports whether a signup-attempt hash is current. */
  validAttempt(tokenHash, now) {
    return this.attempt?.tokenHash === tokenHash && this.attempt.expiresAt > now;
  }
}

/** Minimal shared session and user store. */
class MemorySessionRepository {
  records = new Map();

  users = new Map();

  /** Finds current user claims for refresh. */
  async findSessionUser(userId) {
    return this.users.get(userId);
  }

  /** Stores one refresh session. */
  async createRefreshSession(session) {
    this.records.set(session.id, session);
  }

  /** Finds one refresh session. */
  async findRefreshSession(id) {
    return this.records.get(id);
  }

  /** Rotates one matching refresh hash. */
  async rotateRefreshSession(id, expected, next, expiresAt) {
    const current = this.records.get(id);

    if (!current || current.tokenHash !== expected) {
      return false;
    }

    this.records.set(id, { ...current, tokenHash: next, expiresAt });

    return true;
  }

  /** Deletes one refresh session. */
  async deleteRefreshSession(id) {
    this.records.delete(id);
  }

  /** Deletes expired refresh sessions. */
  async deleteExpiredRefreshSessions() {
    return 0;
  }
}

/** Stores one rotating guest hash and its random user. */
class MemoryGuestRepository {
  currentHash = undefined;

  user = { id: crypto.randomUUID(), claims: { role: "guest", name: "Guest" } };

  /** Creates a guest and credential atomically. */
  async createGuestAccount({ tokenHash }) {
    this.currentHash = tokenHash;

    return this.user;
  }

  /** Finds a guest by current credential hash. */
  async findGuestByCredential(tokenHash) {
    return this.currentHash === tokenHash ? this.user : undefined;
  }

  /** Rotates only a matching current credential. */
  async rotateGuestCredential({ expectedTokenHash, nextTokenHash }) {
    if (!this.currentHash || this.currentHash !== expectedTokenHash) {
      return false;
    }

    this.currentHash = nextTokenHash;

    return true;
  }

  /** Deletes expired guest credentials. */
  async deleteExpiredGuestCredentials() {
    return 0;
  }
}

/** Stores and atomically consumes one password-reset attempt. */
class MemoryPasswordResetRepository {
  attempt = undefined;

  /** Finds the only recoverable account. */
  async findPasswordResetAccount(credentialId) {
    return credentialId === "member"
      ? { credentialId, userId: "user-id", email: "member@example.test" }
      : undefined;
  }

  /** Stores one reset attempt. */
  async createPasswordResetAttempt(attempt) {
    this.attempt = attempt;
  }

  /** Deletes a failed-delivery attempt. */
  async deletePasswordResetAttempt(tokenHash) {
    if (this.attempt?.tokenHash === tokenHash) {
      this.attempt = undefined;
    }
  }

  /** Atomically consumes one current reset attempt. */
  async completePasswordReset({ tokenHash, now }) {
    if (this.attempt?.tokenHash !== tokenHash || this.attempt.expiresAt <= now) {
      return { status: "invalid_attempt" };
    }

    const userId = this.attempt.userId;

    this.attempt = undefined;

    return { status: "completed", userId };
  }

  /** Deletes expired reset attempts. */
  async deleteExpiredPasswordResetAttempts() {
    return 0;
  }
}

/** Captures password-reset notifications. */
class MemoryPasswordResetMailer {
  messages = [];

  /** Queues one reset message in memory. */
  async sendPasswordReset(message) {
    this.messages.push(message);
  }
}

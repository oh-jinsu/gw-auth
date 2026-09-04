import test from "node:test";

import {
  assertOAuthTransactionRepositoryConformance,
  assertPasswordResetRepositoryConformance,
  assertSessionRepositoryConformance,
  assertSocialRepositoryConformance,
} from "../dist/testing/index.mjs";

test("validates SessionRepository security invariants", async () => {
  await assertSessionRepositoryConformance(() => ({
    repository: new MemorySessionRepository(),
  }));
});

test("validates OAuthTransactionRepository security invariants", async () => {
  await assertOAuthTransactionRepositoryConformance(() => ({
    repository: new MemoryOAuthTransactionRepository(),
  }));
});

test("validates SocialRepository security invariants", async () => {
  await assertSocialRepositoryConformance(() => ({
    repository: new MemorySocialRepository(),
    registration: { displayName: "Member" },
  }));
});

test("validates PasswordResetRepository security invariants", async () => {
  const repository = new MemoryPasswordResetRepository();

  await assertPasswordResetRepositoryConformance(() => ({
    repository,
    account: repository.account,
    nextPasswordHash: "next-password-hash",
    readPasswordHash: async () => repository.passwordHash,
    countActiveRefreshSessions: async () => repository.sessionCount,
    countOtherActiveRefreshSessions: async () => repository.otherSessionCount,
  }));
});

/** In-memory session repository implementing the atomic rotation contract. */
class MemorySessionRepository {
  records = new Map();

  /** Persists one refresh session. */
  async createRefreshSession(session) {
    this.records.set(session.id, session);
  }

  /** Reads one refresh session. */
  async findRefreshSession(id) {
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

  /** Deletes one refresh session. */
  async deleteRefreshSession(id) {
    this.records.delete(id);
  }

  /** Deletes refresh sessions older than the boundary. */
  async deleteExpiredRefreshSessions(before) {
    return deleteExpired(this.records, before);
  }
}

/** In-memory OAuth transaction repository with single-consumer behavior. */
class MemoryOAuthTransactionRepository {
  records = new Map();

  /** Persists one OAuth transaction. */
  async createOAuthTransaction(transaction) {
    this.records.set(transaction.stateHash, transaction);
  }

  /** Atomically consumes one matching unexpired transaction. */
  async consumeOAuthTransaction(stateHash, now) {
    const current = this.records.get(stateHash);

    if (!current || current.expiresAt <= now) {
      return undefined;
    }

    this.records.delete(stateHash);

    return current;
  }

  /** Deletes expired OAuth transactions. */
  async deleteExpiredOAuthTransactions(before) {
    return deleteExpired(this.records, before);
  }
}

/** In-memory social repository with an atomically consumed signup attempt. */
class MemorySocialRepository {
  attempts = new Map();

  identities = new Set();

  /** Returns no linked identity in this focused fixture. */
  async findUserBySocialIdentity() {
    return undefined;
  }

  /** Persists one social signup attempt. */
  async createSocialSignupAttempt(attempt) {
    this.attempts.set(attempt.tokenHash, attempt);
  }

  /** Reads safe profile hints from one active attempt. */
  async findSocialSignupProfile(tokenHash, now) {
    const attempt = this.validAttempt(tokenHash, now);

    return attempt
      ? socialProfile(attempt.identity)
      : undefined;
  }

  /** Atomically consumes an attempt and creates its identity once. */
  async completeSocialSignup({ tokenHash, now }) {
    const attempt = this.validAttempt(tokenHash, now);

    if (!attempt) {
      return { status: "invalid_attempt" };
    }

    this.attempts.delete(tokenHash);

    const identityKey = `${attempt.identity.provider}:${attempt.identity.id}`;

    if (this.identities.has(identityKey)) {
      return { status: "identity_exists" };
    }

    this.identities.add(identityKey);

    return { status: "created", user: { id: crypto.randomUUID(), claims: {} } };
  }

  /** Deletes the expired attempt if present. */
  async deleteExpiredSocialSignupAttempts(before) {
    let deleted = 0;

    for (const [tokenHash, attempt] of this.attempts) {
      if (attempt.expiresAt < before) {
        this.attempts.delete(tokenHash);
        deleted += 1;
      }
    }

    return deleted;
  }

  /** Reports whether the current attempt matches and remains active. */
  validAttempt(tokenHash, now) {
    const attempt = this.attempts.get(tokenHash);

    return attempt?.expiresAt > now ? attempt : undefined;
  }
}

/** In-memory password-reset repository with session-family revocation. */
class MemoryPasswordResetRepository {
  account = { credentialId: "member", userId: "user", email: "member@example.test" };

  attempt = undefined;

  passwordHash = "old-password-hash";

  sessionCount = 2;

  otherSessionCount = 1;

  /** Finds the single resettable account. */
  async findPasswordResetAccount(credentialId) {
    return credentialId === this.account.credentialId ? this.account : undefined;
  }

  /** Persists one password-reset attempt. */
  async createPasswordResetAttempt(attempt) {
    this.attempt = attempt;
  }

  /** Deletes one matching password-reset attempt. */
  async deletePasswordResetAttempt(tokenHash) {
    if (this.attempt?.tokenHash === tokenHash) {
      this.attempt = undefined;
    }
  }

  /** Atomically consumes an attempt, replaces the password, and revokes sessions. */
  async completePasswordReset({ tokenHash, passwordHash, now }) {
    if (this.attempt?.tokenHash !== tokenHash || this.attempt.expiresAt <= now) {
      return { status: "invalid_attempt" };
    }

    this.attempt = undefined;
    this.passwordHash = passwordHash;
    this.sessionCount = 0;

    return { status: "completed", userId: this.account.userId };
  }

  /** Deletes the expired reset attempt if present. */
  async deleteExpiredPasswordResetAttempts(before) {
    if (!this.attempt || this.attempt.expiresAt >= before) {
      return 0;
    }

    this.attempt = undefined;

    return 1;
  }
}

/** Deletes expired map values and returns the number removed. */
function deleteExpired(records, before) {
  let deleted = 0;

  for (const [key, value] of records) {
    if (value.expiresAt < before) {
      records.delete(key);
      deleted += 1;
    }
  }

  return deleted;
}

/** Selects only social profile hints safe for a signup screen. */
function socialProfile(identity) {
  const { provider, email, name, picture } = identity;

  return { provider, email, name, picture };
}

import assert from "node:assert/strict";
import test from "node:test";

import { err, ok } from "gw-result";
import { SignJWT } from "jose";

import {
  AuthError,
  authErrorCategory,
  createAuth,
} from "../dist/core/index.mjs";

const accessSecret = "account-access-secret-with-32-bytes-minimum";
const refreshSecret = "account-refresh-secret-with-32-bytes-minimum";
const serviceName = "account-tests";

test("revokes Apple before completing mobile account deletion", async () => {
  const captured = [];
  const { account, repository, userId } = accountFixture(async (input) => {
    captured.push(input);

    return ok();
  });
  const result = await account.mobile().delete({ accessToken: await accessToken(userId) });

  assert.equal(result.isOk, true);
  assert.deepEqual(captured, [{
    providerClientId: "com.example.app",
    providerRefreshToken: "apple-refresh-token",
  }]);
  assert.equal(repository.accountExists, false);
  assert.equal(repository.completedRevocations.has("apple-revocation"), true);
});

test("keeps failed provider revocation pending and resumes it server-side", async () => {
  let providerAvailable = false;
  const { account, repository, userId } = accountFixture(async () => {
    return providerAvailable
      ? ok()
      : err(new AuthError("APPLE_REVOKE_FAILED", "Apple unavailable"));
  });
  const failed = await account.mobile().delete({ accessToken: await accessToken(userId) });

  assert.equal(failed.error.code, "ACCOUNT_PROVIDER_REVOCATION_FAILED");
  assert.equal(authErrorCategory(failed.error), "upstream");
  assert.equal(repository.deletionPending, true);
  assert.equal(repository.activeSessionCount, 0);
  assert.equal(repository.accountExists, true);

  providerAvailable = true;

  const retried = await account.retryPending(userId);

  assert.equal(retried.isOk, true);
  assert.equal(repository.accountExists, false);
});

test("clears browser session cookies only after account deletion completes", async () => {
  const { account, repository, userId } = accountFixture(async () => ok());
  const operation = await account.browser().delete({
    cookies: { [`${serviceName}_access_token`]: await accessToken(userId) },
  });

  assert.equal(operation.result.isOk, true);
  assert.deepEqual(operation.cookies.map(({ name, operation: mutation }) => ({
    name,
    operation: mutation,
  })), [
    { name: `${serviceName}_access_token`, operation: "delete" },
    { name: `${serviceName}_refresh_token`, operation: "delete" },
  ]);
  assert.equal(repository.accountExists, false);
});

test("does not begin deletion for an invalid access token", async () => {
  const { account, repository } = accountFixture(async () => ok());
  const result = await account.mobile().delete({ accessToken: "invalid" });

  assert.equal(result.error.code, "INVALID_ACCESS_TOKEN");
  assert.equal(repository.beginCalls, 0);
  assert.equal(repository.accountExists, true);
});

test("keeps an Apple deletion pending when its revoker is not configured", async () => {
  const { account, repository, userId } = accountFixture();
  const result = await account.mobile().delete({ accessToken: await accessToken(userId) });

  assert.equal(result.error.code, "AUTH_SYSTEM_FAILURE");
  assert.equal(repository.deletionPending, true);
  assert.equal(repository.accountExists, true);
});

/** Creates the public facade with a resumable in-memory account repository. */
function accountFixture(revoke) {
  const repository = new MemoryAccountDeletionRepository();
  const auth = createAuth({
    serviceName,
    sessions: sessionRepository(),
    tokens: {
      access: { secret: accessSecret, expiresIn: "15m" },
      refresh: { secret: refreshSecret, expiresIn: "30d" },
    },
  });
  const account = auth.account({
    repository,
    ...(revoke ? { providers: { apple: { revoke } } } : {}),
  });

  return { account, repository, userId: repository.userId };
}

/** Signs one access token matching the public facade's managed claims. */
function accessToken(userId) {
  return new SignJWT({ tokenUse: "access", userId, sessionId: "session" })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt()
    .setIssuer(serviceName)
    .setAudience(serviceName)
    .setExpirationTime("15m")
    .sign(new TextEncoder().encode(accessSecret));
}

/** Supplies the session ports required at the common composition root. */
function sessionRepository() {
  return {
    findSessionUser: async () => undefined,
    createRefreshSession: async () => {},
    findRefreshSession: async () => undefined,
    rotateRefreshSession: async () => ({ status: "invalid" }),
    deleteRefreshSession: async () => {},
    deleteExpiredRefreshSessions: async () => 0,
  };
}

/** Stores one account, two sessions, and one encrypted-at-rest Apple token. */
class MemoryAccountDeletionRepository {
  userId = "account-user";

  accountExists = true;

  deletionPending = false;

  activeSessionCount = 2;

  beginCalls = 0;

  completedRevocations = new Set();

  /** Atomically marks deletion pending and revokes all sessions. */
  async beginAccountDeletion(userId) {
    this.beginCalls += 1;

    if (!this.accountExists || userId !== this.userId) {
      return undefined;
    }

    this.deletionPending = true;
    this.activeSessionCount = 0;

    return {
      revocations: this.completedRevocations.has("apple-revocation")
        ? []
        : [appleRevocation()],
    };
  }

  /** Records a successfully revoked Apple credential. */
  async completeAccountProviderRevocation(revocationId) {
    this.completedRevocations.add(revocationId);
  }

  /** Completes deletion only when no provider work remains. */
  async completeAccountDeletion(userId) {
    if (userId !== this.userId || !this.accountExists) {
      return;
    }

    if (!this.completedRevocations.has("apple-revocation")) {
      throw new Error("provider revocation remains pending");
    }

    this.accountExists = false;
    this.deletionPending = false;
  }
}

/** Returns the decrypted Apple credential only to the deletion service. */
function appleRevocation() {
  return {
    id: "apple-revocation",
    provider: "apple",
    providerClientId: "com.example.app",
    providerRefreshToken: "apple-refresh-token",
  };
}

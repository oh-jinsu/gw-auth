import test from "node:test";

import {
  assertAccountDeletionRepositoryConformance,
} from "../dist/testing/index.mjs";

test("validates AccountDeletionRepository security invariants", async () => {
  const repository = new MemoryAccountDeletionRepository();

  await assertAccountDeletionRepositoryConformance(() => ({
    repository,
    userId: repository.userId,
    inspect: () => repository.inspect(),
  }));
});

/** In-memory account deletion repository with one pending Apple revocation. */
class MemoryAccountDeletionRepository {
  userId = "account-user";

  accountExists = true;

  deletionPending = false;

  activeSessionCount = 2;

  revocations = new Map([["apple-revocation", appleRevocation()]]);

  /** Atomically enters deletion-pending state and revokes every local session. */
  async beginAccountDeletion(userId) {
    if (!this.accountExists || userId !== this.userId) {
      return undefined;
    }

    this.deletionPending = true;
    this.activeSessionCount = 0;

    return { revocations: [...this.revocations.values()] };
  }

  /** Idempotently records one completed provider revocation. */
  async completeAccountProviderRevocation(revocationId) {
    this.revocations.delete(revocationId);
  }

  /** Completes deletion only after all provider revocations are recorded. */
  async completeAccountDeletion(userId) {
    if (userId !== this.userId || !this.accountExists) {
      return;
    }

    if (this.revocations.size) {
      throw new Error("provider revocation remains pending");
    }

    this.accountExists = false;
    this.deletionPending = false;
  }

  /** Returns state observed by the reusable conformance assertion. */
  async inspect() {
    return {
      accountExists: this.accountExists,
      deletionPending: this.deletionPending,
      activeSessionCount: this.activeSessionCount,
      pendingRevocationIds: [...this.revocations.keys()],
    };
  }
}

/** Creates one decrypted Apple credential returned only during deletion. */
function appleRevocation() {
  return {
    id: "apple-revocation",
    provider: "apple",
    providerClientId: "com.example.app",
    providerRefreshToken: "provider-refresh-token",
  };
}

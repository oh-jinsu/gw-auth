import assert from "node:assert/strict";

import type { AccountDeletionRepository } from "gw-auth/core";
import {
  withRepositoryFixture,
  type RepositoryConformanceFactory,
  type RepositoryConformanceFixture,
} from "./fixture";

/** Observable state supplied by an account-deletion repository fixture. */
export type AccountDeletionRepositoryState = {
  accountExists: boolean;
  deletionPending: boolean;
  activeSessionCount: number;
  pendingRevocationIds: readonly string[];
};

/** Fixture containing one active account, sessions, and an Apple revocation. */
export type AccountDeletionRepositoryConformanceFixture =
  RepositoryConformanceFixture<AccountDeletionRepository> & {
    /** User identifier for the fixture's initially active account. */
    userId: string;

    /** Reads account, session, and pending-revocation state without mutating it. */
    inspect(): Promise<AccountDeletionRepositoryState>;
  };

/** Verifies atomic preparation, resumability, provider completion, and final deletion. */
export function assertAccountDeletionRepositoryConformance(
  factory: RepositoryConformanceFactory<AccountDeletionRepositoryConformanceFixture>,
) {
  return withRepositoryFixture(factory, async (fixture) => {
    const pending = await assertAtomicPreparation(fixture);

    await assertPendingCannotComplete(fixture);
    await assertRevocationCompletion(fixture, pending.revocations.map(({ id }) => id));
    await assertFinalDeletion(fixture);
  });
}

/** Ensures concurrent preparation is idempotent and revokes every local session. */
async function assertAtomicPreparation(fixture: AccountDeletionRepositoryConformanceFixture) {
  const pending = await Promise.all([
    fixture.repository.beginAccountDeletion(fixture.userId),
    fixture.repository.beginAccountDeletion(fixture.userId),
  ]);

  assert.ok(pending[0]);
  assert.deepEqual(pending[1], pending[0]);

  const state = await fixture.inspect();

  assert.equal(state.accountExists, true);
  assert.equal(state.deletionPending, true);
  assert.equal(state.activeSessionCount, 0);
  assert.deepEqual(state.pendingRevocationIds, pending[0].revocations.map(({ id }) => id));

  return pending[0];
}

/** Ensures local deletion cannot race ahead of required provider revocation. */
async function assertPendingCannotComplete(
  fixture: AccountDeletionRepositoryConformanceFixture,
) {
  await assert.rejects(() => fixture.repository.completeAccountDeletion(fixture.userId));
}

/** Ensures successful provider work is durable and omitted from resumed preparation. */
async function assertRevocationCompletion(
  fixture: AccountDeletionRepositoryConformanceFixture,
  revocationIds: readonly string[],
) {
  for (const id of revocationIds) {
    await fixture.repository.completeAccountProviderRevocation(id);
    await fixture.repository.completeAccountProviderRevocation(id);
  }

  const resumed = await fixture.repository.beginAccountDeletion(fixture.userId);

  assert.deepEqual(resumed?.revocations, []);
  assert.deepEqual((await fixture.inspect()).pendingRevocationIds, []);
}

/** Ensures final deletion is idempotent and cannot be prepared again. */
async function assertFinalDeletion(fixture: AccountDeletionRepositoryConformanceFixture) {
  await fixture.repository.completeAccountDeletion(fixture.userId);
  await fixture.repository.completeAccountDeletion(fixture.userId);

  const state = await fixture.inspect();

  assert.equal(state.accountExists, false);
  assert.equal(state.deletionPending, false);
  assert.equal(state.activeSessionCount, 0);
  assert.equal(await fixture.repository.beginAccountDeletion(fixture.userId), undefined);
}

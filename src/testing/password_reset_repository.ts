import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import type {
  PasswordResetAccount,
  PasswordResetRepository,
} from "gw-auth/core";
import {
  withRepositoryFixture,
  type RepositoryConformanceFactory,
  type RepositoryConformanceFixture,
} from "./fixture";

/** Password-reset fixture with one account and at least one active refresh session. */
export type PasswordResetRepositoryConformanceFixture =
  RepositoryConformanceFixture<PasswordResetRepository> & {
    /** Existing account targeted by the seeded recovery flow. */
    account: PasswordResetAccount;

    /** Distinct password hash written only by a successful completion. */
    nextPasswordHash: string;

    /** Reads the account's current persisted password hash. */
    readPasswordHash(): Promise<string>;

    /** Counts every active refresh session belonging to the fixture account. */
    countActiveRefreshSessions(): Promise<number>;

    /** Counts seeded active refresh sessions belonging to other users. */
    countOtherActiveRefreshSessions(): Promise<number>;
  };

/** Verifies expiration, single completion, password replacement, and session revocation. */
export function assertPasswordResetRepositoryConformance(
  factory: RepositoryConformanceFactory<PasswordResetRepositoryConformanceFixture>,
) {
  return withRepositoryFixture(factory, async (fixture) => {
    await assertExpiredAttempt(fixture);
    await assertAtomicCompletion(fixture);
  });
}

/** Verifies that an expired attempt changes neither password nor active sessions. */
async function assertExpiredAttempt(fixture: PasswordResetRepositoryConformanceFixture) {
  const tokenHash = randomBytes(32).toString("hex");
  const previousHash = await fixture.readPasswordHash();
  const previousSessions = await fixture.countActiveRefreshSessions();
  const previousOtherSessions = await fixture.countOtherActiveRefreshSessions();

  assert.ok(previousSessions > 0, "fixture must seed at least one active refresh session");

  await fixture.repository.createPasswordResetAttempt({
    tokenHash,
    credentialId: fixture.account.credentialId,
    userId: fixture.account.userId,
    expiresAt: new Date(Date.now() - 60_000),
  });

  const completed = await fixture.repository.completePasswordReset({
    tokenHash,
    passwordHash: fixture.nextPasswordHash,
    now: new Date(),
  });

  assert.equal(completed.status, "invalid_attempt");
  assert.equal(await fixture.readPasswordHash(), previousHash);
  assert.equal(await fixture.countActiveRefreshSessions(), previousSessions);
  assert.equal(await fixture.countOtherActiveRefreshSessions(), previousOtherSessions);

  await createExpiredAttempt(fixture);

  assert.ok(await fixture.repository.deleteExpiredPasswordResetAttempts(new Date()) >= 1);
}

/** Persists a separate expired attempt so cleanup is observable after completion checks. */
async function createExpiredAttempt(fixture: PasswordResetRepositoryConformanceFixture) {
  await fixture.repository.createPasswordResetAttempt({
    tokenHash: randomBytes(32).toString("hex"),
    credentialId: fixture.account.credentialId,
    userId: fixture.account.userId,
    expiresAt: new Date(Date.now() - 60_000),
  });
}

/** Verifies that one contender replaces the password and revokes every session. */
async function assertAtomicCompletion(fixture: PasswordResetRepositoryConformanceFixture) {
  const tokenHash = randomBytes(32).toString("hex");
  const previousOtherSessions = await fixture.countOtherActiveRefreshSessions();

  await fixture.repository.createPasswordResetAttempt({
    tokenHash,
    credentialId: fixture.account.credentialId,
    userId: fixture.account.userId,
    expiresAt: new Date(Date.now() + 60_000),
  });

  const completed = await Promise.all([
    complete(fixture, tokenHash),
    complete(fixture, tokenHash),
  ]);

  const winners = completed.filter(({ status }) => status === "completed");
  const winner = completed.find(({ status }) => status === "completed");

  assert.equal(
    winners.length,
    1,
    "exactly one password-reset completion must succeed",
  );
  assert.equal(winner?.status, "completed");

  if (winner?.status === "completed") {
    assert.equal(winner.userId, fixture.account.userId);
  }
  assert.equal(await fixture.readPasswordHash(), fixture.nextPasswordHash);
  assert.equal(await fixture.countActiveRefreshSessions(), 0);
  assert.equal(await fixture.countOtherActiveRefreshSessions(), previousOtherSessions);

  assert.equal((await complete(fixture, tokenHash)).status, "invalid_attempt");
}

/** Completes one password reset with the fixture's replacement hash. */
function complete(
  fixture: PasswordResetRepositoryConformanceFixture,
  tokenHash: string,
) {
  return fixture.repository.completePasswordReset({
    tokenHash,
    passwordHash: fixture.nextPasswordHash,
    now: new Date(),
  });
}

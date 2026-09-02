import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import type {
  OAuthTransaction,
  OAuthTransactionRepository,
} from "gw-auth/core";
import {
  withRepositoryFixture,
  type RepositoryConformanceFactory,
  type RepositoryConformanceFixture,
} from "./fixture";

/** Isolated OAuthTransactionRepository fixture consumed by its assertion. */
export type OAuthTransactionRepositoryConformanceFixture =
  RepositoryConformanceFixture<OAuthTransactionRepository>;

/** Verifies atomic single consumption, replay rejection, and expiration cleanup. */
export function assertOAuthTransactionRepositoryConformance(
  factory: RepositoryConformanceFactory<OAuthTransactionRepositoryConformanceFixture>,
) {
  return withRepositoryFixture(factory, async ({ repository }) => {
    await assertSingleConsumption(repository);
    await assertExpirationCleanup(repository);
  });
}

/** Verifies that concurrent consumers can obtain a transaction only once. */
async function assertSingleConsumption(repository: OAuthTransactionRepository) {
  const transaction = newTransaction();

  await repository.createOAuthTransaction(transaction);

  const consumed = await Promise.all([
    repository.consumeOAuthTransaction(transaction.stateHash, new Date()),
    repository.consumeOAuthTransaction(transaction.stateHash, new Date()),
  ]);
  const winners = consumed.filter((value) => value !== undefined);

  assert.equal(winners.length, 1, "exactly one OAuth transaction consumer must win");
  assert.equal(winners[0]?.stateHash, transaction.stateHash);
  assert.equal(winners[0]?.provider, transaction.provider);
  assert.equal(winners[0]?.nonce, transaction.nonce);
  assert.equal(
    await repository.consumeOAuthTransaction(transaction.stateHash, new Date()),
    undefined,
  );
}

/** Verifies that expiration cleanup preserves active transactions. */
async function assertExpirationCleanup(repository: OAuthTransactionRepository) {
  const active = newTransaction();
  const expired = newTransaction(new Date(Date.now() - 60_000));

  await repository.createOAuthTransaction(active);
  await repository.createOAuthTransaction(expired);

  const deleted = await repository.deleteExpiredOAuthTransactions(new Date());

  assert.equal(deleted, 1);
  assert.equal(
    await repository.consumeOAuthTransaction(expired.stateHash, new Date()),
    undefined,
  );
  assert.notEqual(
    await repository.consumeOAuthTransaction(active.stateHash, new Date()),
    undefined,
  );
}

/** Creates one provider transaction with realistic persisted values. */
function newTransaction(
  expiresAt = new Date(Math.ceil(Date.now() / 1000) * 1000 + 60_000),
): OAuthTransaction {
  return {
    stateHash: randomBytes(32).toString("hex"),
    provider: "google",
    redirectPath: "/settings",
    codeVerifier: randomBytes(32).toString("base64url"),
    nonce: randomBytes(32).toString("base64url"),
    expiresAt,
  };
}

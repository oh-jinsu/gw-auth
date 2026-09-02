import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";

import type { RefreshSession, SessionRepository } from "gw-auth/core";
import {
  withRepositoryFixture,
  type RepositoryConformanceFactory,
  type RepositoryConformanceFixture,
} from "./fixture";

/** Isolated SessionRepository fixture consumed by its conformance assertion. */
export type SessionRepositoryConformanceFixture =
  RepositoryConformanceFixture<SessionRepository>;

/** Verifies persistence, deletion, CAS rotation, races, and expiration cleanup. */
export function assertSessionRepositoryConformance(
  factory: RepositoryConformanceFactory<SessionRepositoryConformanceFixture>,
) {
  return withRepositoryFixture(factory, async ({ repository }) => {
    await assertPersistence(repository);
    await assertCompareAndSwap(repository);
    await assertExpirationCleanup(repository);
  });
}

/** Verifies that a session can be read and deleted by its exact identifier. */
async function assertPersistence(repository: SessionRepository) {
  const session = newSession();

  await repository.createRefreshSession(session);

  assertSession(await repository.findRefreshSession(session.id), session);

  await repository.deleteRefreshSession(session.id);

  assert.equal(await repository.findRefreshSession(session.id), undefined);
}

/** Verifies that exactly one concurrent hash replacement wins. */
async function assertCompareAndSwap(repository: SessionRepository) {
  const session = newSession();
  const firstHash = tokenHash();
  const secondHash = tokenHash();

  await repository.createRefreshSession(session);

  const results = await Promise.all([
    repository.rotateRefreshSession(session.id, session.tokenHash, firstHash, futureDate()),
    repository.rotateRefreshSession(session.id, session.tokenHash, secondHash, futureDate()),
  ]);

  assert.equal(results.filter(Boolean).length, 1, "exactly one refresh CAS must succeed");

  const stored = await repository.findRefreshSession(session.id);
  const winningHash = results[0] ? firstHash : secondHash;

  assert.equal(stored?.tokenHash, winningHash);

  await repository.deleteRefreshSession(session.id);
}

/** Verifies that cleanup removes expired sessions without deleting active ones. */
async function assertExpirationCleanup(repository: SessionRepository) {
  const active = newSession();
  const expired = newSession(pastDate());

  await repository.createRefreshSession(active);
  await repository.createRefreshSession(expired);

  const deleted = await repository.deleteExpiredRefreshSessions(new Date());

  assert.equal(deleted, 1);
  assert.equal(await repository.findRefreshSession(expired.id), undefined);
  assert.notEqual(await repository.findRefreshSession(active.id), undefined);

  await repository.deleteRefreshSession(active.id);
}

/** Creates one valid refresh-session fixture. */
function newSession(expiresAt = futureDate()): RefreshSession {
  return {
    id: randomUUID(),
    userId: randomUUID(),
    tokenHash: tokenHash(),
    expiresAt,
  };
}

/** Creates one random SHA-256-shaped token hash. */
function tokenHash() {
  return randomBytes(32).toString("hex");
}

/** Creates a stable future timestamp without subsecond database precision. */
function futureDate() {
  return new Date(Math.ceil(Date.now() / 1000) * 1000 + 60_000);
}

/** Creates a stable expired timestamp. */
function pastDate() {
  return new Date(Date.now() - 60_000);
}

/** Compares the persistence fields required by the SessionRepository contract. */
function assertSession(actual: RefreshSession | undefined, expected: RefreshSession) {
  assert.equal(actual?.id, expected.id);
  assert.equal(actual?.userId, expected.userId);
  assert.equal(actual?.tokenHash, expected.tokenHash);
}

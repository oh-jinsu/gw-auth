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

/** Verifies persistence, atomic rotation, overlap handling, replay, and cleanup. */
export function assertSessionRepositoryConformance(
  factory: RepositoryConformanceFactory<SessionRepositoryConformanceFixture>,
) {
  return withRepositoryFixture(factory, async ({ repository }) => {
    await assertPersistence(repository);
    await assertConcurrentRotation(repository);
    await assertReplayRevocation(repository);
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

/** Verifies that a rotation loser receives the exact persisted winner. */
async function assertConcurrentRotation(repository: SessionRepository) {
  const session = newSession();
  const first = newTokenState();
  const second = newTokenState();
  const now = new Date();

  await repository.createRefreshSession(session);

  const results = await Promise.all([
    repository.rotateRefreshSession(rotationInput(session, first, now)),
    repository.rotateRefreshSession(rotationInput(session, second, now)),
  ]);

  assert.deepEqual(
    results.map(({ status }) => status).sort(),
    ["concurrent", "rotated"],
    "one request must rotate and one must receive the persisted winner",
  );

  const stored = await repository.findRefreshSession(session.id);
  const winning = results[0].status === "rotated" ? first : second;
  const concurrent = results.find(({ status }) => status === "concurrent");
  const expected = {
    id: session.id,
    userId: session.userId,
    previousTokenHash: session.tokenHash,
    rotatedAt: now,
    ...winning,
  };

  assertSession(stored, expected);
  assert.equal(concurrent?.status, "concurrent");

  if (concurrent?.status === "concurrent") {
    assertSession(concurrent.session, expected);
  }

  await repository.deleteRefreshSession(session.id);
}

/** Verifies that prior-token reuse outside the overlap window revokes the family. */
async function assertReplayRevocation(repository: SessionRepository) {
  const session = newSession();
  const next = newTokenState();
  const rotationTime = new Date();

  await repository.createRefreshSession(session);

  assert.equal(
    (await repository.rotateRefreshSession(rotationInput(session, next, rotationTime))).status,
    "rotated",
  );

  const overlapTime = new Date(rotationTime.getTime() + 10_000);
  const overlap = await repository.rotateRefreshSession(rotationInput(
    session,
    newTokenState(),
    overlapTime,
  ));

  assert.equal(overlap.status, "concurrent");

  const replayTime = new Date(rotationTime.getTime() + 10_001);
  const replay = await repository.rotateRefreshSession(rotationInput(
    session,
    newTokenState(),
    replayTime,
  ));

  assert.equal(replay.status, "reused");
  assert.equal(await repository.findRefreshSession(session.id), undefined);
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
    previousTokenHash: null,
    rotatedAt: new Date(),
    ...newTokenState(expiresAt),
  };
}

/** Creates persisted metadata for one non-secret refresh-token representation. */
function newTokenState(expiresAt = futureDate()) {
  return {
    tokenHash: tokenHash(),
    tokenId: randomUUID(),
    issuedAt: new Date(Math.floor(Date.now() / 1000) * 1000),
    expiresAt,
  };
}

/** Creates one atomic rotation request around a presented session token. */
function rotationInput(
  session: RefreshSession,
  next: ReturnType<typeof newTokenState>,
  now: Date,
) {
  return {
    sessionId: session.id,
    userId: session.userId,
    expectedTokenHash: session.tokenHash,
    next,
    now,
    reuseWindowStart: new Date(now.getTime() - 10_000),
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
  assert.equal(actual?.tokenId, expected.tokenId);
  assert.equal(actual?.issuedAt.getTime(), expected.issuedAt.getTime());
  assert.equal(actual?.expiresAt.getTime(), expected.expiresAt.getTime());
  assert.equal(actual?.previousTokenHash, expected.previousTokenHash);
  assert.equal(actual?.rotatedAt.getTime(), expected.rotatedAt.getTime());
}

import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";

import type { SocialRepository } from "gw-auth/core";
import {
  withRepositoryFixture,
  type RepositoryConformanceFactory,
  type RepositoryConformanceFixture,
} from "./fixture";

/** Isolated SocialRepository fixture with valid application registration data. */
export type SocialRepositoryConformanceFixture<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
> = RepositoryConformanceFixture<SocialRepository<TRegistrationInput, TClaims>> & {
  /** Application-valid registration data used to complete staged signup. */
  registration: TRegistrationInput;
};

/** Verifies public profile secrecy, atomic completion, replay, and expiration. */
export function assertSocialRepositoryConformance<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  factory: RepositoryConformanceFactory<
    SocialRepositoryConformanceFixture<TRegistrationInput, TClaims>
  >,
) {
  return withRepositoryFixture(factory, async ({ repository, registration }) => {
    await assertSingleCompletion(repository, registration);
    await assertIdentityUniqueness(repository, registration);
    await assertExpiredAttempt(repository, registration);
  });
}

/** Verifies profile filtering and exactly one account creation under contention. */
async function assertSingleCompletion<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  repository: SocialRepository<TRegistrationInput, TClaims>,
  registration: TRegistrationInput,
) {
  const attempt = newAttempt();

  await repository.createSocialSignupAttempt(attempt);

  const profile = await repository.findSocialSignupProfile(attempt.tokenHash, new Date());

  assert.equal(profile?.provider, "apple");
  assert.equal(profile && "id" in profile, false);
  assert.equal(profile && "providerClientId" in profile, false);
  assert.equal(profile && "providerRefreshToken" in profile, false);

  const completed = await Promise.all([
    repository.completeSocialSignup({ tokenHash: attempt.tokenHash, registration, now: new Date() }),
    repository.completeSocialSignup({ tokenHash: attempt.tokenHash, registration, now: new Date() }),
  ]);

  assert.equal(
    completed.filter(({ status }) => status === "created").length,
    1,
    "exactly one social signup completion must create an account",
  );

  const replay = await repository.completeSocialSignup({
    tokenHash: attempt.tokenHash,
    registration,
    now: new Date(),
  });

  assert.notEqual(replay.status, "created");
}

/** Verifies that distinct attempts for one provider identity cannot create two users. */
async function assertIdentityUniqueness<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  repository: SocialRepository<TRegistrationInput, TClaims>,
  registration: TRegistrationInput,
) {
  const identity = newIdentity();
  const first = newAttempt(undefined, identity);
  const second = newAttempt(undefined, identity);

  await repository.createSocialSignupAttempt(first);
  await repository.createSocialSignupAttempt(second);

  const completed = await Promise.all([
    complete(repository, first.tokenHash, registration),
    complete(repository, second.tokenHash, registration),
  ]);

  assert.equal(completed.filter(({ status }) => status === "created").length, 1);
  assert.equal(completed.filter(({ status }) => status === "identity_exists").length, 1);
}

/** Completes one social signup attempt at the current time. */
function complete<TRegistrationInput, TClaims extends Record<string, unknown>>(
  repository: SocialRepository<TRegistrationInput, TClaims>,
  tokenHash: string,
  registration: TRegistrationInput,
) {
  return repository.completeSocialSignup({ tokenHash, registration, now: new Date() });
}

/** Verifies that expired attempts cannot create an account and cleanup removes them. */
async function assertExpiredAttempt<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  repository: SocialRepository<TRegistrationInput, TClaims>,
  registration: TRegistrationInput,
) {
  const attempt = newAttempt(new Date(Date.now() - 60_000));

  await repository.createSocialSignupAttempt(attempt);

  const completed = await repository.completeSocialSignup({
    tokenHash: attempt.tokenHash,
    registration,
    now: new Date(),
  });

  assert.equal(completed.status, "invalid_attempt");

  await repository.createSocialSignupAttempt(newAttempt(new Date(Date.now() - 60_000)));

  assert.ok(await repository.deleteExpiredSocialSignupAttempts(new Date()) >= 1);
}

/** Creates one server-verified social signup attempt. */
function newAttempt(
  expiresAt = new Date(Date.now() + 60_000),
  identity = newIdentity(),
) {
  return {
    tokenHash: randomBytes(32).toString("hex"),
    identity,
    expiresAt,
  };
}

/** Creates one provider identity with private revocation metadata. */
function newIdentity() {
  const providerUserId = randomUUID();

  return {
    provider: "apple" as const,
    id: providerUserId,
    email: `${providerUserId}@example.test`,
    name: "Conformance User",
    providerClientId: "provider-client-id",
    providerRefreshToken: "provider-refresh-token",
  };
}

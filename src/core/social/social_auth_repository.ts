import type { SessionUser } from "../session/session_repository";
import type { SocialIdentity } from "./social_identity";

/**
 * Persisted one-time social signup attempt containing server-verified identity.
 * Encrypt `identity.providerRefreshToken` at rest when a provider supplies it.
 */
export type NewSocialSignupAttempt = {
  tokenHash: string;
  identity: SocialIdentity;
  expiresAt: Date;
};

/** Provider profile hints safe to display while collecting application fields. */
export type SocialSignupProfile = Pick<
  SocialIdentity,
  "email" | "name" | "picture" | "provider"
>;

/** Parameters consumed by the repository's atomic social-account transaction. */
export type CompleteSocialSignupParams<TRegistrationInput> = {
  tokenHash: string;
  registration: TRegistrationInput;
  now: Date;
};

/** Expected outcomes from a one-time social signup transaction. */
export type CompleteSocialSignupResult<TClaims extends Record<string, unknown>> =
  | { status: "created"; user: SessionUser<TClaims> }
  | { status: "identity_exists" }
  | { status: "invalid_attempt" };

/** Persists provider identities and one-time staged signup attempts. */
export interface SocialAuthRepository<
  TRegistrationInput = unknown,
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> {
  /** Finds a local user only by the provider and provider-scoped identifier. */
  findUserBySocialIdentity(
    provider: SocialIdentity["provider"],
    providerUserId: string,
  ): Promise<SessionUser<TClaims> | undefined>;

  /** Persists a new hashed, expiring, single-use social signup attempt. */
  createSocialSignupAttempt(attempt: NewSocialSignupAttempt): Promise<void>;

  /** Finds public profile hints for a matching unexpired, unconsumed attempt. */
  findSocialSignupProfile(
    tokenHash: string,
    now: Date,
  ): Promise<SocialSignupProfile | undefined>;

  /**
   * Atomically consumes the attempt, creates a random user, and links the identity.
   * Implementations must enforce uniqueness on `(provider, providerUserId)` and
   * encrypt a provider refresh token before linking it to the account.
   */
  completeSocialSignup(
    params: CompleteSocialSignupParams<TRegistrationInput>,
  ): Promise<CompleteSocialSignupResult<TClaims>>;

  /** Deletes expired or consumed social signup attempts and returns the number removed. */
  deleteExpiredSocialSignupAttempts(before: Date): Promise<number>;
}

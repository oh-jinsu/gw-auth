import { ok, resultFrom } from "gw-result";

import { authError, authSystemError } from "../auth_error";
import { hashCredential, isCredential, randomCredential } from "../credential";
import type { SessionAuthService } from "../session/session_auth_service";
import type { SocialAuthRepository } from "./social_auth_repository";
import type { SocialIdentity } from "./social_identity";

const defaultSignupAttemptLifetimeMs = 15 * 60 * 1000;

/** Coordinates staged signup, account lookup, and sessions for verified identities. */
export class SocialAuthService<
  TRegistrationInput = unknown,
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> {
  /** Creates the social flow with a short-lived signup-attempt policy. */
  constructor(
    private readonly repository: SocialAuthRepository<TRegistrationInput, TClaims>,
    private readonly sessions: SessionAuthService<TClaims>,
    private readonly signupAttemptLifetimeMs = defaultSignupAttemptLifetimeMs,
  ) {}

  /** Continues a verified browser or mobile identity into login or staged signup. */
  async continueWithIdentity(identity: SocialIdentity) {
    const normalized = normalizeIdentity(identity);
    const found = await resultFrom(() => this.repository.findUserBySocialIdentity(
      normalized.provider,
      normalized.id,
    ));

    if (found.isErr) {
      return authSystemError("find_social_identity", found.error);
    }

    if (found.value) {
      const tokens = await this.sessions.issueTokenPair(found.value);

      return tokens.isErr
        ? tokens
        : ok({ status: "authenticated", tokens: tokens.value } as const);
    }

    return this.createSignupAttempt(normalized);
  }

  /** Atomically completes staged signup with application-validated registration data. */
  async completeSignup(signupToken: string, registration: TRegistrationInput) {
    if (!isCredential(signupToken)) {
      return invalidSignupToken();
    }

    const hash = await hashCredential(signupToken);

    if (hash.isErr) {
      return hash;
    }

    const completed = await resultFrom(() => this.repository.completeSocialSignup({
      tokenHash: hash.value,
      registration,
      now: new Date(),
    }));

    if (completed.isErr) {
      return authSystemError("complete_social_signup", completed.error);
    }

    if (completed.value.status === "invalid_attempt") {
      return invalidSignupToken();
    }

    if (completed.value.status === "identity_exists") {
      return authError("IDENTITY_ALREADY_EXISTS", "이미 가입된 간편 로그인 계정입니다.");
    }

    return this.sessions.issueTokenPair(completed.value.user);
  }

  /** Reads provider profile hints without exposing the one-time token or provider ID. */
  async signupProfile(signupToken: string) {
    if (!isCredential(signupToken)) {
      return invalidSignupToken();
    }

    const hash = await hashCredential(signupToken);

    if (hash.isErr) {
      return hash;
    }

    const profile = await resultFrom(() =>
      this.repository.findSocialSignupProfile(hash.value, new Date()),
    );

    if (profile.isErr) {
      return authSystemError("find_social_signup_profile", profile.error);
    }

    return profile.value ? ok(profile.value) : invalidSignupToken();
  }

  /** Removes expired or consumed social signup attempts. */
  async deleteExpiredSignupAttempts(before = new Date()) {
    const deleted = await resultFrom(() =>
      this.repository.deleteExpiredSocialSignupAttempts(before),
    );

    return deleted.isErr
      ? authSystemError("delete_expired_social_signup_attempts", deleted.error)
      : deleted;
  }

  /** Creates and persists a hashed one-time signup credential. */
  private async createSignupAttempt(identity: SocialIdentity) {
    const signupToken = randomCredential();
    const hash = await hashCredential(signupToken);

    if (hash.isErr) {
      return hash;
    }

    const signupExpiresAt = new Date(Date.now() + this.signupAttemptLifetimeMs);
    const created = await resultFrom(() => this.repository.createSocialSignupAttempt({
      tokenHash: hash.value,
      identity,
      expiresAt: signupExpiresAt,
    }));

    if (created.isErr) {
      return authSystemError("create_social_signup_attempt", created.error);
    }

    return ok({
      status: "signup_required",
      signupToken,
      signupExpiresAt,
      profile: publicProfile(identity),
    } as const);
  }
}

/** Normalizes provider identifiers once at the trusted verifier boundary. */
function normalizeIdentity(identity: SocialIdentity): SocialIdentity {
  return { ...identity, id: String(identity.id) };
}

/** Selects provider profile hints that are safe to show on a signup screen. */
function publicProfile(identity: SocialIdentity) {
  const { email, name, picture, provider } = identity;

  return { email, name, picture, provider };
}

/** Returns one response for malformed, expired, consumed, or unknown signup credentials. */
function invalidSignupToken() {
  return authError(
    "INVALID_SOCIAL_SIGNUP_TOKEN",
    "간편 로그인 회원가입 정보가 유효하지 않습니다.",
  );
}

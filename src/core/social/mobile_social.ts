import { resultFrom } from "gw-result";

import { authError, authSystemError } from "../auth_error";
import type { SocialAuthService } from "./social_auth_service";
import type { SocialSignupProfile } from "./social_auth_repository";
import type { SocialIdentityVerifier } from "./social_identity";
import type { AuthResult, MobileSession } from "../api/auth_result";

/** Explicit-token result returned by a mobile provider login. */
export type MobileSocialLoginResult<
  TClaims extends Record<string, unknown>,
> =
  | { status: "authenticated"; tokens: MobileSession<TClaims> }
  | {
      status: "signup_required";
      signupToken: string;
      signupExpiresAt: Date;
      profile: SocialSignupProfile;
    };

/** Framework-neutral mobile social login operation. */
export type MobileSocialAuth<TClaims extends Record<string, unknown>, TInput> = {
  /** Verifies one provider credential and continues local social authentication. */
  login(input: TInput): Promise<AuthResult<MobileSocialLoginResult<TClaims>>>;
};

/** Maps one provider-specific input into the canonical social credential flow. */
export function createMobileSocialAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
  TInput,
>(
  service: SocialAuthService<TRegistrationInput, TClaims>,
  verifier: SocialIdentityVerifier,
  credential: (input: TInput) => string,
): MobileSocialAuth<TClaims, TInput> {
  return {
    login: (input) => login(service, verifier, credential(input)),
  };
}

/** Verifies one provider credential before continuing local social authentication. */
async function login<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  service: SocialAuthService<TRegistrationInput, TClaims>,
  verifier: SocialIdentityVerifier,
  credential: string,
) {
  if (!credential) {
    return authError("INVALID_PROVIDER_CREDENTIAL", "간편 로그인 인증 정보가 필요합니다.");
  }

  const verified = await resultFrom(() => verifier.verify(credential));

  if (verified.isErr) {
    return authSystemError("verify_social_credential", verified.error);
  }

  return verified.value.isErr
    ? verified.value
    : service.continueWithIdentity(verified.value.value);
}

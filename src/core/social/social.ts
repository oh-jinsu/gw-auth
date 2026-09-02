import type { SocialRepository } from "./social_repository";
import type { OAuthTransactionRepository } from "./oauth/oauth_transaction_repository";
import type { AuthContext } from "../api/context";
import {
  createAppleSocialAuth,
  type AppleOptions,
  type AppleSocialAuth,
} from "./apple/apple";
import {
  createGoogleSocialAuth,
  type GoogleOptions,
  type GoogleSocialAuth,
} from "./google/google";
import {
  createKakaoSocialAuth,
  type KakaoOptions,
  type KakaoSocialAuth,
} from "./kakao/kakao";
import {
  createNaverSocialAuth,
  type NaverOptions,
  type NaverSocialAuth,
} from "./naver/naver";
import type { AuthResult } from "../api/auth_result";
import { createSocialService, type SocialContext } from "./social_context";
import { createSocialSignupAuth, type SocialSignupAuth } from "./social_signup";

/** Options shared by every provider configured under one social feature. */
export type SocialOptions<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
> = {
  repository: SocialRepository<TRegistrationInput, TClaims>;
  /** Required for browser OAuth unless `repository` implements this port too. */
  transactions?: OAuthTransactionRepository;
};

/** Social feature with shared persistence and provider-specific factories. */
export type SocialAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
> = {
  /** Configures Google credentials before selecting browser or mobile delivery. */
  google(options: GoogleOptions): GoogleSocialAuth<TClaims>;

  /** Configures Kakao credentials before selecting browser or mobile delivery. */
  kakao(options?: KakaoOptions): KakaoSocialAuth<TClaims>;

  /** Configures Naver credentials before selecting browser or mobile delivery. */
  naver(options?: NaverOptions): NaverSocialAuth<TClaims>;

  /** Configures Apple credentials before selecting browser or mobile delivery. */
  apple(options: AppleOptions): AppleSocialAuth<TClaims>;

  /** Provides provider-independent staged social-signup operations. */
  signup: SocialSignupAuth<TRegistrationInput, TClaims>;

  /** Deletes expired staged social-signup attempts. */
  deleteExpiredSignupAttempts(before?: Date): Promise<AuthResult<number>>;
};

/** Creates one shared social feature before selecting providers and environments. */
export function createSocialAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: AuthContext<TClaims>,
  options: SocialOptions<TRegistrationInput, TClaims>,
): SocialAuth<TRegistrationInput, TClaims> {
  const socialContext: SocialContext<TRegistrationInput, TClaims> = {
    ...context,
    repository: options.repository,
    transactions: options.transactions ?? transactionRepository(options.repository),
  };
  const service = createSocialService(socialContext);

  return {
    google: (provider) => createGoogleSocialAuth(socialContext, provider),
    kakao: (provider) => createKakaoSocialAuth(socialContext, provider),
    naver: (provider) => createNaverSocialAuth(socialContext, provider),
    apple: (provider) => createAppleSocialAuth(socialContext, provider),
    signup: createSocialSignupAuth(socialContext, service),
    deleteExpiredSignupAttempts: (before) => service.deleteExpiredSignupAttempts(before),
  };
}

/** Reuses a combined adapter when it also implements OAuth transaction storage. */
function transactionRepository(value: object): OAuthTransactionRepository | undefined {
  const candidate = value as Partial<OAuthTransactionRepository>;
  const valid = typeof candidate.createOAuthTransaction === "function"
    && typeof candidate.consumeOAuthTransaction === "function"
    && typeof candidate.deleteExpiredOAuthTransactions === "function";

  return valid ? candidate as OAuthTransactionRepository : undefined;
}

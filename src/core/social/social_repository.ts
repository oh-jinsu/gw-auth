import type { SocialAuthRepository } from "./social_auth_repository";

/** Storage shared by every configured social provider and delivery environment. */
export interface SocialRepository<
  TRegistrationInput = unknown,
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> extends SocialAuthRepository<TRegistrationInput, TClaims> {}

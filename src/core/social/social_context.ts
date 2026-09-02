import type { OAuthProvider } from "./oauth/oauth_provider";
import { OAuthService } from "./oauth/oauth_service";
import type { OAuthTransactionRepository } from "./oauth/oauth_transaction_repository";
import { SocialAuthService } from "./social_auth_service";
import type { SocialRepository } from "./social_repository";
import type { AuthContext } from "../api/context";
import { createBrowserOAuth } from "./browser_oauth";

/** Dependencies shared by every provider under one configured social feature. */
export type SocialContext<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
> = AuthContext<TClaims> & {
  repository: SocialRepository<TRegistrationInput, TClaims>;
  transactions?: OAuthTransactionRepository;
};

/** Creates a browser OAuth facade with one provider-specific adapter. */
export function browserSocialAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  provider: OAuthProvider,
) {
  if (!context.transactions) {
    throw new TypeError("Browser social authentication requires OAuth transaction storage.");
  }

  const social = createSocialService(context);
  const oauth = new OAuthService(
    context.transactions,
    provider,
    social,
  );

  return createBrowserOAuth(context, oauth);
}

/** Creates provider-independent social account and staged-signup operations. */
export function createSocialService<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(context: SocialContext<TRegistrationInput, TClaims>) {
  return new SocialAuthService(context.repository, context.sessions);
}

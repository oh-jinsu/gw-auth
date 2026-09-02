import { AppleAuth } from "./apple_auth";
import { AppleAuthorizationCodeVerifier } from "./apple_authorization_code_verifier";
import type { AuthResult } from "../../api/auth_result";
import type { BrowserOAuth } from "../browser_oauth";
import { createMobileSocialAuth, type MobileSocialAuth } from "../mobile_social";
import type { SocialContext } from "../social_context";
import { browserSocialAuth, createSocialService } from "../social_context";

/** Apple credentials shared before choosing a delivery environment. */
export type AppleOptions = {
  authKey: string;
  clientId: string;
  teamId: string;
  keyId: string;
};

/** Apple browser OAuth configuration. */
export type AppleBrowserOptions = {
  redirectUri: string;
};

/** Apple social feature projected into browser or mobile operations. */
export type AppleSocialAuth<TClaims extends Record<string, unknown>> = {
  /** Configures Apple's browser authorization-code flow. */
  browser(options: AppleBrowserOptions): BrowserOAuth<TClaims>;

  /** Configures Apple authorization-code verification for mobile clients. */
  mobile(): MobileSocialAuth<TClaims, { authorizationCode: string }>;

  /** Revokes a provider refresh token retained for account deletion. */
  revoke(input: { providerRefreshToken: string }): Promise<AuthResult>;
};

/** Creates the Apple feature after its shared social repository is configured. */
export function createAppleSocialAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  options: AppleOptions,
): AppleSocialAuth<TClaims> {
  const verifier = new AppleAuthorizationCodeVerifier(options);

  return {
    browser: (browser) => browserSocialAuth(context, new AppleAuth({
      ...options,
      redirectUri: browser.redirectUri,
    })),
    mobile: () => createAppleMobile(context, verifier),
    revoke: ({ providerRefreshToken }) => verifier.revoke(providerRefreshToken),
  };
}

/** Creates Apple's authorization-code verification flow for mobile clients. */
function createAppleMobile<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  verifier: AppleAuthorizationCodeVerifier,
) {
  const service = createSocialService(context);

  return createMobileSocialAuth<
    TRegistrationInput,
    TClaims,
    { authorizationCode: string }
  >(
    service,
    verifier,
    ({ authorizationCode }) => authorizationCode,
  );
}

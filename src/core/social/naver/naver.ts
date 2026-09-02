import { NaverAuth } from "./naver_auth";
import { NaverAccessTokenVerifier } from "./naver_access_token_verifier";
import type { BrowserOAuth } from "../browser_oauth";
import { createMobileSocialAuth, type MobileSocialAuth } from "../mobile_social";
import type { SocialContext } from "../social_context";
import { browserSocialAuth, createSocialService } from "../social_context";

/** Naver credentials shared before choosing a delivery environment. */
export type NaverOptions = {
  clientId?: string;
  clientSecret?: string;
};

/** Naver browser OAuth configuration. */
export type NaverBrowserOptions = {
  redirectUri: string;
};

/** Naver social feature projected into browser or mobile operations. */
export type NaverSocialAuth<TClaims extends Record<string, unknown>> = {
  /** Configures Naver's server-side authorization-code flow. */
  browser(options: NaverBrowserOptions): BrowserOAuth<TClaims>;

  /** Configures Naver access-token verification for mobile SDK credentials. */
  mobile(): MobileSocialAuth<TClaims, { accessToken: string }>;
};

/** Creates the Naver feature after its shared social repository is configured. */
export function createNaverSocialAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  options: NaverOptions = {},
): NaverSocialAuth<TClaims> {
  return {
    browser: (browser) => createNaverBrowser(context, options, browser),
    mobile: () => createNaverMobile(context),
  };
}

/** Creates Naver's browser authorization-code flow. */
function createNaverBrowser<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  options: NaverOptions,
  browser: NaverBrowserOptions,
) {
  if (!options.clientId || !options.clientSecret) {
    throw new TypeError("Naver browser authentication requires clientId and clientSecret.");
  }

  return browserSocialAuth(context, new NaverAuth({
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: browser.redirectUri,
  }));
}

/** Creates Naver's access-token verification flow for mobile clients. */
function createNaverMobile<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(context: SocialContext<TRegistrationInput, TClaims>) {
  const verifier = new NaverAccessTokenVerifier();
  const service = createSocialService(context);

  return createMobileSocialAuth<
    TRegistrationInput,
    TClaims,
    { accessToken: string }
  >(service, verifier, ({ accessToken }) => accessToken);
}

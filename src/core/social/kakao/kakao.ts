import { KakaoAuth } from "./kakao_auth";
import { KakaoAccessTokenVerifier } from "./kakao_access_token_verifier";
import type { BrowserOAuth } from "../browser_oauth";
import { createMobileSocialAuth, type MobileSocialAuth } from "../mobile_social";
import type { SocialContext } from "../social_context";
import { browserSocialAuth, createSocialService } from "../social_context";

/** Kakao credentials shared before choosing a delivery environment. */
export type KakaoOptions = {
  clientId?: string;
  clientSecret?: string;
};

/** Kakao browser OAuth configuration. */
export type KakaoBrowserOptions = {
  redirectUri: string;
};

/** Kakao social feature projected into browser or mobile operations. */
export type KakaoSocialAuth<TClaims extends Record<string, unknown>> = {
  /** Configures Kakao's server-side authorization-code flow. */
  browser(options: KakaoBrowserOptions): BrowserOAuth<TClaims>;

  /** Configures Kakao access-token verification for mobile SDK credentials. */
  mobile(): MobileSocialAuth<TClaims, { accessToken: string }>;
};

/** Creates the Kakao feature after its shared social repository is configured. */
export function createKakaoSocialAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  options: KakaoOptions = {},
): KakaoSocialAuth<TClaims> {
  return {
    browser: (browser) => createKakaoBrowser(context, options, browser),
    mobile: () => createKakaoMobile(context),
  };
}

/** Creates Kakao's browser authorization-code flow. */
function createKakaoBrowser<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  options: KakaoOptions,
  browser: KakaoBrowserOptions,
) {
  if (!options.clientId) {
    throw new TypeError("Kakao browser authentication requires clientId.");
  }

  return browserSocialAuth(context, new KakaoAuth({
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: browser.redirectUri,
  }));
}

/** Creates Kakao's access-token verification flow for mobile clients. */
function createKakaoMobile<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(context: SocialContext<TRegistrationInput, TClaims>) {
  const verifier = new KakaoAccessTokenVerifier();
  const service = createSocialService(context);

  return createMobileSocialAuth<
    TRegistrationInput,
    TClaims,
    { accessToken: string }
  >(service, verifier, ({ accessToken }) => accessToken);
}

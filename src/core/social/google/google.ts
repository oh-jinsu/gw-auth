import { GoogleAuth } from "./google_auth";
import { GoogleIdTokenVerifier } from "./google_id_token_verifier";
import type { SocialContext } from "../social_context";
import { browserSocialAuth, createSocialService } from "../social_context";
import { createMobileSocialAuth, type MobileSocialAuth } from "../mobile_social";
import type { BrowserOAuth } from "../browser_oauth";

/** Google credentials shared before choosing a delivery environment. */
export type GoogleOptions = {
  clientId: string;
  clientSecret?: string;
};

/** Google browser OAuth configuration. */
export type GoogleBrowserOptions = {
  redirectUri: string;
};

/** Optional additional Google audiences accepted from mobile SDKs. */
export type GoogleMobileOptions = {
  clientIds?: string[];
};

/** Google social feature projected into browser or mobile operations. */
export type GoogleSocialAuth<TClaims extends Record<string, unknown>> = {
  /** Configures Google's server-side authorization-code flow. */
  browser(options: GoogleBrowserOptions): BrowserOAuth<TClaims>;

  /** Configures Google ID-token verification for mobile SDK credentials. */
  mobile(options?: GoogleMobileOptions): MobileSocialAuth<TClaims, { idToken: string }>;
};

/** Creates the Google feature after its shared social repository is configured. */
export function createGoogleSocialAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  options: GoogleOptions,
): GoogleSocialAuth<TClaims> {
  return {
    browser: (browser) => createGoogleBrowser(context, options, browser),
    mobile: (mobile = {}) => createGoogleMobile(context, options, mobile),
  };
}

/** Creates Google's confidential browser authorization-code flow. */
function createGoogleBrowser<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  options: GoogleOptions,
  browser: GoogleBrowserOptions,
) {
  if (!options.clientSecret) {
    throw new TypeError("Google browser authentication requires clientSecret.");
  }

  return browserSocialAuth(context, new GoogleAuth({
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: browser.redirectUri,
  }));
}

/** Creates Google's signed ID-token flow for mobile clients. */
function createGoogleMobile<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  options: GoogleOptions,
  mobile: GoogleMobileOptions,
) {
  const verifier = new GoogleIdTokenVerifier(mobile.clientIds ?? [options.clientId]);
  const service = createSocialService(context);

  return createMobileSocialAuth<
    TRegistrationInput,
    TClaims,
    { idToken: string }
  >(service, verifier, ({ idToken }) => idToken);
}

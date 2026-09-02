import { createAppleAndroidAuth, type AppleAndroidAuth } from "./apple_android";
import { AppleAuth } from "./apple_auth";
import { AppleAuthorizationCodeVerifier } from "./apple_authorization_code_verifier";
import type { AuthResult } from "../../api/auth_result";
import type { BrowserOAuth } from "../browser_oauth";
import { createMobileSocialAuth, type MobileSocialAuth } from "../mobile_social";
import type { SocialContext } from "../social_context";
import { browserSocialAuth, createSocialService } from "../social_context";

/** Apple signing credentials shared by its Browser and Native APIs. */
export type AppleOptions = {
  authKey: string;
  teamId: string;
  keyId: string;
};

/** Services ID and exact HTTPS return URI required by Apple's Browser API. */
export type AppleBrowserOptions = {
  serviceId: string;
  redirectUri: string;
};

/** App ID required when exchanging a credential from Apple's Native API. */
export type AppleNativeOptions = {
  appId: string;
};

/** Apple provider-token revocation bound to its persisted issuing client identifier. */
export type AppleTokenRevocation = {
  /** Revokes a refresh token with the App ID or Services ID that originally issued it. */
  revoke(input: {
    providerRefreshToken: string;
    providerClientId: string;
  }): Promise<AuthResult>;
};

/** Apple Browser API projected into website-cookie or Android-token delivery. */
export type AppleBrowserApi<TClaims extends Record<string, unknown>> = {
  /** Creates the website flow with browser-bound state and session cookies. */
  web(): BrowserOAuth<TClaims>;

  /** Creates the Flutter Android flow with server-bound state and nonce. */
  android(): AppleAndroidAuth<TClaims>;
};

/** Apple Native API projected into explicit iOS session-token delivery. */
export type AppleNativeApi<TClaims extends Record<string, unknown>> = {
  /** Creates the iOS authorization-code flow using the configured App ID. */
  ios(): MobileSocialAuth<TClaims, { authorizationCode: string }>;
};

/** Apple feature that selects the provider API before its delivery environment. */
export type AppleSocialAuth<TClaims extends Record<string, unknown>> = AppleTokenRevocation & {
  /** Configures the Services ID and return URI required by Apple's Browser API. */
  browser(options: AppleBrowserOptions): AppleBrowserApi<TClaims>;

  /** Configures the App ID required by Apple's Native API. */
  native(options: AppleNativeOptions): AppleNativeApi<TClaims>;
};

/** Creates the Apple feature from signing credentials shared by both provider APIs. */
export function createAppleSocialAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  options: AppleOptions,
): AppleSocialAuth<TClaims> {
  return {
    browser: (browser) => createAppleBrowserApi(context, options, browser),
    native: (native) => createAppleNativeApi(context, options, native),
    revoke: (input) => revokeAppleToken(options, input),
  };
}

/** Recreates the exact issuing-client verifier before revoking a stored token. */
function revokeAppleToken(
  options: AppleOptions,
  input: { providerRefreshToken: string; providerClientId: string },
) {
  const verifier = new AppleAuthorizationCodeVerifier({
    ...options,
    clientId: input.providerClientId,
  });

  return verifier.revoke(input.providerRefreshToken);
}

/** Creates website and Android projections sharing one Services ID and return URI. */
function createAppleBrowserApi<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  options: AppleOptions,
  browser: AppleBrowserOptions,
): AppleBrowserApi<TClaims> {
  const providerOptions = {
    ...options,
    clientId: browser.serviceId,
    redirectUri: browser.redirectUri,
  };
  const verifier = new AppleAuthorizationCodeVerifier(providerOptions);

  return {
    web: () => browserSocialAuth(context, new AppleAuth(providerOptions)),
    android: () => createAndroid(context, verifier, browser),
  };
}

/** Creates the Native API projection bound to one Apple App ID. */
function createAppleNativeApi<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  options: AppleOptions,
  native: AppleNativeOptions,
): AppleNativeApi<TClaims> {
  const verifier = new AppleAuthorizationCodeVerifier({
    ...options,
    clientId: native.appId,
  });

  return {
    ios: () => createAppleIos(context, verifier),
  };
}

/** Creates Android Browser API operations after requiring transaction persistence. */
function createAndroid<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: SocialContext<TRegistrationInput, TClaims>,
  verifier: AppleAuthorizationCodeVerifier,
  browser: AppleBrowserOptions,
) {
  if (!context.transactions) {
    throw new TypeError("Apple Android authentication requires OAuth transaction storage.");
  }

  return createAppleAndroidAuth({
    transactions: context.transactions,
    social: createSocialService(context),
    verifier,
    serviceId: browser.serviceId,
    redirectUri: browser.redirectUri,
  });
}

/** Creates Apple's Native API authorization-code verification for iOS. */
function createAppleIos<
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
  >(service, verifier, ({ authorizationCode }) => authorizationCode);
}

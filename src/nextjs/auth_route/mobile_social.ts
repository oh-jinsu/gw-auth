import type {
  MobileSocialAuth,
  SocialSignupAuth,
} from "gw-auth/core";
import type { NextRequest } from "next/server.js";

import {
  authResultResponse,
  invalidAuthRequest,
  mapAuthResult,
} from "./response";
import { readJsonObject, requiredString } from "./request";
import type {
  AuthRouteDefinition,
  AuthRouteSocial,
} from "./types";
import { appleAndroidRoutes } from "./apple_android";
import { serializeMobileSocialLogin } from "./mobile_social_result";

/** Creates provider and staged-signup mobile routes. */
export function mobileSocialRoutes<TRegistration, TClaims extends Record<string, unknown>>(
  social: AuthRouteSocial<TRegistration, TClaims>,
  siteOrigin: string,
) {
  const routes = [mobileSocialSignupRoute(social.signup.mobile())];

  addGoogleProvider(routes, social);
  addProvider(routes, "kakao", mobileFeature(social.kakao), "accessToken");
  addProvider(routes, "naver", mobileFeature(social.naver), "accessToken");
  addAppleRoutes(routes, social, siteOrigin);

  return routes;
}

/** Registers Google mobile login with its optional additional client IDs. */
function addGoogleProvider<TRegistration, TClaims extends Record<string, unknown>>(
  routes: AuthRouteDefinition[],
  social: AuthRouteSocial<TRegistration, TClaims>,
) {
  const provider = social.google;

  if (provider?.mobile) {
    const options = provider.mobile === true ? undefined : provider.mobile;

    addProvider(routes, "google", provider.feature.mobile(options), "idToken");
  }
}

/** Selects and projects a mobile provider only when explicitly enabled. */
function mobileFeature<TClaims extends Record<string, unknown>>(
  provider?: {
    feature: { mobile(): MobileSocialAuth<TClaims, { accessToken: string }> };
    mobile?: true;
  },
) {
  return provider?.mobile ? provider.feature.mobile() : undefined;
}

/** Registers one provider-specific mobile credential route when enabled. */
function addProvider<TClaims extends Record<string, unknown>, TInput>(
  routes: AuthRouteDefinition[],
  name: string,
  social: MobileSocialAuth<TClaims, TInput> | undefined,
  credentialKey: string,
) {
  if (social) {
    routes.push(route("POST", `mobile/${name}`, (request) => {
      return mobileSocialLogin(request, social, credentialKey);
    }));
  }
}

/** Parses one provider credential and serializes staged-signup expiration. */
async function mobileSocialLogin<TClaims extends Record<string, unknown>, TInput>(
  request: NextRequest,
  social: MobileSocialAuth<TClaims, TInput>,
  credentialKey: string,
) {
  const body = await readJsonObject(request);
  const credential = body && requiredString(body, credentialKey);

  if (!credential) {
    return invalidAuthRequest();
  }

  return authResultResponse(request, async () => mapAuthResult(
    await social.login({ [credentialKey]: credential } as unknown as TInput),
    serializeMobileSocialLogin,
  ));
}

/** Adds configured iOS Native API and Android Browser API routes. */
function addAppleRoutes<
  TRegistration,
  TClaims extends Record<string, unknown>,
>(
  routes: AuthRouteDefinition[],
  social: AuthRouteSocial<TRegistration, TClaims>,
  siteOrigin: string,
) {
  if (social.apple?.ios) {
    const ios = social.apple.feature.native({ appId: social.apple.ios.appId }).ios();

    addProvider(routes, "apple/native", ios, "authorizationCode");
  }

  if (social.apple?.android) {
    routes.push(...appleAndroidRoutes(social.apple, siteOrigin));
  }
}

/** Creates the fixed mobile staged social-signup completion route. */
function mobileSocialSignupRoute<TRegistration, TClaims extends Record<string, unknown>>(
  signup: ReturnType<SocialSignupAuth<TRegistration, TClaims>["mobile"]>,
): AuthRouteDefinition {
  return route("POST", "mobile/social-signup", async (request) => {
    const body = await readJsonObject(request);
    const signupToken = body && requiredString(body, "signupToken");

    return signupToken && body && "registration" in body
      ? authResultResponse(request, () => signup.complete({
        signupToken,
        registration: body.registration as TRegistration,
      }))
      : invalidAuthRequest();
  });
}

/** Creates one internal mobile social route definition. */
function route(
  method: AuthRouteDefinition["method"],
  path: string,
  handler: AuthRouteDefinition["handler"],
): AuthRouteDefinition {
  return { method, path, handler };
}

import type {
  MobileSocialAuth,
  MobileSocialLoginResult,
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

/** Creates provider and staged-signup mobile routes. */
export function mobileSocialRoutes<TRegistration, TClaims extends Record<string, unknown>>(
  social: AuthRouteSocial<TRegistration, TClaims>,
) {
  const routes = [mobileSocialSignupRoute(social.signup.mobile())];

  addProvider(routes, "google", social.google?.mobile(), "idToken");
  addProvider(routes, "kakao", social.kakao?.mobile(), "accessToken");
  addProvider(routes, "naver", social.naver?.mobile(), "accessToken");
  addProvider(routes, "apple", social.apple?.mobile(), "authorizationCode");

  return routes;
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
    serializeSocialLogin,
  ));
}

/** Converts a mobile staged-signup expiration to its JSON representation. */
function serializeSocialLogin<TClaims extends Record<string, unknown>>(
  result: MobileSocialLoginResult<TClaims>,
) {
  return result.status === "authenticated"
    ? result
    : { ...result, signupExpiresAt: result.signupExpiresAt.toISOString() };
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

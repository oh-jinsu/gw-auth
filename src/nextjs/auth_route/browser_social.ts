import type {
  BrowserOAuth,
  OAuthCompleteOutput,
  SocialSignupAuth,
} from "gw-auth/core";
import { NextResponse, type NextRequest } from "next/server.js";

import { nextRequestCookies } from "../route_handler";
import {
  authResultResponse,
  browserOperationResponse,
  invalidAuthRequest,
  relativeRedirect,
} from "./response";
import { readJsonObject, readOAuthCallback } from "./request";
import type {
  AuthRouteDefinition,
  AuthRouteSocial,
} from "./types";

/** Builds fixed browser OAuth and staged-signup routes. */
export function browserSocialRoutes<
  TRegistration,
  TClaims extends Record<string, unknown>,
>(
  social: AuthRouteSocial<TRegistration, TClaims>,
  siteOrigin: string,
) {
  const routes = socialSignupRoutes(social.signup.browser());

  addProvider(routes, "google", browserFeature(social.google), siteOrigin);
  addProvider(routes, "kakao", browserFeature(social.kakao), siteOrigin);
  addProvider(routes, "naver", browserFeature(social.naver), siteOrigin);
  addAppleProvider(routes, social, siteOrigin);

  return routes;
}

/** Selects a provider only when its browser delivery was explicitly enabled. */
function browserFeature<TFeature>(provider?: { feature: TFeature; browser?: boolean }) {
  return provider?.browser ? provider.feature : undefined;
}

/** Provider feature shape shared before the browser projection is selected. */
type BrowserProviderFeature<TClaims extends Record<string, unknown>> = {
  browser(options: { redirectUri: string }): BrowserOAuth<TClaims>;
};

/** Registers start plus GET and form-post callback routes for one provider. */
function addProvider<TClaims extends Record<string, unknown>>(
  routes: AuthRouteDefinition[],
  name: string,
  feature: BrowserProviderFeature<TClaims> | undefined,
  siteOrigin: string,
) {
  if (!feature) {
    return;
  }

  const oauth = feature.browser({ redirectUri: callbackUrl(siteOrigin, name) });

  addOAuth(routes, name, oauth);
}

/** Registers Apple website OAuth when a Services ID is enabled. */
function addAppleProvider<
  TRegistration,
  TClaims extends Record<string, unknown>,
>(
  routes: AuthRouteDefinition[],
  social: AuthRouteSocial<TRegistration, TClaims>,
  siteOrigin: string,
) {
  if (!social.apple?.web) {
    return;
  }

  const oauth = social.apple.feature.browser({
    serviceId: social.apple.web.serviceId,
    redirectUri: callbackUrl(siteOrigin, "apple"),
  }).web();

  addOAuth(routes, "apple", oauth);
}

/** Registers start and callback handlers for one configured browser OAuth flow. */
function addOAuth<TClaims extends Record<string, unknown>>(
  routes: AuthRouteDefinition[],
  name: string,
  oauth: BrowserOAuth<TClaims>,
) {
  routes.push(providerStartRoute(name, oauth));
  routes.push(providerCallbackRoute("GET", name, oauth));
  routes.push(providerCallbackRoute("POST", name, oauth));
}

/** Creates a provider start route that immediately leaves for the provider. */
function providerStartRoute<TClaims extends Record<string, unknown>>(
  name: string,
  oauth: BrowserOAuth<TClaims>,
): AuthRouteDefinition {
  return route("GET", name, (request) => browserOperationResponse(
    request,
    () => oauth.start({ redirectPath: redirectPath(request) }),
    {
      success: ({ authorizationUrl }) => NextResponse.redirect(authorizationUrl, 302),
      failure: (error) => loginRedirect(error.code),
    },
  ));
}

/** Creates one query or form-post OAuth callback route. */
function providerCallbackRoute<TClaims extends Record<string, unknown>>(
  method: "GET" | "POST",
  name: string,
  oauth: BrowserOAuth<TClaims>,
): AuthRouteDefinition {
  return route(
    method,
    `${name}/callback`,
    (request) => oauthCallback(request, oauth),
    method === "POST",
  );
}

/** Completes OAuth and applies its state or session cookie effects before redirecting. */
async function oauthCallback<TClaims extends Record<string, unknown>>(
  request: NextRequest,
  oauth: BrowserOAuth<TClaims>,
) {
  const callback = await readOAuthCallback(request);

  return browserOperationResponse(
    request,
    () => oauth.complete({ ...callback, cookies: nextRequestCookies(request) }),
    {
      success: oauthRedirect,
      failure: (error) => loginRedirect(error.code),
    },
  );
}

/** Redirects authenticated users or staged signups to the fixed UI routes. */
function oauthRedirect<TClaims extends Record<string, unknown>>(
  result: OAuthCompleteOutput<TClaims>,
) {
  return result.status === "authenticated"
    ? relativeRedirect(result.redirectPath)
    : signupRedirect(result.redirectPath);
}

/** Preserves the final redirect while sending an unknown identity to signup. */
function signupRedirect(redirectPath: string) {
  const search = new URLSearchParams({ redirectPath });

  return relativeRedirect(`/signup?${search.toString()}`);
}

/** Sends provider failures to the fixed login page without exposing a cause. */
function loginRedirect(code: string) {
  return relativeRedirect(`/login?error=${encodeURIComponent(code)}`);
}

/** Reads the optional relative post-authentication destination. */
function redirectPath(request: NextRequest) {
  return request.nextUrl.searchParams.get("redirectPath") ?? "/";
}

/** Derives the provider callback from one trusted public site origin. */
function callbackUrl(siteOrigin: string, provider: string) {
  return new URL(`/api/auth/${provider}/callback`, siteOrigin).toString();
}

/** Creates fixed browser staged-signup profile and completion routes. */
function socialSignupRoutes<
  TRegistration,
  TClaims extends Record<string, unknown>,
>(signup: ReturnType<SocialSignupAuth<TRegistration, TClaims>["browser"]>) {
  return [
    route("GET", "social-signup", (request) => authResultResponse(
      request,
      () => signup.profile({ cookies: nextRequestCookies(request) }),
    )),
    route("POST", "social-signup", (request) => completeSignup(request, signup)),
  ];
}

/** Parses the fixed registration wrapper and completes staged browser signup. */
async function completeSignup<TRegistration, TClaims extends Record<string, unknown>>(
  request: NextRequest,
  signup: ReturnType<SocialSignupAuth<TRegistration, TClaims>["browser"]>,
) {
  const body = await readJsonObject(request);

  return body && "registration" in body
    ? browserOperationResponse(request, () => signup.complete({
      cookies: nextRequestCookies(request),
      registration: body.registration as TRegistration,
    }))
    : invalidAuthRequest();
}

/** Creates one internal social route definition. */
function route(
  method: AuthRouteDefinition["method"],
  path: string,
  handler: AuthRouteDefinition["handler"],
  acceptsCrossOrigin = false,
): AuthRouteDefinition {
  return { method, path, handler, acceptsCrossOrigin };
}

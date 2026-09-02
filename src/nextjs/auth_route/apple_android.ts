import type { AppleAndroidAuth } from "gw-auth/core";
import type { NextRequest } from "next/server.js";

import {
  authResultResponse,
  externalRedirect,
  invalidAuthRequest,
  mapAuthResult,
} from "./response";
import {
  readAppleCallbackParameters,
  readJsonObject,
  requiredString,
} from "./request";
import { serializeMobileSocialLogin } from "./mobile_social_result";
import type { AuthRouteApple, AuthRouteDefinition } from "./types";

/** Creates Flutter-compatible Android Apple routes from one Services ID. */
export function appleAndroidRoutes<TClaims extends Record<string, unknown>>(
  apple: AuthRouteApple<TClaims>,
  siteOrigin: string,
) {
  const android = apple.android!;
  const auth = apple.feature.browser({
    serviceId: android.serviceId,
    redirectUri: androidCallbackUrl(siteOrigin),
  }).android();

  return [
    startRoute(auth),
    completeRoute(auth),
    callbackRoute(android.packageId),
  ];
}

/** Returns server-owned state and nonce for `getAppleIDCredential`. */
function startRoute<TClaims extends Record<string, unknown>>(
  auth: AppleAndroidAuth<TClaims>,
): AuthRouteDefinition {
  return route("POST", "mobile/apple/browser/start", (request) => {
    return authResultResponse(request, () => auth.start());
  });
}

/** Exchanges the Flutter credential after consuming its server-owned state. */
function completeRoute<TClaims extends Record<string, unknown>>(
  auth: AppleAndroidAuth<TClaims>,
): AuthRouteDefinition {
  return route("POST", "mobile/apple/browser", (request) => {
    return completeAndroidApple(request, auth);
  });
}

/** Relays Apple's form-post values into the Flutter plugin callback Activity. */
function callbackRoute(packageId: string): AuthRouteDefinition {
  return route("POST", "mobile/apple/callback", async (request) => {
    const parameters = await readAppleCallbackParameters(request);

    return parameters
      ? externalRedirect(androidIntent(packageId, parameters), 302)
      : invalidAuthRequest("Apple callback 형식이 유효하지 않습니다.");
  }, true);
}

/** Parses and completes one Android Apple browser credential. */
async function completeAndroidApple<TClaims extends Record<string, unknown>>(
  request: NextRequest,
  auth: AppleAndroidAuth<TClaims>,
) {
  const body = await readJsonObject(request);
  const authorizationCode = body && requiredString(body, "authorizationCode");
  const state = body && requiredString(body, "state");

  if (!authorizationCode || !state) {
    return invalidAuthRequest();
  }

  return authResultResponse(request, async () => mapAuthResult(
    await auth.complete({ authorizationCode, state }),
    serializeMobileSocialLogin,
  ));
}

/** Derives the exact Apple HTTPS callback registered for the Android flow. */
function androidCallbackUrl(siteOrigin: string) {
  return new URL("/api/auth/mobile/apple/callback", siteOrigin).toString();
}

/** Builds the exact Intent URI consumed by Flutter's sign_in_with_apple plugin. */
function androidIntent(packageId: string, parameters: URLSearchParams) {
  return `intent://callback?${parameters.toString()}`
    + `#Intent;package=${packageId};scheme=signinwithapple;end`;
}

/** Creates one internal Android Apple route definition. */
function route(
  method: AuthRouteDefinition["method"],
  path: string,
  handler: AuthRouteDefinition["handler"],
  acceptsCrossOrigin = false,
): AuthRouteDefinition {
  return { method, path, handler, acceptsCrossOrigin };
}

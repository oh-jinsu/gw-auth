import type { AppleAndroidAuth } from "gw-auth/core";
import type { NextRequest } from "next/server.js";

import {
  authResultResponse,
  externalRedirect,
  invalidAuthRequest,
  mapAuthResult,
} from "./response";
import {
  readFormStrings,
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
  }).android({ packageId: android.packageId });

  return [
    startRoute(auth),
    completeRoute(auth),
    callbackRoute(auth),
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
function callbackRoute<TClaims extends Record<string, unknown>>(
  auth: AppleAndroidAuth<TClaims>,
): AuthRouteDefinition {
  return route("POST", "mobile/apple/callback", async (request) => {
    const values = await readFormStrings(request);

    if (!values) {
      return invalidAuthRequest("Apple callback 형식이 유효하지 않습니다.");
    }

    const handoff = auth.handoff(values);

    return handoff.isOk
      ? externalRedirect(handoff.value.redirectUrl, 302)
      : authResultResponse(request, async () => handoff);
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

/** Creates one internal Android Apple route definition. */
function route(
  method: AuthRouteDefinition["method"],
  path: string,
  handler: AuthRouteDefinition["handler"],
  acceptsCrossOrigin = false,
): AuthRouteDefinition {
  return { method, path, handler, acceptsCrossOrigin };
}

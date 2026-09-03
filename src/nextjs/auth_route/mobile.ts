import type {
  AuthResult,
  GuestAuth,
  MobileGuestAuthentication,
  MobilePasswordAuth,
  MobileAccountAuth,
  MobileSessionAuth,
} from "gw-auth/core";
import type { NextRequest } from "next/server.js";

import {
  accessTokenRequired,
  authResultResponse,
  invalidAuthRequest,
  mapAuthResult,
} from "./response";
import { bearerToken, optionalString, readJsonObject, requiredString } from "./request";
import { mobileSocialRoutes } from "./mobile_social";
import type {
  AuthRouteDefinition,
  AuthRouteOptions,
} from "./types";

/** Builds fixed mobile routes from the same unprojected features as browser routes. */
export function mobileAuthRoutes<
  TClaims extends Record<string, unknown>,
  TPasswordRegistration,
  TSocialRegistration,
>(options: AuthRouteOptions<TClaims, TPasswordRegistration, TSocialRegistration>) {
  const routes = mobileSessionRoutes(options.session.mobile());

  if (options.password) {
    routes.push(...mobilePasswordRoutes(options.password.mobile()));
  }

  if (options.account) {
    routes.push(mobileAccountDeletionRoute(options.account.mobile()));
  }

  if (options.guest) {
    routes.push(mobileGuestRoute(options.guest.mobile()));
  }

  if (options.social) {
    routes.push(...mobileSocialRoutes(options.social, options.siteOrigin));
  }

  return routes;
}

/** Creates account deletion from the standard bearer access-token header. */
function mobileAccountDeletionRoute(account: MobileAccountAuth): AuthRouteDefinition {
  return route("POST", "mobile/account/delete", async (request) => {
    const accessToken = bearerToken(request);

    return accessToken
      ? authResultResponse(request, () => account.delete({ accessToken }))
      : accessTokenRequired();
  });
}

/** Creates fixed mobile refresh and logout routes. */
function mobileSessionRoutes<TClaims extends Record<string, unknown>>(
  session: MobileSessionAuth<TClaims>,
): AuthRouteDefinition[] {
  return [
    route("POST", "mobile/refresh", (request) => requiredBodyOperation(
      request,
      "refreshToken",
      (refreshToken) => session.refresh({ refreshToken }),
    )),
    route("POST", "mobile/logout", (request) => requiredBodyOperation(
      request,
      "refreshToken",
      (refreshToken) => session.logout({ refreshToken }),
    )),
  ];
}

/** Creates fixed mobile password login and signup routes. */
function mobilePasswordRoutes<TRegistration, TClaims extends Record<string, unknown>>(
  password: MobilePasswordAuth<TRegistration, TClaims>,
): AuthRouteDefinition[] {
  return [
    route("POST", "mobile/password/login", (request) => passwordLogin(request, password)),
    route("POST", "mobile/password/signup", (request) => passwordSignup(request, password)),
  ];
}

/** Parses and executes a mobile password-login request. */
async function passwordLogin<TRegistration, TClaims extends Record<string, unknown>>(
  request: NextRequest,
  password: MobilePasswordAuth<TRegistration, TClaims>,
) {
  const body = await readJsonObject(request);
  const id = body && requiredString(body, "id");
  const secret = body && requiredString(body, "password");

  return id && secret
    ? authResultResponse(request, () => password.login({ id, password: secret }))
    : invalidAuthRequest();
}

/** Parses and executes a mobile password-signup request. */
async function passwordSignup<TRegistration, TClaims extends Record<string, unknown>>(
  request: NextRequest,
  password: MobilePasswordAuth<TRegistration, TClaims>,
) {
  const body = await readJsonObject(request);
  const input = body && passwordSignupInput<TRegistration>(body);

  return input
    ? authResultResponse(request, () => password.signup(input))
    : invalidAuthRequest();
}

/** Reads fixed mobile password-signup fields and opaque registration data. */
function passwordSignupInput<TRegistration>(body: Record<string, unknown>) {
  const id = requiredString(body, "id");
  const password = requiredString(body, "password");
  const passwordConfirm = requiredString(body, "passwordConfirm");

  return id && password && passwordConfirm && "registration" in body
    ? { id, password, passwordConfirm, registration: body.registration as TRegistration }
    : undefined;
}

/** Creates the fixed mobile guest-authentication route. */
function mobileGuestRoute<TClaims extends Record<string, unknown>>(
  guest: ReturnType<GuestAuth<TClaims>["mobile"]>,
): AuthRouteDefinition {
  return route("POST", "mobile/guest", async (request) => {
    const body = await readJsonObject(request);
    const credential = body && optionalString(body, "guestCredential");

    if (!body || credential === null) {
      return invalidAuthRequest();
    }

    return authResultResponse(request, async () => mapAuthResult(
      await guest.authenticate({ guestCredential: credential }),
      serializeGuest,
    ));
  });
}

/** Converts the mobile guest credential expiry to its JSON representation. */
function serializeGuest<TClaims extends Record<string, unknown>>(
  result: MobileGuestAuthentication<TClaims>,
) {
  return { ...result, guestCredentialExpiresAt: result.guestCredentialExpiresAt.toISOString() };
}

/** Executes an operation from one required string JSON field. */
async function requiredBodyOperation<TValue>(
  request: NextRequest,
  key: string,
  operation: (value: string) => Promise<AuthResult<TValue>>,
) {
  const body = await readJsonObject(request);
  const value = body && requiredString(body, key);

  return value ? authResultResponse(request, () => operation(value)) : invalidAuthRequest();
}

/** Creates one internal mobile route definition. */
function route(
  method: AuthRouteDefinition["method"],
  path: string,
  handler: AuthRouteDefinition["handler"],
): AuthRouteDefinition {
  return { method, path, handler };
}

import {
  authStateFromAccessPayload,
  type BrowserAccountAuth,
  type BrowserPasswordAuth,
  type BrowserSessionAuth,
  type GuestAuth,
  type PasswordRecoveryAuth,
} from "gw-auth/core";
import type { NextRequest } from "next/server.js";

import { nextRequestCookies } from "../route_handler";
import {
  authResultResponse,
  browserOperationResponse,
  invalidAuthRequest,
  mapAuthResult,
} from "./response";
import { readJsonObject, requiredString } from "./request";
import type { AuthRouteDefinition, AuthRouteOptions } from "./types";

/** Builds fixed browser routes for every enabled non-social feature. */
export function browserAuthRoutes<
  TClaims extends Record<string, unknown>,
  TPasswordRegistration,
  TSocialRegistration,
>(options: AuthRouteOptions<TClaims, TPasswordRegistration, TSocialRegistration>) {
  const routes = sessionRoutes(options.session.browser());

  if (options.password) {
    routes.push(...passwordRoutes(options.password.browser()));
  }

  if (options.account) {
    routes.push(accountDeletionRoute(options.account.browser()));
  }

  if (options.guest) {
    routes.push(...guestRoutes(options.guest.browser()));
  }

  if (options.recovery) {
    routes.push(...recoveryRoutes(options.recovery));
  }

  return routes;
}

/** Creates browser session verification, refresh, and logout routes. */
function sessionRoutes<TClaims extends Record<string, unknown>>(
  session: BrowserSessionAuth<TClaims>,
): AuthRouteDefinition[] {
  return [
    route("GET", "session", (request) => authResultResponse(
      request,
      async () => mapAuthResult(
        await session.verify({ cookies: nextRequestCookies(request) }),
        authStateFromAccessPayload,
      ),
    )),
    route("POST", "refresh", (request) => browserOperationResponse(
      request,
      () => session.refresh({ cookies: nextRequestCookies(request) }),
    )),
    route("POST", "logout", (request) => browserOperationResponse(
      request,
      () => session.logout({ cookies: nextRequestCookies(request) }),
    )),
  ];
}

/** Creates account deletion for the user represented by browser cookies. */
function accountDeletionRoute(account: BrowserAccountAuth): AuthRouteDefinition {
  return route("POST", "account/delete", (request) => browserOperationResponse(
    request,
    () => account.delete({ cookies: nextRequestCookies(request) }),
  ));
}

/** Creates fixed browser password login and signup routes. */
function passwordRoutes<TRegistration, TClaims extends Record<string, unknown>>(
  password: BrowserPasswordAuth<TRegistration, TClaims>,
): AuthRouteDefinition[] {
  return [
    route("POST", "login", (request) => passwordLogin(request, password)),
    route("POST", "signup", (request) => passwordSignup(request, password)),
  ];
}

/** Parses and executes the fixed password-login request body. */
async function passwordLogin<TRegistration, TClaims extends Record<string, unknown>>(
  request: NextRequest,
  password: BrowserPasswordAuth<TRegistration, TClaims>,
) {
  const body = await readJsonObject(request);
  const id = body && requiredString(body, "id");
  const secret = body && requiredString(body, "password");

  return id && secret
    ? browserOperationResponse(request, () => password.login({ id, password: secret }))
    : invalidAuthRequest();
}

/** Parses and executes the fixed password-signup request body. */
async function passwordSignup<TRegistration, TClaims extends Record<string, unknown>>(
  request: NextRequest,
  password: BrowserPasswordAuth<TRegistration, TClaims>,
) {
  const body = await readJsonObject(request);
  const input = body && passwordSignupInput<TRegistration>(body);

  return input
    ? browserOperationResponse(request, () => password.signup(input))
    : invalidAuthRequest();
}

/** Selects common password fields and the opaque application registration value. */
function passwordSignupInput<TRegistration>(body: Record<string, unknown>) {
  const id = requiredString(body, "id");
  const password = requiredString(body, "password");
  const passwordConfirm = requiredString(body, "passwordConfirm");

  return id && password && passwordConfirm && "registration" in body
    ? { id, password, passwordConfirm, registration: body.registration as TRegistration }
    : undefined;
}

/** Creates the fixed browser guest-authentication route. */
function guestRoutes<TClaims extends Record<string, unknown>>(
  guest: ReturnType<GuestAuth<TClaims>["browser"]>,
): AuthRouteDefinition[] {
  return [route("POST", "guest", (request) => browserOperationResponse(
    request,
    () => guest.authenticate({ cookies: nextRequestCookies(request) }),
  ))];
}

/** Creates fixed password-reset request and completion routes. */
function recoveryRoutes(recovery: PasswordRecoveryAuth): AuthRouteDefinition[] {
  return [
    route("POST", "password-reset/request", (request) => recoveryRequest(request, recovery)),
    route("POST", "password-reset/complete", (request) => recoveryComplete(request, recovery)),
  ];
}

/** Parses and executes a password-reset discovery request. */
async function recoveryRequest(request: NextRequest, recovery: PasswordRecoveryAuth) {
  const body = await readJsonObject(request);
  const credentialId = body && requiredString(body, "credentialId");

  return credentialId
    ? authResultResponse(request, () => recovery.request({ credentialId }))
    : invalidAuthRequest();
}

/** Parses and executes a password-reset completion request. */
async function recoveryComplete(request: NextRequest, recovery: PasswordRecoveryAuth) {
  const body = await readJsonObject(request);
  const input = body && recoveryInput(body);

  return input
    ? authResultResponse(request, () => recovery.reset(input))
    : invalidAuthRequest();
}

/** Reads the fixed password-reset completion fields. */
function recoveryInput(body: Record<string, unknown>) {
  const token = requiredString(body, "token");
  const password = requiredString(body, "password");
  const passwordConfirm = requiredString(body, "passwordConfirm");

  return token && password && passwordConfirm ? { token, password, passwordConfirm } : undefined;
}

/** Creates one internal exact-path route definition. */
function route(
  method: AuthRouteDefinition["method"],
  path: string,
  handler: AuthRouteDefinition["handler"],
): AuthRouteDefinition {
  return { method, path, handler };
}

import type { NextRequest } from "next/server.js";

import { browserAuthRoutes } from "./browser";
import { browserSocialRoutes } from "./browser_social";
import { mobileAuthRoutes } from "./mobile";
import {
  authMethodNotAllowed,
  authOriginForbidden,
  authRouteNotFound,
} from "./response";
import type {
  AuthRouteContext,
  AuthRouteDefinition,
  AuthRouteHandlers,
  AuthRouteMethod,
  AuthRouteOptions,
} from "./types";

/**
 * Creates fixed GET and POST handlers for `app/api/auth/[...auth]/route.ts`.
 * @throws {TypeError} When `siteOrigin` is not an exact HTTPS or localhost origin.
 */
export function createAuthRoute<
  TClaims extends Record<string, unknown>,
  TPasswordRegistration = unknown,
  TSocialRegistration = unknown,
>(
  options: AuthRouteOptions<TClaims, TPasswordRegistration, TSocialRegistration>,
): AuthRouteHandlers {
  assertSiteOrigin(options.siteOrigin);

  const routes = allRoutes(options);

  return {
    GET: methodHandler("GET", routes, options.siteOrigin),
    POST: methodHandler("POST", routes, options.siteOrigin),
  };
}

/** Collects browser, mobile, and optional social routes once at composition time. */
function allRoutes<
  TClaims extends Record<string, unknown>,
  TPasswordRegistration,
  TSocialRegistration,
>(options: AuthRouteOptions<TClaims, TPasswordRegistration, TSocialRegistration>) {
  const routes = [
    ...browserAuthRoutes(options),
    ...mobileAuthRoutes(options),
  ];

  if (options.social) {
    routes.push(...browserSocialRoutes(options.social, options.siteOrigin));
  }

  return routes;
}

/** Binds one exported HTTP method to the shared exact-path dispatcher. */
function methodHandler(
  method: AuthRouteMethod,
  routes: AuthRouteDefinition[],
  siteOrigin: string,
) {
  return (request: NextRequest, context: AuthRouteContext) => {
    return dispatchRoute(method, routes, request, context, siteOrigin);
  };
}

/** Dispatches a catch-all request or returns stable 404 and 405 responses. */
async function dispatchRoute(
  method: AuthRouteMethod,
  routes: AuthRouteDefinition[],
  request: NextRequest,
  context: AuthRouteContext,
  siteOrigin: string,
) {
  const path = await authPath(context);
  const matched = routes.find((route) => route.path === path && route.method === method);

  if (matched) {
    if (!matched.acceptsCrossOrigin && !hasTrustedOrigin(request, siteOrigin)) {
      return authOriginForbidden();
    }

    return matched.handler(request);
  }

  const allowed = routes.filter((route) => route.path === path).map((route) => route.method);

  return allowed.length ? authMethodNotAllowed(allowed) : authRouteNotFound();
}

/** Accepts same-origin browser requests and clients that do not send Origin. */
function hasTrustedOrigin(request: NextRequest, siteOrigin: string) {
  const origin = request.headers.get("Origin");

  return origin === null || origin === siteOrigin;
}

/** Joins the required catch-all parameter into one internal route key. */
async function authPath(context: AuthRouteContext) {
  const params = await context.params;

  return Array.isArray(params.auth) ? params.auth.join("/") : "";
}

/** Rejects untrusted or ambiguous OAuth callback origins at composition time. */
function assertSiteOrigin(siteOrigin: string) {
  const parsed = new URL(siteOrigin);
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
  const secure = parsed.protocol === "https:" || (parsed.protocol === "http:" && local);

  if (parsed.origin !== siteOrigin || !secure) {
    throw new TypeError("AuthRoute siteOrigin must be an HTTPS origin or localhost origin.");
  }
}

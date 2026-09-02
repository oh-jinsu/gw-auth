import { NextResponse, type NextRequest } from "next/server.js";

import type {
  AuthError,
  BrowserCookieValues,
  BrowserOperation,
} from "gw-auth/core";
import { applyResponseCookies } from "./cookie";
import {
  nextAuthResponse,
  publicAuthError,
  type NextAuthError,
} from "./result";

const unauthorizedCodes = new Set([
  "ACCESS_TOKEN_REQUIRED",
  "INVALID_ACCESS_TOKEN",
  "INVALID_GUEST_CREDENTIAL",
  "INVALID_OAUTH_STATE",
  "INVALID_PASSWORD",
  "INVALID_PROVIDER_CREDENTIAL",
  "INVALID_SOCIAL_SIGNUP_TOKEN",
  "INVALID_TOKEN",
  "REFRESH_TOKEN_REQUIRED",
  "REFRESH_TOKEN_REUSED",
  "SESSION_USER_NOT_FOUND",
]);

/** Maps one core operation to a Next.js App Router handler invocation. */
export type NextAuthRouteOperation<TContext, TValue> = (
  request: NextRequest,
  context: TContext,
) => Promise<BrowserOperation<TValue>>;

/** Optional HTTP response policy for a Next.js authentication route. */
export type NextAuthRouteOptions<TValue> = {
  success?: (value: TValue, request: NextRequest) => NextResponse;
  failure?: (error: NextAuthError, request: NextRequest) => NextResponse;
  errorStatus?: (error: NextAuthError) => number;
};

/** Creates an App Router Route Handler and applies cookie effects on both branches. */
export function routeHandler<TValue, TContext = unknown>(
  operation: NextAuthRouteOperation<TContext, TValue>,
  options: NextAuthRouteOptions<TValue> = {},
) {
  return async (request: NextRequest, context: TContext) => {
    const completed = await operation(request, context);
    const response = operationResponse(completed, request, options);

    applyResponseCookies(response, completed.cookies);

    return preventCaching(response);
  };
}

/** Converts all request cookies to the framework-neutral core input shape. */
export function nextRequestCookies(request: NextRequest): BrowserCookieValues {
  return Object.fromEntries(
    request.cookies.getAll().map(({ name, value }) => [name, value]),
  );
}

/** Builds either an application-supplied response or the default JSON envelope. */
function operationResponse<TValue>(
  operation: BrowserOperation<TValue>,
  request: NextRequest,
  options: NextAuthRouteOptions<TValue>,
) {
  if (operation.result.isOk) {
    return options.success?.(operation.result.value, request)
      ?? NextResponse.json(nextAuthResponse(operation.result));
  }

  return failureResponse(operation.result.error, request, options);
}

/** Builds a sanitized failure response without exposing an internal error cause. */
function failureResponse<TValue>(
  error: AuthError,
  request: NextRequest,
  options: NextAuthRouteOptions<TValue>,
) {
  const publicError = publicAuthError(error);

  return options.failure?.(publicError, request)
    ?? NextResponse.json(
      { ok: false, error: publicError },
      { status: options.errorStatus?.(publicError) ?? defaultErrorStatus(publicError) },
    );
}

/** Prevents intermediaries and browsers from caching authentication responses. */
function preventCaching(response: NextResponse) {
  response.headers.set("Cache-Control", "no-store");

  return response;
}

/** Provides conservative defaults while allowing applications to override statuses. */
function defaultErrorStatus(error: NextAuthError) {
  if (error.code === "AUTH_SYSTEM_FAILURE") {
    return 500;
  }

  if (error.code.endsWith("ALREADY_EXISTS")) {
    return 409;
  }

  return unauthorizedCodes.has(error.code) ? 401 : 400;
}

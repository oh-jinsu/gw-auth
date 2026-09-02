import { NextResponse, type NextRequest } from "next/server.js";

import {
  authErrorCategory,
  type AuthError,
  type AuthResult,
  type BrowserCookieValues,
  type BrowserOperation,
} from "gw-auth/core";
import { applyResponseCookies } from "./cookie";
import { normalizeAuthOperation } from "./operation";
import {
  nextAuthResponse,
  publicAuthError,
  type NextAuthError,
} from "./result";

/** Maps one core operation to a Next.js App Router handler invocation. */
export type NextAuthRouteOperation<TContext, TValue> = (
  request: NextRequest,
  context: TContext,
) => Promise<BrowserOperation<TValue>>;

/** Cookie-free core result mapped by a Next.js Route Handler. */
export type NextAuthResultRouteOperation<TContext, TValue> = (
  request: NextRequest,
  context: TContext,
) => Promise<AuthResult<TValue>>;

/** Optional HTTP response policy for a Next.js authentication route. */
export type NextAuthRouteOptions<TValue> = {
  success?: (value: TValue, request: NextRequest) => NextResponse;
  failure?: (error: NextAuthError, request: NextRequest) => NextResponse;
  errorStatus?: (error: NextAuthError) => number;
};

/** Creates an App Router Route Handler and applies cookie effects on both branches. */
export function routeHandler<TValue, TContext = unknown>(
  operation: NextAuthRouteOperation<TContext, TValue>,
  options?: NextAuthRouteOptions<TValue>,
): (request: NextRequest, context: TContext) => Promise<NextResponse>;
export function routeHandler<TValue, TContext = unknown>(
  operation: NextAuthResultRouteOperation<TContext, TValue>,
  options?: NextAuthRouteOptions<TValue>,
): (request: NextRequest, context: TContext) => Promise<NextResponse>;
export function routeHandler<TValue, TContext = unknown>(
  operation:
    | NextAuthRouteOperation<TContext, TValue>
    | NextAuthResultRouteOperation<TContext, TValue>,
  options: NextAuthRouteOptions<TValue> = {},
) {
  return async (request: NextRequest, context: TContext) => {
    const completed = normalizeAuthOperation(await operation(request, context));
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
  const statuses = {
    authentication: 401,
    conflict: 409,
    request: 400,
    system: 500,
    upstream: 502,
  } as const;

  return statuses[authErrorCategory(error)];
}

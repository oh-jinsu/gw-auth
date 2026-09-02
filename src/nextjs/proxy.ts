import {
  NextResponse,
  type NextFetchEvent,
  type NextProxy,
  type NextRequest,
} from "next/server.js";

import type {
  BrowserSessionAuth,
  SessionAccessPayload,
} from "gw-auth/core";
import { applyResponseCookies } from "./cookie";
import { nextRequestCookies } from "./route_handler";

/** Proxy callback receiving optimistic authentication resolved from the access token. */
export type AuthenticatedNextProxy<
  TClaims extends Record<string, unknown>,
> = (
  request: NextRequest,
  event: NextFetchEvent,
  auth: SessionAccessPayload<TClaims> | undefined,
) => ReturnType<NextProxy>;

/** Adds optimistic access verification and safe-request refresh to a Next.js Proxy. */
export function withAuth<TClaims extends Record<string, unknown>>(
  session: BrowserSessionAuth<TClaims>,
  proxy: AuthenticatedNextProxy<TClaims>,
): NextProxy {
  return (request, event) => authenticatedProxyRequest(session, proxy, request, event);
}

/** Resolves access state and refreshes only navigation-safe requests. */
async function authenticatedProxyRequest<TClaims extends Record<string, unknown>>(
  session: BrowserSessionAuth<TClaims>,
  proxy: AuthenticatedNextProxy<TClaims>,
  request: NextRequest,
  event: NextFetchEvent,
) {
  const values = nextRequestCookies(request);
  const verified = await session.verify({ cookies: values });

  if (verified.isOk) {
    return proxy(request, event, verified.value);
  }

  return isSafeRequest(request)
    ? refreshProxySession(session, proxy, request, event, values)
    : proxy(request, event, undefined);
}

/** Attempts session rotation before continuing an unauthenticated safe request. */
async function refreshProxySession<TClaims extends Record<string, unknown>>(
  session: BrowserSessionAuth<TClaims>,
  proxy: AuthenticatedNextProxy<TClaims>,
  request: NextRequest,
  event: NextFetchEvent,
  values: ReturnType<typeof nextRequestCookies>,
) {
  const refreshed = await session.refresh({ cookies: values });

  if (refreshed.result.isOk || refreshed.cookies.length > 0) {
    return redirectWithCookies(request, refreshed.cookies);
  }

  return proxy(request, event, undefined);
}

/** Creates a no-store same-URL redirect carrying core cookie mutations. */
function redirectWithCookies(
  request: NextRequest,
  mutations: Parameters<typeof applyResponseCookies>[1],
) {
  const response = NextResponse.redirect(request.nextUrl);

  applyResponseCookies(response, mutations);
  response.headers.set("Cache-Control", "no-store");

  return response;
}

/** Restricts redirect-based refresh to idempotent navigation requests. */
function isSafeRequest(request: NextRequest) {
  return request.method === "GET" || request.method === "HEAD";
}

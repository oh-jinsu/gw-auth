import { ok, type Result } from "gw-result";
import type { AuthError, AuthResult, BrowserOperation } from "gw-auth/core";
import { NextResponse, type NextRequest } from "next/server.js";

import { routeHandler, type NextAuthRouteOptions } from "../route_handler";

/** Runs one browser operation through the existing cookie-aware Route Handler. */
export function browserOperationResponse<TValue>(
  request: NextRequest,
  operation: () => Promise<BrowserOperation<TValue>>,
  options: NextAuthRouteOptions<TValue> = {},
) {
  return routeHandler(operation, options)(request, undefined);
}

/** Serializes one cookie-free core result through the standard response contract. */
export function authResultResponse<TValue>(
  request: NextRequest,
  operation: () => Promise<AuthResult<TValue>>,
) {
  return routeHandler(operation)(request, undefined);
}

/** Maps only the successful value of an authentication result. */
export function mapAuthResult<TValue, TNext>(
  result: AuthResult<TValue>,
  map: (value: TValue) => TNext,
): Result<TNext, AuthError> {
  return result.isErr ? result : ok(map(result.value));
}

/** Returns a stable no-store response for a malformed fixed-route request. */
export function invalidAuthRequest(message = "인증 요청 형식이 유효하지 않습니다.") {
  return authRouteError("INVALID_AUTH_REQUEST", message, 400);
}

/** Returns a stable authentication failure when a bearer access token is absent. */
export function accessTokenRequired() {
  return authRouteError("ACCESS_TOKEN_REQUIRED", "액세스 토큰이 필요합니다.", 401);
}

/** Rejects a browser request carrying an untrusted explicit Origin header. */
export function authOriginForbidden() {
  return authRouteError("AUTH_ORIGIN_FORBIDDEN", "허용되지 않은 요청 출처입니다.", 403);
}

/** Returns a no-store response when no fixed authentication path matches. */
export function authRouteNotFound() {
  return authRouteError("AUTH_ROUTE_NOT_FOUND", "인증 경로를 찾을 수 없습니다.", 404);
}

/** Returns a no-store response when the path exists under a different method. */
export function authMethodNotAllowed(methods: string[]) {
  const response = authRouteError("AUTH_METHOD_NOT_ALLOWED", "허용되지 않은 요청 방식입니다.", 405);

  response.headers.set("Allow", methods.join(", "));

  return response;
}

/** Creates a relative redirect without trusting the incoming request origin. */
export function relativeRedirect(path: string, status = 303) {
  return noStore(new NextResponse(null, { status, headers: { Location: path } }));
}

/** Creates a no-store redirect to one adapter-validated external destination. */
export function externalRedirect(url: string, status = 303) {
  return noStore(new NextResponse(null, { status, headers: { Location: url } }));
}

/** Creates one sanitized fixed-route failure envelope. */
function authRouteError(code: string, message: string, status: number) {
  return noStore(NextResponse.json({
    ok: false,
    error: { kind: "GW_AUTH_ERROR", code, message },
  }, { status }));
}

/** Prevents caching of dispatcher-generated errors and redirects. */
function noStore(response: NextResponse) {
  response.headers.set("Cache-Control", "no-store");

  return response;
}

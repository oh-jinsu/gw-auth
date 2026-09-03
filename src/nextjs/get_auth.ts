import { headers } from "next/headers.js";

import {
  AuthError,
  authStateFromAccessPayload,
  type AuthResult,
  type AuthState,
  type BrowserSessionAuth,
  type MobileSessionAuth,
  type SessionAuth,
} from "gw-auth/core";
import { err, ok } from "gw-result";

import { bearerToken } from "./bearer_token";
import {
  applyServerCookies,
  nextServerCookieStore,
  serverCookieValues,
} from "./server_cookie";

/** Verifies the access cookie and returns browser-safe state without JWT metadata. */
export async function getAuth<TClaims extends Record<string, unknown>>(
  session: BrowserSessionAuth<TClaims>,
): Promise<AuthResult<AuthState<TClaims>>> {
  const store = await nextServerCookieStore();
  const verified = await session.verify({ cookies: serverCookieValues(store) });

  return verified.isErr ? verified : ok(authStateFromAccessPayload(verified.value));
}

/** Resolves auth and applies refresh cookies inside a Server Action or Route Handler. */
export async function getAuthWithRefresh<TClaims extends Record<string, unknown>>(
  session: BrowserSessionAuth<TClaims>,
): Promise<AuthResult<AuthState<TClaims>>> {
  const store = await nextServerCookieStore();
  const values = serverCookieValues(store);
  const verified = await session.verify({ cookies: values });

  if (verified.isOk) {
    return ok(authStateFromAccessPayload(verified.value));
  }

  const refreshed = await session.refresh({ cookies: values });

  applyServerCookies(store, refreshed.cookies);

  return refreshed.result;
}

/** Bound Next.js authentication lookups over one shared browser and mobile session facade. */
export type AuthResolver<TClaims extends Record<string, unknown>> = {
  /** Verifies cookies and refreshes by default when access verification fails. */
  cookies(options?: {
    /** Enables refresh and cleanup cookie writes after failed access verification. */
    refresh?: boolean;
  }): Promise<AuthResult<AuthState<TClaims>>>;

  /** Resolves a strict bearer header or uses refresh-capable cookies when that header is absent. */
  request(): Promise<AuthResult<AuthState<TClaims>>>;
};

/** Binds one session facade to reusable Next.js server authentication lookups. */
export function createAuthResolver<TClaims extends Record<string, unknown>>(
  session: SessionAuth<TClaims>,
): AuthResolver<TClaims> {
  const browser = session.browser();
  const mobile = session.mobile();

  return {
    cookies: ({ refresh = true } = {}) => refresh ? getAuthWithRefresh(browser) : getAuth(browser),
    request: () => resolveRequestAuth(browser, mobile),
  };
}

/** Selects explicit bearer authentication whenever an Authorization header is present. */
async function resolveRequestAuth<TClaims extends Record<string, unknown>>(
  browser: BrowserSessionAuth<TClaims>,
  mobile: MobileSessionAuth<TClaims>,
) {
  const authorization = (await headers()).get("Authorization");

  if (authorization === null) {
    return getAuthWithRefresh(browser);
  }

  const accessToken = bearerToken(authorization);

  return accessToken
    ? verifyBearerAuth(mobile, accessToken)
    : err(new AuthError("ACCESS_TOKEN_REQUIRED", "액세스 토큰이 필요합니다."));
}

/** Verifies a bearer access token and removes JWT-managed transport metadata. */
async function verifyBearerAuth<TClaims extends Record<string, unknown>>(
  session: MobileSessionAuth<TClaims>,
  accessToken: string,
) {
  const verified = await session.verify({ accessToken });

  return verified.isErr ? verified : ok(authStateFromAccessPayload(verified.value));
}

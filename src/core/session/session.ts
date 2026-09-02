import { ok } from "gw-result";

import type { AuthState, SessionAccessPayload } from "../jwt_payload";
import { authError } from "../auth_error";
import type { SessionAuthService } from "./session_auth_service";
import type { AuthResult, MobileSession } from "../api/auth_result";
import type { AuthContext } from "../api/context";
import { readBrowserCookie, type BrowserCookieValues } from "../api/browser_cookie";
import type { BrowserOperation } from "../api/browser_operation";
import { browserSessionResult, sessionCookieDeletions } from "./session_result";

const invalidBrowserRefreshCodes = new Set([
  "INVALID_REFRESH_TOKEN",
  "REFRESH_TOKEN_REUSED",
  "SESSION_USER_MISMATCH",
  "SESSION_USER_NOT_FOUND",
]);

/** Parsed cookies supplied to browser session operations by an external adapter. */
export type BrowserSessionInput = {
  cookies: BrowserCookieValues;
};

/** Session operations shared by every configured authentication feature. */
export type SessionAuth<TClaims extends Record<string, unknown>> = {
  /** Selects browser cookie session operations. */
  browser(): BrowserSessionAuth<TClaims>;

  /** Selects explicit bearer-token session operations. */
  mobile(): MobileSessionAuth<TClaims>;

  /** Deletes expired refresh-session records. */
  deleteExpired(before?: Date): Promise<AuthResult<number>>;
};

/** Cookie-backed browser session operations. */
export type BrowserSessionAuth<TClaims extends Record<string, unknown>> = {
  /** Verifies the access token found in parsed browser cookies. */
  verify(input: BrowserSessionInput): Promise<AuthResult<SessionAccessPayload<TClaims>>>;

  /** Rotates the refresh token found in parsed cookies. */
  refresh(input: BrowserSessionInput): Promise<BrowserOperation<AuthState<TClaims>>>;

  /** Revokes the current refresh session and returns cookie deletions. */
  logout(input: BrowserSessionInput): Promise<BrowserOperation<void>>;
};

/** Explicit-token session operations intended for mobile clients. */
export type MobileSessionAuth<TClaims extends Record<string, unknown>> = {
  /** Verifies an explicit access token. */
  verify(input: { accessToken: string }): Promise<AuthResult<SessionAccessPayload<TClaims>>>;

  /** Rotates an explicit refresh token and returns its replacement session. */
  refresh(input: { refreshToken: string }): Promise<AuthResult<MobileSession<TClaims>>>;

  /** Revokes the session represented by an explicit refresh token. */
  logout(input: { refreshToken: string }): Promise<AuthResult>;
};

/** Creates browser and mobile views over the shared session service. */
export function createSessionAuth<TClaims extends Record<string, unknown>>(
  context: AuthContext<TClaims>,
): SessionAuth<TClaims> {
  return {
    browser: () => createBrowserSessionAuth(context),
    mobile: () => createMobileSessionAuth(context.sessions),
    deleteExpired: (before) => context.sessions.deleteExpiredSessions(before),
  };
}

/** Creates cookie-backed browser session operations. */
function createBrowserSessionAuth<TClaims extends Record<string, unknown>>(
  context: AuthContext<TClaims>,
): BrowserSessionAuth<TClaims> {
  return {
    verify: (input) => verifyBrowserSession(input, context),
    refresh: (input) => refreshBrowserSession(input, context),
    logout: (input) => logoutBrowserSession(input, context),
  };
}

/** Creates explicit-token mobile session operations. */
function createMobileSessionAuth<TClaims extends Record<string, unknown>>(
  sessions: SessionAuthService<TClaims>,
): MobileSessionAuth<TClaims> {
  return {
    verify: ({ accessToken }) => sessions.verifyAccessToken(accessToken),
    refresh: ({ refreshToken }) => sessions.refreshTokenPair(refreshToken),
    logout: ({ refreshToken }) => sessions.revokeSession(refreshToken),
  };
}

/** Verifies the configured access-token cookie. */
async function verifyBrowserSession<TClaims extends Record<string, unknown>>(
  input: BrowserSessionInput,
  context: AuthContext<TClaims>,
) {
  const token = readBrowserCookie(input.cookies, context.cookies.accessToken);

  return token
    ? context.sessions.verifyAccessToken(token)
    : authError("ACCESS_TOKEN_REQUIRED", "액세스 토큰이 필요합니다.");
}

/** Rotates the configured refresh-token cookie and returns new cookie effects. */
async function refreshBrowserSession<TClaims extends Record<string, unknown>>(
  input: BrowserSessionInput,
  context: AuthContext<TClaims>,
) {
  const token = readBrowserCookie(input.cookies, context.cookies.refreshToken);

  if (!token) {
    return { result: authError("REFRESH_TOKEN_REQUIRED", "리프레시 토큰이 필요합니다."), cookies: [] };
  }

  const refreshed = await context.sessions.refreshTokenPair(token);

  if (refreshed.isOk) {
    return browserSessionResult(refreshed.value, context.cookies);
  }

  const cookies = invalidBrowserRefreshCodes.has(refreshed.error.code)
    ? sessionCookieDeletions(context.cookies)
    : [];

  return { result: refreshed, cookies };
}

/** Revokes the current session and clears browser cookies on every outcome. */
async function logoutBrowserSession<TClaims extends Record<string, unknown>>(
  input: BrowserSessionInput,
  context: AuthContext<TClaims>,
): Promise<BrowserOperation<void>> {
  const token = readBrowserCookie(input.cookies, context.cookies.refreshToken);
  const result = token ? await context.sessions.revokeSession(token) : ok();

  return { result, cookies: sessionCookieDeletions(context.cookies) };
}

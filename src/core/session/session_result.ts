import { ok } from "gw-result";

import type { AuthState } from "../jwt_payload";
import { JWTManager } from "../jwt_manager";
import type { SessionTokenPair } from "./session_auth_service";
import {
  deleteBrowserCookie,
  setBrowserCookie,
  type BrowserCookies,
} from "../api/browser_cookie";
import type { BrowserOperation } from "../api/browser_operation";

/** Converts a new token pair into browser-safe state and HttpOnly cookie effects. */
export function browserSessionResult<TClaims extends Record<string, unknown>>(
  tokens: SessionTokenPair<TClaims>,
  cookies: BrowserCookies,
): BrowserOperation<AuthState<TClaims>> {
  const accessExpiration = JWTManager.getExpirationTime(tokens.accessToken);

  if (accessExpiration.isErr) {
    return { result: accessExpiration, cookies: [] };
  }

  const refreshExpiration = JWTManager.getExpirationTime(tokens.refreshToken);

  if (refreshExpiration.isErr) {
    return { result: refreshExpiration, cookies: [] };
  }

  return {
    result: ok(tokens.auth),
    cookies: [
      setBrowserCookie(cookies.accessToken, tokens.accessToken, accessExpiration.value),
      setBrowserCookie(cookies.refreshToken, tokens.refreshToken, refreshExpiration.value),
    ],
  };
}

/** Creates the two deletion effects required for browser logout. */
export function sessionCookieDeletions(cookies: BrowserCookies) {
  return [
    deleteBrowserCookie(cookies.accessToken),
    deleteBrowserCookie(cookies.refreshToken),
  ];
}

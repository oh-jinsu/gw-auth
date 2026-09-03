import {
  authStateFromAccessPayload,
  type AuthResult,
  type AuthState,
  type BrowserSessionAuth,
} from "gw-auth/core";
import { ok } from "gw-result";

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

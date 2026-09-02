import type {
  AuthResult,
  AuthState,
  BrowserSessionAuth,
} from "gw-auth/core";
import { ok } from "gw-result";

import { publicAuthState } from "./auth_state";
import { nextServerCookieStore, serverCookieValues } from "./server_cookie";

/** Verifies the access cookie and returns browser-safe state without JWT metadata. */
export async function getAuth<TClaims extends Record<string, unknown>>(
  session: BrowserSessionAuth<TClaims>,
): Promise<AuthResult<AuthState<TClaims>>> {
  const store = await nextServerCookieStore();
  const verified = await session.verify({ cookies: serverCookieValues(store) });

  return verified.isErr ? verified : ok(publicAuthState(verified.value));
}

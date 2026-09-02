import type {
  AuthResult,
  BrowserSessionAuth,
  SessionAccessPayload,
} from "gw-auth/core";
import { nextServerCookieStore, serverCookieValues } from "./server_cookie";

/** Verifies the current Next.js request's access cookie through the core session API. */
export async function getAuth<TClaims extends Record<string, unknown>>(
  session: BrowserSessionAuth<TClaims>,
): Promise<AuthResult<SessionAccessPayload<TClaims>>> {
  const store = await nextServerCookieStore();

  return session.verify({ cookies: serverCookieValues(store) });
}

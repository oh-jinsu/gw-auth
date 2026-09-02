import type {
  BrowserCookieMutation,
  BrowserCookieValues,
  BrowserOperation,
} from "gw-auth/core";
import { deleteCookieOptions, setCookieOptions } from "./cookie";
import { nextAuthResponse, type NextAuthResponse } from "./result";
import {
  nextServerCookieStore,
  serverCookieValues,
  type NextServerCookieStore,
} from "./server_cookie";

/** Core browser operation created from cookies visible to a Server Action. */
export type NextServerActionOperation<TValue> = (
  cookies: BrowserCookieValues,
) => BrowserOperation<TValue> | Promise<BrowserOperation<TValue>>;

/** Runs a core browser operation and applies its cookies inside a Server Action. */
export async function serverAction<TValue>(
  operation: NextServerActionOperation<TValue>,
): Promise<NextAuthResponse<TValue>> {
  const store = await nextServerCookieStore();
  const completed = await operation(serverCookieValues(store));

  applyActionCookies(store, completed.cookies);

  return nextAuthResponse(completed.result);
}

/** Applies cookie instructions through the mutable Server Action cookie store. */
function applyActionCookies(
  store: NextServerCookieStore,
  mutations: readonly BrowserCookieMutation[],
) {
  for (const mutation of mutations) {
    if (mutation.operation === "set") {
      store.set(mutation.name, mutation.value, setCookieOptions(mutation));
    } else {
      store.set(mutation.name, "", deleteCookieOptions(mutation));
    }
  }
}

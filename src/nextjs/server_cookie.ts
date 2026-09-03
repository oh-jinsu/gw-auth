import { cookies } from "next/headers.js";

import type { BrowserCookieMutation, BrowserCookieValues } from "gw-auth/core";
import { deleteCookieOptions, setCookieOptions } from "./cookie";

/** Mutable cookie store available in a Next.js Server Function. */
export type NextServerCookieStore = Awaited<ReturnType<typeof cookies>>;

/** Reads the cookie store within the current Next.js request context. */
export function nextServerCookieStore() {
  return cookies();
}

/** Converts a Next.js server cookie store to the core input contract. */
export function serverCookieValues(
  store: NextServerCookieStore,
): BrowserCookieValues {
  return Object.fromEntries(
    store.getAll().map(({ name, value }) => [name, value]),
  );
}

/** Applies cookie instructions in a mutable Server Action or Route Handler context. */
export function applyServerCookies(
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

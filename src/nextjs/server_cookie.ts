import { cookies } from "next/headers.js";

import type { BrowserCookieValues } from "gw-auth/core";

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

import type {
  BrowserCookieMutation,
  DeleteBrowserCookie,
  SetBrowserCookie,
} from "gw-auth/core";
import type { NextResponse } from "next/server.js";

/** Cookie options understood by Next.js response and server-action stores. */
export type NextCookieOptions = {
  domain?: string;
  path: string;
  httpOnly: true;
  secure: boolean;
  sameSite: "strict" | "lax" | "none";
  expires?: Date;
};

/** Extracts the shared security policy for a Next.js cookie write. */
export function nextCookieOptions(
  mutation: BrowserCookieMutation,
): NextCookieOptions {
  return {
    domain: mutation.domain,
    path: mutation.path,
    httpOnly: mutation.httpOnly,
    secure: mutation.secure,
    sameSite: mutation.sameSite,
  };
}

/** Adds an optional absolute expiration to a Next.js cookie write. */
export function setCookieOptions(mutation: SetBrowserCookie): NextCookieOptions {
  const options = nextCookieOptions(mutation);

  return mutation.expiresAt
    ? { ...options, expires: new Date(mutation.expiresAt) }
    : options;
}

/** Expires a cookie while retaining its original path and domain scope. */
export function deleteCookieOptions(
  mutation: DeleteBrowserCookie,
): NextCookieOptions {
  return { ...nextCookieOptions(mutation), expires: new Date(0) };
}

/** Applies set and scoped-expiration instructions to one Next.js response. */
export function applyResponseCookies(
  response: NextResponse,
  mutations: readonly BrowserCookieMutation[],
) {
  for (const mutation of mutations) {
    if (mutation.operation === "set") {
      response.cookies.set(mutation.name, mutation.value, setCookieOptions(mutation));
    } else {
      response.cookies.set(mutation.name, "", deleteCookieOptions(mutation));
    }
  }
}

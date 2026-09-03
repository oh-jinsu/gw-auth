import { err, ok } from "gw-result";

import { AuthError } from "../../../../dist/core/index.mjs";

const authState = { userId: "user-1", sessionId: "session-1", role: "admin" };
const mobileAuthState = { userId: "mobile-user", sessionId: "mobile-session", role: "member" };

export const session = {
  verify: async ({ cookies }) => {
    return cookies.service_access === "valid-access"
      ? ok({ ...authState, tokenUse: "access", exp: 2_000_000_000 })
      : err(new AuthError("INVALID_ACCESS_TOKEN", "invalid"));
  },
  refresh: async ({ cookies }) => {
    return cookies.service_refresh === "valid-refresh"
      ? refreshedSession()
      : invalidSession();
  },
  logout: async () => ({ result: ok(), cookies: [] }),
};

/** Shared browser and mobile session facade used by the resolver fixture. */
export const sessionAuth = {
  browser: () => session,
  mobile: () => ({
    verify: async ({ accessToken }) => accessToken === "valid-bearer"
      ? ok({ ...mobileAuthState, tokenUse: "access", exp: 2_000_000_000 })
      : err(new AuthError("INVALID_ACCESS_TOKEN", "invalid")),
  }),
  deleteExpired: async () => ok(0),
};

/** Returns replacement session cookies for a successful refresh. */
function refreshedSession() {
  return {
    result: ok(authState),
    cookies: [
      setCookie("service_access", "replacement-access"),
      setCookie("service_refresh", "replacement-refresh"),
    ],
  };
}

/** Returns terminal cookie cleanup for an invalid refresh token. */
function invalidSession() {
  return {
    result: err(new AuthError("INVALID_REFRESH_TOKEN", "invalid")),
    cookies: [deleteCookie("service_access"), deleteCookie("service_refresh")],
  };
}

/** Creates one secure replacement-cookie mutation. */
function setCookie(name, value) {
  return {
    operation: "set",
    name,
    value,
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  };
}

/** Creates one secure cookie-deletion mutation. */
function deleteCookie(name) {
  return {
    operation: "delete",
    name,
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  };
}

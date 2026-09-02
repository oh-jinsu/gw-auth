import assert from "node:assert/strict";
import test from "node:test";

import { ok } from "gw-result";
import { NextRequest } from "next/server.js";

import { createAuthRoute } from "../dist/nextjs/server/index.mjs";

test("serves the fixed session, guest, recovery, and signup routes", async () => {
  const captured = {};
  const handlers = createAuthRoute({
    siteOrigin: "https://example.test",
    session: sessionFeature(captured),
    password: passwordFeature(captured),
    guest: guestFeature(captured),
    recovery: recoveryFeature(captured),
    social: { signup: signupFeature(captured) },
  });

  await get(handlers, "session", { cookie: "access=token" });
  await post(handlers, "refresh", undefined, { cookie: "refresh=token" });
  await post(handlers, "logout", undefined, { cookie: "refresh=token" });
  await post(handlers, "signup", passwordSignupBody());
  await post(handlers, "guest", undefined, { cookie: "guest=credential" });
  await post(handlers, "password-reset/request", { credentialId: "member" });
  await post(handlers, "password-reset/complete", resetBody());
  await get(handlers, "social-signup", { cookie: "signup=token" });
  await post(handlers, "social-signup", { registration: { name: "Browser" } });
  const mobileRefresh = await post(handlers, "mobile/refresh", { refreshToken: "refresh" });
  await post(handlers, "mobile/logout", { refreshToken: "refresh" });
  await post(handlers, "mobile/password/signup", passwordSignupBody());
  const mobileGuest = await post(handlers, "mobile/guest", {});
  await post(handlers, "mobile/social-signup", {
    signupToken: "signup-token",
    registration: { name: "Mobile" },
  });

  assert.deepEqual(captured.browserCookies, { access: "token" });
  assert.deepEqual(captured.passwordRegistrations, [{ name: "Member" }, { name: "Member" }]);
  assert.equal(captured.credentialId, "member");
  assert.deepEqual(captured.reset, resetBody());
  assert.deepEqual(captured.socialRegistrations, [{ name: "Browser" }, { name: "Mobile" }]);
  assert.equal((await mobileRefresh.json()).value.accessToken, "mobile-access");
  assert.equal(
    (await mobileGuest.json()).value.guestCredentialExpiresAt,
    "2030-01-01T00:00:00.000Z",
  );
});

/** Invokes one fixed GET route. */
function get(handlers, path, headers) {
  return handlers.GET(request(path, "GET", undefined, headers), context(path));
}

/** Invokes one fixed POST route. */
function post(handlers, path, body, headers) {
  return handlers.POST(request(path, "POST", body, headers), context(path));
}

/** Creates a catch-all route context from one slash-delimited path. */
function context(path) {
  return { params: Promise.resolve({ auth: path.split("/") }) };
}

/** Creates one request for a fixed authentication path. */
function request(path, method, body, headers = {}) {
  const requestHeaders = new Headers(headers);

  if (body !== undefined) {
    requestHeaders.set("Content-Type", "application/json");
  }

  return new NextRequest(`https://example.test/api/auth/${path}`, {
    method,
    headers: requestHeaders,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** Returns the common password-signup request body. */
function passwordSignupBody() {
  return {
    id: "member",
    password: "secret",
    passwordConfirm: "secret",
    registration: { name: "Member" },
  };
}

/** Returns the common password-reset completion body. */
function resetBody() {
  return { token: "reset", password: "next", passwordConfirm: "next" };
}

/** Creates shared browser and mobile session projections. */
function sessionFeature(captured) {
  return {
    browser: () => ({
      verify: async ({ cookies }) => {
        captured.browserCookies = cookies;

        return ok({ userId: "user", sessionId: "browser" });
      },
      refresh: async () => browserOperation({ userId: "user", sessionId: "browser" }),
      logout: async () => browserOperation(),
    }),
    mobile: () => ({
      refresh: async () => ok(mobileSession()),
      logout: async () => ok(),
    }),
  };
}

/** Creates shared password projections that record signup registration. */
function passwordFeature(captured) {
  const signup = async ({ registration }) => {
    captured.passwordRegistrations ??= [];
    captured.passwordRegistrations.push(registration);

    return ok(mobileSession());
  };

  return {
    browser: () => ({
      login: async () => browserOperation(),
      signup: async (input) => browserOperation((await signup(input)).value.auth),
    }),
    mobile: () => ({ login: async () => ok(mobileSession()), signup }),
  };
}

/** Creates guest projections for cookie and explicit-credential delivery. */
function guestFeature() {
  return {
    browser: () => ({ authenticate: async () => browserOperation({ userId: "guest" }) }),
    mobile: () => ({
      authenticate: async () => ok({
        guestCredential: "guest-token",
        guestCredentialExpiresAt: new Date("2030-01-01T00:00:00.000Z"),
        tokens: mobileSession(),
      }),
    }),
  };
}

/** Creates password-recovery operations that record both request shapes. */
function recoveryFeature(captured) {
  return {
    request: async ({ credentialId }) => {
      captured.credentialId = credentialId;

      return ok();
    },
    reset: async (input) => {
      captured.reset = input;

      return ok();
    },
  };
}

/** Creates staged-signup projections that record browser and mobile registration. */
function signupFeature(captured) {
  const complete = (registration) => {
    captured.socialRegistrations ??= [];
    captured.socialRegistrations.push(registration);
  };

  return {
    browser: () => ({
      profile: async () => ok({ provider: "google" }),
      complete: async ({ registration }) => {
        complete(registration);

        return browserOperation({ userId: "social" });
      },
    }),
    mobile: () => ({
      complete: async ({ registration }) => {
        complete(registration);

        return ok(mobileSession());
      },
    }),
  };
}

/** Creates one successful browser operation. */
function browserOperation(value) {
  return { result: ok(value), cookies: [] };
}

/** Creates one explicit-token mobile session. */
function mobileSession() {
  return {
    accessToken: "mobile-access",
    refreshToken: "mobile-refresh",
    auth: { userId: "user", sessionId: "mobile" },
  };
}

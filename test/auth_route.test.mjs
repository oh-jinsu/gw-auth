import assert from "node:assert/strict";
import test from "node:test";

import { ok } from "gw-result";
import { NextRequest } from "next/server.js";

import { createAuthRoute } from "../dist/nextjs/server/index.mjs";

test("projects one password feature into fixed browser and mobile routes", async () => {
  const captured = {};
  const password = passwordFeature(captured);
  const handlers = createAuthRoute({
    siteOrigin: "https://example.test",
    session: sessionFeature(),
    password,
  });
  const browserResponse = await handlers.POST(
    jsonRequest("login", { id: "member", password: "secret" }),
    routeContext("login"),
  );
  const mobileResponse = await handlers.POST(
    jsonRequest("mobile/password/login", { id: "member", password: "secret" }),
    routeContext("mobile", "password", "login"),
  );

  assert.equal(captured.browserProjections, 1);
  assert.equal(captured.mobileProjections, 1);
  assert.deepEqual(captured.browserLogin, { id: "member", password: "secret" });
  assert.deepEqual(captured.mobileLogin, { id: "member", password: "secret" });
  assert.match(browserResponse.headers.get("Set-Cookie"), /access=browser-token/);
  assert.equal((await mobileResponse.json()).value.accessToken, "mobile-access");
});

test("returns stable no-store errors for malformed, missing, and wrong-method routes", async () => {
  const handlers = createAuthRoute({
    siteOrigin: "https://example.test",
    session: sessionFeature(),
    password: passwordFeature({}),
  });
  const malformed = await handlers.POST(
    jsonRequest("login", { id: "member" }),
    routeContext("login"),
  );
  const wrongMethod = await handlers.GET(
    new NextRequest("https://example.test/api/auth/login"),
    routeContext("login"),
  );
  const missing = await handlers.GET(
    new NextRequest("https://example.test/api/auth/missing"),
    routeContext("missing"),
  );

  assert.equal(malformed.status, 400);
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongMethod.headers.get("Allow"), "POST");
  assert.equal(missing.status, 404);
  assert.equal(missing.headers.get("Cache-Control"), "no-store");
});

test("accepts only exact trusted callback origins", () => {
  assert.doesNotThrow(() => createAuthRoute({
    siteOrigin: "http://localhost:3000",
    session: sessionFeature(),
  }));
  assert.throws(() => createAuthRoute({
    siteOrigin: "https://example.test/path",
    session: sessionFeature(),
  }), /HTTPS origin or localhost origin/);
});

test("derives OAuth callbacks and serves browser and mobile provider routes", async () => {
  const captured = {};
  const handlers = createAuthRoute({
    siteOrigin: "https://example.test",
    session: sessionFeature(),
    social: socialFeatures(captured),
  });
  const started = await handlers.GET(
    new NextRequest("https://example.test/api/auth/google?redirectPath=%2Fdashboard"),
    routeContext("google"),
  );
  const completed = await handlers.GET(
    new NextRequest("https://example.test/api/auth/google/callback?code=code&state=state", {
      headers: { cookie: "oauth_state=state" },
    }),
    routeContext("google", "callback"),
  );
  const mobile = await handlers.POST(
    jsonRequest("mobile/google", { idToken: "provider-token" }),
    routeContext("mobile", "google"),
  );
  const mobileBody = await mobile.json();

  assert.equal(captured.redirectUri, "https://example.test/api/auth/google/callback");
  assert.equal(captured.redirectPath, "/dashboard");
  assert.equal(started.status, 302);
  assert.equal(started.headers.get("location"), "https://accounts.example/authorize");
  assert.equal(completed.status, 303);
  assert.equal(completed.headers.get("location"), "/dashboard");
  assert.equal(captured.idToken, "provider-token");
  assert.equal(mobileBody.value.signupExpiresAt, "2030-01-01T00:00:00.000Z");
});

/** Creates the dynamic context used by `[...auth]`. */
function routeContext(...auth) {
  return { params: Promise.resolve({ auth }) };
}

/** Creates one JSON request under the fixed authentication route. */
function jsonRequest(path, body) {
  return new NextRequest(`https://example.test/api/auth/${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** Creates a shared session feature with browser and mobile projections. */
function sessionFeature() {
  return {
    browser: () => ({
      verify: async () => ok({ userId: "user", sessionId: "session", tokenUse: "access" }),
      refresh: async () => browserOperation({ userId: "user", sessionId: "session" }),
      logout: async () => browserOperation(),
    }),
    mobile: () => ({
      verify: async () => ok({ userId: "user", sessionId: "session", tokenUse: "access" }),
      refresh: async () => ok(mobileSession()),
      logout: async () => ok(),
    }),
  };
}

/** Creates one password feature and records both transport projections. */
function passwordFeature(captured) {
  return {
    browser: () => {
      captured.browserProjections = (captured.browserProjections ?? 0) + 1;

      return {
        login: async (input) => {
          captured.browserLogin = input;

          return browserOperation(
            { userId: "user", sessionId: "browser" },
            [setCookie("access", "browser-token")],
          );
        },
        signup: async () => browserOperation({ userId: "user", sessionId: "browser" }),
      };
    },
    mobile: () => {
      captured.mobileProjections = (captured.mobileProjections ?? 0) + 1;

      return {
        login: async (input) => {
          captured.mobileLogin = input;

          return ok(mobileSession());
        },
        signup: async () => ok(mobileSession()),
      };
    },
  };
}

/** Creates social signup and Google features shared by both transports. */
function socialFeatures(captured) {
  return {
    signup: {
      browser: () => ({
        profile: async () => ok({ provider: "google" }),
        complete: async () => browserOperation({ userId: "user", sessionId: "browser" }),
      }),
      mobile: () => ({
        profile: async () => ok({ provider: "google" }),
        complete: async () => ok(mobileSession()),
      }),
    },
    google: googleFeature(captured),
  };
}

/** Creates one Google feature with browser OAuth and mobile identity login. */
function googleFeature(captured) {
  return {
    browser: ({ redirectUri }) => {
      captured.redirectUri = redirectUri;

      return browserGoogle(captured);
    },
    mobile: () => ({
      login: async ({ idToken }) => {
        captured.idToken = idToken;

        return ok({
          status: "signup_required",
          signupToken: "signup-token",
          signupExpiresAt: new Date("2030-01-01T00:00:00.000Z"),
          profile: { provider: "google" },
        });
      },
    }),
  };
}

/** Creates browser Google start and completion operations. */
function browserGoogle(captured) {
  return {
    start: async ({ redirectPath }) => {
      captured.redirectPath = redirectPath;

      return browserOperation(
        { authorizationUrl: "https://accounts.example/authorize" },
        [setCookie("oauth_state", "state")],
      );
    },
    complete: async () => browserOperation({
      status: "authenticated",
      auth: { userId: "user", sessionId: "browser" },
      redirectPath: "/dashboard",
    }),
  };
}

/** Creates one successful browser operation. */
function browserOperation(value, cookies = []) {
  return { result: ok(value), cookies };
}

/** Creates one explicit-token mobile session. */
function mobileSession() {
  return {
    accessToken: "mobile-access",
    refreshToken: "mobile-refresh",
    auth: { userId: "user", sessionId: "mobile" },
  };
}

/** Creates one secure browser cookie instruction. */
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

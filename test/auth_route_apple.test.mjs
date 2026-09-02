import assert from "node:assert/strict";
import test from "node:test";

import { ok } from "gw-result";
import { NextRequest } from "next/server.js";

import { createAuthRoute } from "../dist/nextjs/server/index.mjs";

test("serves distinct Apple website, Android Browser API, and iOS Native API routes", async () => {
  const captured = { browser: [] };
  const handlers = createAuthRoute({
    siteOrigin: "https://example.test",
    session: sessionFeature(),
    social: {
      signup: signupFeature(),
      apple: {
        feature: appleFeature(captured),
        web: { serviceId: "web-service" },
        android: { serviceId: "android-service", packageId: "com.example.app" },
        ios: { appId: "com.example.app" },
      },
    },
  });
  const web = await handlers.GET(
    request("apple", "GET"),
    context("apple"),
  );
  const started = await handlers.POST(
    request("mobile/apple/browser/start", "POST", {}),
    context("mobile/apple/browser/start"),
  );
  const callback = await handlers.POST(
    appleCallbackRequest(),
    context("mobile/apple/callback"),
  );
  const android = await handlers.POST(
    request("mobile/apple/browser", "POST", {
      authorizationCode: "android-code",
      state: "android-state",
    }),
    context("mobile/apple/browser"),
  );
  const ios = await handlers.POST(
    request("mobile/apple/native", "POST", { authorizationCode: "ios-code" }),
    context("mobile/apple/native"),
  );

  assert.equal(web.headers.get("location"), "https://apple.example/authorize");
  assert.deepEqual(captured.browser, [
    {
      serviceId: "android-service",
      redirectUri: "https://example.test/api/auth/mobile/apple/callback",
    },
    {
      serviceId: "web-service",
      redirectUri: "https://example.test/api/auth/apple/callback",
    },
  ]);
  assert.equal(captured.androidPackageId, "com.example.app");
  assert.equal((await started.json()).value.nonce, "server-nonce");
  assert.equal(captured.android.authorizationCode, "android-code");
  assert.equal(captured.android.state, "android-state");
  assert.equal((await android.json()).value.signupExpiresAt, "2030-01-01T00:00:00.000Z");
  assert.equal(captured.appId, "com.example.app");
  assert.equal(captured.ios.authorizationCode, "ios-code");
  assert.equal((await ios.json()).value.status, "authenticated");
  assert.equal(callback.status, 302);
  assert.equal(callback.headers.get("Cache-Control"), "no-store");
  assert.match(callback.headers.get("location"), /^intent:\/\/callback\?code=apple-code/);
  assert.match(callback.headers.get("location"), /id_token=apple-id-token/);
  assert.match(callback.headers.get("location"), /state=apple-state/);
  assert.match(callback.headers.get("location"), /user=%7B%22name%22/);
  assert.match(callback.headers.get("location"), /package=com\.example\.app/);
  assert.deepEqual(captured.handoff, {
    code: "apple-code",
    id_token: "apple-id-token",
    state: "apple-state",
    user: JSON.stringify({ name: { firstName: "Member" } }),
  });
});

/** Creates one Apple feature fake covering all three public projections. */
function appleFeature(captured) {
  return {
    revoke: async () => ok(),
    browser: (options) => {
      captured.browser.push(options);

      return {
        web: () => ({
          start: async () => browserOperation({
            authorizationUrl: "https://apple.example/authorize",
          }),
          complete: async () => browserOperation({
            status: "authenticated",
            auth: { userId: "user", sessionId: "web" },
            redirectPath: "/",
          }),
        }),
        android: ({ packageId }) => ({
          start: async () => ok({
            serviceId: options.serviceId,
            redirectUri: options.redirectUri,
            state: "server-state",
            nonce: "server-nonce",
          }),
          complete: async (input) => {
            captured.android = input;

            return ok(signupRequired());
          },
          handoff: (values) => {
            captured.androidPackageId = packageId;
            captured.handoff = values;

            const parameters = new URLSearchParams(values);

            return ok({
              redirectUrl: `intent://callback?${parameters.toString()}`
                + `#Intent;package=${packageId};scheme=signinwithapple;end`,
            });
          },
        }),
      };
    },
    native: ({ appId }) => {
      captured.appId = appId;

      return {
        ios: () => ({
          login: async (input) => {
            captured.ios = input;

            return ok({ status: "authenticated", tokens: mobileSession() });
          },
        }),
      };
    },
  };
}

/** Creates the form-post callback emitted by Apple for Flutter Android. */
function appleCallbackRequest() {
  return new NextRequest("https://example.test/api/auth/mobile/apple/callback", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: "https://appleid.apple.com",
    },
    body: new URLSearchParams({
      code: "apple-code",
      id_token: "apple-id-token",
      state: "apple-state",
      user: JSON.stringify({ name: { firstName: "Member" } }),
    }),
  });
}

/** Creates one fixed route request with an optional JSON body. */
function request(path, method, body) {
  return new NextRequest(`https://example.test/api/auth/${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
}

/** Creates a catch-all context from one route path. */
function context(path) {
  return { params: Promise.resolve({ auth: path.split("/") }) };
}

/** Creates inert browser and mobile session projections. */
function sessionFeature() {
  return {
    browser: () => ({
      verify: async () => ok(),
      refresh: async () => browserOperation(),
      logout: async () => browserOperation(),
    }),
    mobile: () => ({
      refresh: async () => ok(mobileSession()),
      logout: async () => ok(),
    }),
  };
}

/** Creates inert staged-signup projections required by social routing. */
function signupFeature() {
  return {
    browser: () => ({
      profile: async () => ok({ provider: "apple" }),
      complete: async () => browserOperation(),
    }),
    mobile: () => ({ complete: async () => ok(mobileSession()) }),
  };
}

/** Creates one successful browser operation. */
function browserOperation(value) {
  return { result: ok(value), cookies: [] };
}

/** Creates one explicit-token mobile session. */
function mobileSession() {
  return {
    accessToken: "access",
    refreshToken: "refresh",
    auth: { userId: "user", sessionId: "mobile" },
  };
}

/** Creates one staged signup result with a serializable target expiration. */
function signupRequired() {
  return {
    status: "signup_required",
    signupToken: "signup",
    signupExpiresAt: new Date("2030-01-01T00:00:00.000Z"),
    profile: { provider: "apple" },
  };
}

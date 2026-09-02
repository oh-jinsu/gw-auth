import assert from "node:assert/strict";
import test from "node:test";

import { err, ok } from "gw-result";
import { NextRequest, NextResponse } from "next/server.js";

import { AuthError } from "../dist/core/index.mjs";
import { authRequest, startOAuth } from "../dist/nextjs/client/index.mjs";
import {
  nextRequestCookies,
  routeHandler,
  withAuth,
} from "../dist/nextjs/server/index.mjs";

test("applies route cookies and prevents caching", async () => {
  const handler = routeHandler(async () => ({
    result: ok({ userId: "user-1" }),
    cookies: [setCookie("service_access", "token")],
  }));
  const request = new NextRequest("https://example.test/auth/login");
  const response = await handler(request);

  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.match(response.headers.get("Set-Cookie"), /service_access=token/);
  assert.deepEqual(await response.json(), {
    ok: true,
    value: { userId: "user-1" },
  });
});

test("maps invalid password input to 400 and applies deletion cookies", async () => {
  const handler = routeHandler(async () => ({
    result: err(new AuthError("INVALID_PASSWORD", "로그인 실패", new Error("internal"))),
    cookies: [deleteCookie("service_refresh")],
  }));
  const request = new NextRequest("https://example.test/auth/login");
  const response = await handler(request);

  assert.equal(response.status, 400);
  assert.match(response.headers.get("Set-Cookie"), /service_refresh=;/);
  assert.deepEqual(await response.json(), {
    ok: false,
    error: {
      kind: "GW_AUTH_ERROR",
      code: "INVALID_PASSWORD",
      message: "로그인 실패",
    },
  });
});

test("maps credential and refresh failures from AuthResult operations to 401", async () => {
  const codes = [
    "APPLE_AUTH_FAILED",
    "GOOGLE_AUTH_FAILED",
    "INVALID_CREDENTIAL",
    "INVALID_REFRESH_TOKEN",
    "KAKAO_AUTH_FAILED",
    "NAVER_AUTH_FAILED",
    "SESSION_USER_MISMATCH",
  ];

  for (const code of codes) {
    const handler = routeHandler(async () => err(new AuthError(code, "invalid")));
    const request = new NextRequest("https://example.test/auth/mobile");
    const response = await handler(request);

    assert.equal(response.status, 401);
    assert.equal(response.headers.get("Cache-Control"), "no-store");
  }
});

test("maps provider outages and malformed upstream responses to 502", async () => {
  for (const code of ["PROVIDER_UNAVAILABLE", "INVALID_PROVIDER_RESPONSE"]) {
    const handler = routeHandler(async () => err(new AuthError(code, "upstream failure")));
    const request = new NextRequest("https://example.test/auth/provider");
    const response = await handler(request);

    assert.equal(response.status, 502);
  }
});

test("maps core token-processing failures to 500", async () => {
  for (const code of ["TOKEN_SIGNING_FAILED", "INVALID_TOKEN_EXPIRATION"]) {
    const handler = routeHandler(async () => err(new AuthError(code, "internal token failure")));
    const request = new NextRequest("https://example.test/auth/session");
    const response = await handler(request);

    assert.equal(response.status, 500);
  }
});

test("serializes successful AuthResult values without browser cookie effects", async () => {
  const handler = routeHandler(async () => ok({
    expiresAt: new Date("2030-01-01T00:00:00.000Z"),
  }));
  const request = new NextRequest("https://example.test/auth/mobile");
  const response = await handler(request);

  assert.deepEqual(await response.json(), {
    ok: true,
    value: { expiresAt: "2030-01-01T00:00:00.000Z" },
  });
  assert.equal(response.headers.has("Set-Cookie"), false);
});

test("converts NextRequest cookies to core values", () => {
  const request = new NextRequest("https://example.test/auth", {
    headers: { cookie: "access=one; refresh=two" },
  });

  assert.deepEqual(nextRequestCookies(request), {
    access: "one",
    refresh: "two",
  });
});

test("client requests preserve the Result contract", async () => {
  const originalFetch = globalThis.fetch;
  let captured;

  globalThis.fetch = async (_input, init) => {
    captured = init;

    return Response.json({ ok: true, value: { userId: "user-1" } });
  };

  const result = await authRequest("/auth/login", { method: "POST" });

  globalThis.fetch = originalFetch;

  assert.equal(result.isOk, true);
  assert.deepEqual(result.value, { userId: "user-1" });
  assert.equal(captured.cache, "no-store");
  assert.equal(captured.credentials, "same-origin");
});

test("client requests preserve auth errors from non-OK HTTP responses", async () => {
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async () => Response.json({
    ok: false,
    error: {
      kind: "GW_AUTH_ERROR",
      code: "INVALID_REFRESH_TOKEN",
      message: "invalid",
    },
  }, { status: 401 });

  try {
    const result = await authRequest("/auth/logout", { method: "POST" });

    assert.equal(result.error.code, "INVALID_REFRESH_TOKEN");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("client OAuth navigation uses the application-owned route", () => {
  const originalWindow = globalThis.window;
  let assigned;

  globalThis.window = { location: { assign: (href) => { assigned = href; } } };

  startOAuth("/auth/google?redirectPath=%2Fsettings");

  globalThis.window = originalWindow;

  assert.equal(assigned, "/auth/google?redirectPath=%2Fsettings");
});

test("proxy passes verified access claims to application policy", async () => {
  const session = proxySession({ verify: ok({ userId: "user-1", sessionId: "session-1" }) });
  const proxy = withAuth(session, async (_request, _event, auth) => NextResponse.json(auth));
  const response = await proxy(new NextRequest("https://example.test/admin"), {});

  assert.deepEqual(await response.json(), {
    userId: "user-1",
    sessionId: "session-1",
  });
});

test("proxy refreshes safe navigation with a same-URL cookie redirect", async () => {
  const session = proxySession({
    verify: err(new AuthError("INVALID_ACCESS_TOKEN", "expired")),
    refresh: {
      result: ok({ userId: "user-1", sessionId: "session-1" }),
      cookies: [setCookie("service_access", "replacement")],
    },
  });
  const proxy = withAuth(session, async () => NextResponse.next());
  const response = await proxy(new NextRequest("https://example.test/admin"), {});

  assert.equal(response.status, 307);
  assert.equal(response.headers.get("location"), "https://example.test/admin");
  assert.match(response.headers.get("Set-Cookie"), /service_access=replacement/);
});

test("proxy never refreshes a mutation request", async () => {
  let refreshCount = 0;
  const session = proxySession({
    verify: err(new AuthError("INVALID_ACCESS_TOKEN", "expired")),
    onRefresh: () => { refreshCount += 1; },
  });
  const proxy = withAuth(session, async (_request, _event, auth) => {
    return NextResponse.json({ authenticated: auth !== undefined });
  });
  const request = new NextRequest("https://example.test/action", { method: "POST" });
  const response = await proxy(request, {});

  assert.equal(refreshCount, 0);
  assert.deepEqual(await response.json(), { authenticated: false });
});

test("proxy applies core cleanup effects after invalid refresh", async () => {
  let logoutCount = 0;
  const session = proxySession({
    verify: err(new AuthError("INVALID_ACCESS_TOKEN", "expired")),
    refresh: {
      result: err(new AuthError("INVALID_REFRESH_TOKEN", "invalid")),
      cookies: [
        deleteCookie("service_access"),
        deleteCookie("service_refresh"),
      ],
    },
    onLogout: () => { logoutCount += 1; },
  });
  const proxy = withAuth(session, async () => NextResponse.next());
  const response = await proxy(new NextRequest("https://example.test/admin"), {});

  assert.equal(response.status, 307);
  assert.match(response.headers.get("Set-Cookie"), /service_refresh=;/);
  assert.equal(logoutCount, 0);
});

/** Creates one secure set-cookie mutation for adapter tests. */
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

/** Creates one scoped cookie deletion for adapter tests. */
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

/** Creates a browser-session fake at the same boundary consumed by Proxy. */
function proxySession(overrides = {}) {
  return {
    verify: async () => overrides.verify ?? err(new AuthError("ACCESS_TOKEN_REQUIRED", "missing")),
    refresh: async () => {
      overrides.onRefresh?.();

      return overrides.refresh ?? {
        result: err(new AuthError("REFRESH_TOKEN_REQUIRED", "missing")),
        cookies: [],
      };
    },
    logout: async () => {
      overrides.onLogout?.();

      return { result: ok(), cookies: [deleteCookie("service_refresh")] };
    },
  };
}

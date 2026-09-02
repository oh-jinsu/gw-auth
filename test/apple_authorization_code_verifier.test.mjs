import assert from "node:assert/strict";
import test from "node:test";

import {
  exportJWK,
  exportPKCS8,
  generateKeyPair,
  jwtVerify,
  SignJWT,
} from "jose";

import { createAuth } from "../dist/core/index.mjs";

test("signs an Apple client secret before exchanging an authorization code", async () => {
  const keys = await generateKeyPair("ES256", { extractable: true });
  const authKey = await exportPKCS8(keys.privateKey);
  const originalFetch = globalThis.fetch;
  let clientSecret;
  let redirectUri;
  let signal;

  globalThis.fetch = async (_input, init) => {
    const body = new URLSearchParams(init.body);

    clientSecret = body.get("client_secret");
    redirectUri = body.get("redirect_uri");
    signal = init.signal;

    return new Response("invalid", { status: 400 });
  };

  try {
    const apple = auth()
      .social({ repository: {} })
      .apple(appleOptions(authKey))
      .native({ appId: "com.example.app" })
      .ios();
    const verified = await apple.login({ authorizationCode: "authorization-code" });

    assert.equal(verified.isErr, true);
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(typeof clientSecret, "string");
  assert.equal(redirectUri, null);
  assert.equal(signal instanceof AbortSignal, true);

  const verifiedSecret = await jwtVerify(clientSecret, keys.publicKey, {
    audience: "https://appleid.apple.com",
    issuer: "TEAM_ID",
    subject: "com.example.app",
  });

  assert.equal(verifiedSecret.protectedHeader.kid, "KEY_ID");
});

test("retains the Apple browser refresh token in a staged social identity", async () => {
  const clientKeys = await generateKeyPair("ES256", { extractable: true });
  const authKey = await exportPKCS8(clientKeys.privateKey);
  const providerKeys = await generateKeyPair("RS256", { extractable: true });
  const providerKey = await exportJWK(providerKeys.publicKey);
  const repository = new AppleBrowserRepository();
  const originalFetch = globalThis.fetch;
  const social = auth().social({ repository });
  const apple = social.apple(appleOptions(authKey)).browser({
    serviceId: "com.example.service",
    redirectUri: "https://example.test/auth/apple/callback",
  }).web();
  const started = await apple.start();
  const state = started.result.value.authorizationUrl.match(/state=([^&]+)/)?.[1];
  const nonce = repository.transaction.nonce;
  const idToken = await appleIdToken(
    providerKeys.privateKey,
    nonce,
    "com.example.service",
  );
  let tokenRequest;

  globalThis.fetch = async (input, init) => {
    if (input.toString().endsWith("/auth/keys")) {
      return Response.json({ keys: [{ ...providerKey, alg: "RS256", kid: "APPLE_KEY", use: "sig" }] });
    }

    tokenRequest = new URLSearchParams(init.body);

    return Response.json({ id_token: idToken, refresh_token: "provider-refresh-token" });
  };

  try {
    const completed = await apple.complete({
      code: "authorization-code",
      state,
      cookies: { "apple-tests_oauth_state": state },
    });

    assert.equal(completed.result.value.status, "signup_required");
    assert.equal(repository.signup.identity.providerRefreshToken, "provider-refresh-token");
    assert.equal(repository.signup.identity.providerClientId, "com.example.service");
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(tokenRequest.get("client_id"), "com.example.service");
  assert.equal(tokenRequest.get("redirect_uri"), "https://example.test/auth/apple/callback");
});

test("separates Apple provider outages from malformed successful responses", async () => {
  const keys = await generateKeyPair("ES256", { extractable: true });
  const authKey = await exportPKCS8(keys.privateKey);
  const apple = auth()
    .social({ repository: {} })
    .apple(appleOptions(authKey))
    .native({ appId: "com.example.app" })
    .ios();
  const originalFetch = globalThis.fetch;
  let response = () => new Response("unavailable", { status: 503 });

  globalThis.fetch = async () => response();

  try {
    const unavailable = await apple.login({ authorizationCode: "authorization-code" });

    response = () => new Response("not-json", {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

    const malformed = await apple.login({ authorizationCode: "authorization-code" });

    assert.equal(unavailable.error.code, "PROVIDER_UNAVAILABLE");
    assert.equal(malformed.error.code, "INVALID_PROVIDER_RESPONSE");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("revokes an Apple refresh token with its persisted issuing client ID", async () => {
  const keys = await generateKeyPair("ES256", { extractable: true });
  const authKey = await exportPKCS8(keys.privateKey);
  const apple = auth().social({ repository: {} }).apple(appleOptions(authKey));
  const originalFetch = globalThis.fetch;
  let tokenRequest;

  globalThis.fetch = async (_input, init) => {
    tokenRequest = new URLSearchParams(init.body);

    return new Response(null, { status: 200 });
  };

  try {
    const revoked = await apple.revoke({
      providerClientId: "com.example.app",
      providerRefreshToken: "provider-refresh-token",
    });

    assert.equal(revoked.isOk, true);
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(tokenRequest.get("client_id"), "com.example.app");
  assert.equal(tokenRequest.get("token"), "provider-refresh-token");
});

function appleOptions(authKey) {
  return {
    authKey,
    teamId: "TEAM_ID",
    keyId: "KEY_ID",
  };
}

/** Signs one Apple-compatible identity token for the browser exchange test. */
function appleIdToken(privateKey, nonce, audience) {
  return new SignJWT({ nonce })
    .setProtectedHeader({ alg: "RS256", kid: "APPLE_KEY" })
    .setIssuer("https://appleid.apple.com")
    .setAudience(audience)
    .setSubject("apple-user")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

/** In-memory Apple OAuth and staged-signup persistence used by the browser test. */
class AppleBrowserRepository {
  /** Stores the initiating OAuth transaction. */
  async createOAuthTransaction(transaction) {
    this.transaction = transaction;
  }

  /** Atomically consumes the only OAuth transaction. */
  async consumeOAuthTransaction() {
    const transaction = this.transaction;

    this.transaction = undefined;

    return transaction;
  }

  /** Deletes no expired records in this focused test. */
  async deleteExpiredOAuthTransactions() {
    return 0;
  }

  /** Returns no existing social account so signup is staged. */
  async findUserBySocialIdentity() {
    return undefined;
  }

  /** Captures the provider identity stored in the signup attempt. */
  async createSocialSignupAttempt(signup) {
    this.signup = signup;
  }
}

/** Creates a facade whose unused stores are replaced by inert test objects. */
function auth() {
  return createAuth({
    serviceName: "apple-tests",
    sessions: {},
    tokens: {
      access: {
        secret: "0123456789abcdef0123456789abcdef",
        expiresIn: "30m",
      },
      refresh: {
        secret: "fedcba9876543210fedcba9876543210",
        expiresIn: "30d",
      },
    },
  });
}

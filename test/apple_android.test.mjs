import assert from "node:assert/strict";
import test from "node:test";

import { exportJWK, exportPKCS8, generateKeyPair, SignJWT } from "jose";

import { createAuth } from "../dist/core/index.mjs";

test("binds Flutter Android Apple credentials to server-owned state and nonce", async () => {
  const clientKeys = await generateKeyPair("ES256", { extractable: true });
  const providerKeys = await generateKeyPair("RS256", { extractable: true });
  const authKey = await exportPKCS8(clientKeys.privateKey);
  const providerKey = await exportJWK(providerKeys.publicKey);
  const repository = new AppleAndroidRepository();
  const android = apple(repository, authKey);
  const started = await android.start();
  const originalFetch = globalThis.fetch;
  let tokenRequest;

  assert.equal(started.isOk, true);
  assert.equal(started.value.serviceId, "com.example.service");
  assert.equal(started.value.redirectUri, "https://example.test/api/auth/mobile/apple/callback");
  assert.notEqual(repository.transaction.stateHash, started.value.state);

  const handoff = android.handoff({
    code: "apple-code",
    id_token: "apple-id-token",
    state: started.value.state,
    ignored: "secret",
  });

  assert.equal(handoff.isOk, true);
  assert.match(handoff.value.redirectUrl, /^intent:\/\/callback\?code=apple-code/);
  assert.match(handoff.value.redirectUrl, /id_token=apple-id-token/);
  assert.match(handoff.value.redirectUrl, /state=/);
  assert.doesNotMatch(handoff.value.redirectUrl, /ignored/);
  assert.match(handoff.value.redirectUrl, /package=com\.example\.app/);

  let idToken = await appleIdToken(
    providerKeys.privateKey,
    started.value.nonce,
  );

  globalThis.fetch = async (input, init) => {
    if (input.toString().endsWith("/auth/keys")) {
      return Response.json({ keys: [{ ...providerKey, alg: "RS256", kid: "APPLE_KEY", use: "sig" }] });
    }

    tokenRequest = new URLSearchParams(init.body);

    return Response.json({ id_token: idToken, refresh_token: "provider-refresh-token" });
  };

  try {
    const wrong = await android.complete({
      authorizationCode: "authorization-code",
      state: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    const completed = await android.complete({
      authorizationCode: "authorization-code",
      state: started.value.state,
    });
    const replayed = await android.complete({
      authorizationCode: "authorization-code",
      state: started.value.state,
    });

    assert.equal(wrong.error.code, "INVALID_OAUTH_STATE");
    assert.equal(completed.value.status, "signup_required");
    assert.equal(replayed.error.code, "INVALID_OAUTH_STATE");

    const nonceAttempt = await android.start();

    idToken = await appleIdToken(providerKeys.privateKey, "wrong-nonce");

    const mismatchedNonce = await android.complete({
      authorizationCode: "authorization-code",
      state: nonceAttempt.value.state,
    });

    assert.equal(mismatchedNonce.error.code, "APPLE_AUTH_FAILED");
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(tokenRequest.get("client_id"), "com.example.service");
  assert.equal(
    tokenRequest.get("redirect_uri"),
    "https://example.test/api/auth/mobile/apple/callback",
  );
  assert.equal(repository.signup.identity.providerRefreshToken, "provider-refresh-token");
  assert.equal(repository.signup.identity.providerClientId, "com.example.service");
});

test("requires transaction storage before creating Android Apple operations", async () => {
  const clientKeys = await generateKeyPair("ES256", { extractable: true });
  const authKey = await exportPKCS8(clientKeys.privateKey);
  const feature = auth({}).social({ repository: {} }).apple({
    authKey,
    teamId: "TEAM_ID",
    keyId: "KEY_ID",
  }).browser({
    serviceId: "com.example.service",
    redirectUri: "https://example.test/api/auth/mobile/apple/callback",
  });

  assert.throws(
    () => feature.android({ packageId: "com.example.app" }),
    /requires OAuth transaction storage/,
  );
});

test("rejects unsafe packages and malformed callback handoffs in core", async () => {
  const clientKeys = await generateKeyPair("ES256", { extractable: true });
  const authKey = await exportPKCS8(clientKeys.privateKey);
  const repository = new AppleAndroidRepository();
  const browser = auth(repository).social({ repository, transactions: repository }).apple({
    authKey,
    teamId: "TEAM_ID",
    keyId: "KEY_ID",
  }).browser({
    serviceId: "com.example.service",
    redirectUri: "https://example.test/api/auth/mobile/apple/callback",
  });

  assert.throws(
    () => browser.android({ packageId: "com.example;scheme=bad" }),
    /packageId is invalid/,
  );

  const android = browser.android({ packageId: "com.example.app" });
  const malformed = android.handoff({ state: "state-without-outcome" });
  const oversized = android.handoff({
    code: "x".repeat(8193),
    state: "state-with-oversized-code",
  });

  assert.equal(malformed.error.code, "INVALID_OAUTH_RESPONSE");
  assert.equal(oversized.error.code, "INVALID_OAUTH_RESPONSE");
});

/** Creates one configured Android Browser API projection. */
function apple(repository, authKey) {
  return auth(repository).social({ repository }).apple({
    authKey,
    teamId: "TEAM_ID",
    keyId: "KEY_ID",
  }).browser({
    serviceId: "com.example.service",
    redirectUri: "https://example.test/api/auth/mobile/apple/callback",
  }).android({ packageId: "com.example.app" });
}

/** Creates an authentication facade with one optional combined test repository. */
function auth(repository) {
  return createAuth({
    serviceName: "apple-android-tests",
    sessions: repository,
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

/** Signs an Apple-compatible ID token bound to the server-issued nonce. */
function appleIdToken(privateKey, nonce) {
  return new SignJWT({ nonce })
    .setProtectedHeader({ alg: "RS256", kid: "APPLE_KEY" })
    .setIssuer("https://appleid.apple.com")
    .setAudience("com.example.service")
    .setSubject("apple-user")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

/** In-memory transaction and staged-signup persistence for Android Apple tests. */
class AppleAndroidRepository {
  /** Reports no linked identity so the verified login creates a signup attempt. */
  async findUserBySocialIdentity() {
    return undefined;
  }

  /** Stores one server-issued Android OAuth transaction. */
  async createOAuthTransaction(transaction) {
    this.transaction = transaction;
  }

  /** Atomically consumes only one matching unexpired transaction. */
  async consumeOAuthTransaction(stateHash, now) {
    if (this.transaction?.stateHash !== stateHash || this.transaction.expiresAt <= now) {
      return undefined;
    }

    const transaction = this.transaction;

    this.transaction = undefined;

    return transaction;
  }

  /** Deletes no transactions in this focused test. */
  async deleteExpiredOAuthTransactions() {
    return 0;
  }

  /** Captures the verified identity stored for staged signup. */
  async createSocialSignupAttempt(signup) {
    this.signup = signup;
  }
}

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

  globalThis.fetch = async (_input, init) => {
    clientSecret = new URLSearchParams(init.body).get("client_secret");

    return new Response("invalid", { status: 400 });
  };

  try {
    const apple = auth().social({ repository: {} }).apple(appleOptions(authKey)).mobile();
    const verified = await apple.login({ authorizationCode: "authorization-code" });

    assert.equal(verified.isErr, true);
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(typeof clientSecret, "string");

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
    redirectUri: "https://example.test/auth/apple/callback",
  });
  const started = await apple.start();
  const state = started.result.value.authorizationUrl.match(/state=([^&]+)/)?.[1];
  const nonce = repository.transaction.nonce;
  const idToken = await appleIdToken(providerKeys.privateKey, nonce);

  globalThis.fetch = async (input) => {
    if (input.toString().endsWith("/auth/keys")) {
      return Response.json({ keys: [{ ...providerKey, alg: "RS256", kid: "APPLE_KEY", use: "sig" }] });
    }

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
  } finally {
    globalThis.fetch = originalFetch;
  }
});

function appleOptions(authKey) {
  return {
    authKey,
    clientId: "com.example.app",
    teamId: "TEAM_ID",
    keyId: "KEY_ID",
  };
}

/** Signs one Apple-compatible identity token for the browser exchange test. */
function appleIdToken(privateKey, nonce) {
  return new SignJWT({ nonce })
    .setProtectedHeader({ alg: "RS256", kid: "APPLE_KEY" })
    .setIssuer("https://appleid.apple.com")
    .setAudience("com.example.app")
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

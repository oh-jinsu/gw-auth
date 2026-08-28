import assert from "node:assert/strict";
import test from "node:test";

import { exportPKCS8, generateKeyPair, jwtVerify } from "jose";

import { AppleAuthorizationCodeVerifier } from "../dist/server/index.mjs";

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
    const verifier = new AppleAuthorizationCodeVerifier(appleOptions(authKey));
    const verified = await verifier.verify("authorization-code");

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

function appleOptions(authKey) {
  return {
    authKey,
    clientId: "com.example.app",
    teamId: "TEAM_ID",
    keyId: "KEY_ID",
  };
}

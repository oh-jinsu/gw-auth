import { ok, resultFrom } from "gw-result";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

import { authError } from "../../auth_error";
import type { SocialIdentity } from "../social_identity";
import { providerVerificationError } from "../provider_response";

const appleIssuer = "https://appleid.apple.com";
const appleKeys = createRemoteJWKSet(
  new URL(`${appleIssuer}/auth/keys`),
  { timeoutDuration: 10_000 },
);

/** Verifies Apple ID tokens shared by browser and mobile code exchanges. */
export class AppleIdentityTokenVerifier {
  /** Creates a verifier for one Apple App ID or Services ID audience. */
  constructor(private readonly clientId: string) {}

  /** Verifies signature, issuer, audience, subject, and an optional expected nonce. */
  async verify(token: string, expectedNonce?: string) {
    const verified = await resultFrom(() => jwtVerify(token, appleKeys, {
      audience: this.clientId,
      issuer: appleIssuer,
    }));

    if (verified.isErr || typeof verified.value.payload.sub !== "string") {
      return verified.isErr
        ? providerVerificationError(
          verified.error,
          "apple",
          "APPLE_AUTH_FAILED",
          "Apple 인증에 실패했습니다.",
        )
        : authError("APPLE_AUTH_FAILED", "Apple 인증에 실패했습니다.");
    }

    if (expectedNonce && verified.value.payload.nonce !== expectedNonce) {
      return authError("APPLE_AUTH_FAILED", "Apple nonce가 일치하지 않습니다.");
    }

    return ok(appleIdentity(verified.value.payload));
  }
}

/** Converts verified Apple claims to the canonical social identity. */
function appleIdentity(payload: JWTPayload): SocialIdentity {
  return {
    provider: "apple",
    id: payload.sub!,
    ...(typeof payload.email === "string" ? { email: payload.email } : {}),
  };
}

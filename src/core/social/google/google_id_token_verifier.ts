import { ok, resultFrom } from "gw-result";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

import { authError } from "../../auth_error";
import type { SocialIdentityVerifier } from "../social_identity";

const googleKeys = createRemoteJWKSet(new URL("https://www.googleapis.com/oauth2/v3/certs"));
const googleIssuers = ["accounts.google.com", "https://accounts.google.com"];

/** Verifies Google ID-token signature, issuer, audience, and optional nonce. */
export class GoogleIdTokenVerifier implements SocialIdentityVerifier {
  /** Creates a verifier accepting only the configured Google client audiences. */
  constructor(private readonly clientIds: string[]) {}

  /** Verifies and normalizes one Google ID token. */
  async verify(idToken: string, expectedNonce?: string) {
    const verified = await resultFrom(() => jwtVerify(idToken, googleKeys, {
      audience: this.clientIds,
      issuer: googleIssuers,
    }));

    if (verified.isErr || typeof verified.value.payload.sub !== "string") {
      return authError(
        "GOOGLE_AUTH_FAILED",
        "Google 인증에 실패했습니다.",
        verified.isErr ? verified.error : undefined,
      );
    }

    if (expectedNonce && verified.value.payload.nonce !== expectedNonce) {
      return authError("GOOGLE_AUTH_FAILED", "Google nonce가 일치하지 않습니다.");
    }

    return ok(googleIdentity(verified.value.payload));
  }
}

/** Converts verified Google claims to the canonical social identity. */
function googleIdentity(payload: JWTPayload) {
  return {
    provider: "google" as const,
    id: payload.sub!,
    ...(payload.email_verified === true ? optionalString("email", payload.email) : {}),
    ...optionalString("name", payload.name),
    ...optionalString("picture", payload.picture),
  };
}

/** Includes a provider claim only when it is a non-empty string. */
function optionalString(key: string, value: unknown) {
  return typeof value === "string" && value ? { [key]: value } : {};
}

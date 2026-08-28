import { exception, ok, resultFrom } from "gw-result";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

import type { SocialIdentityVerifier } from "./social_identity";

const googleKeys = createRemoteJWKSet(new URL("https://www.googleapis.com/oauth2/v3/certs"));
const googleIssuers = ["accounts.google.com", "https://accounts.google.com"];

export class GoogleIdTokenVerifier implements SocialIdentityVerifier {
  readonly provider = "google" as const;

  constructor(private readonly clientIds: string[]) {}

  async verify(idToken: string) {
    const verified = await resultFrom(() => jwtVerify(idToken, googleKeys, {
      audience: this.clientIds,
      issuer: googleIssuers,
    }));

    if (verified.isErr || typeof verified.value.payload.sub !== "string") {
      return exception("GOOGLE_AUTH_FAILED", "구글 인증에 실패했습니다.");
    }

    return ok(googleIdentity(verified.value.payload));
  }
}

function googleIdentity(payload: JWTPayload) {
  return {
    provider: "google" as const,
    id: payload.sub!,
    ...optionalString("email", payload.email),
    ...optionalString("name", payload.name),
    ...optionalString("picture", payload.picture),
  };
}

function optionalString(key: string, value: unknown) {
  return typeof value === "string" ? { [key]: value } : {};
}

import { exception, fetchWithResult, ok, resultFrom } from "gw-result";
import { createRemoteJWKSet, importPKCS8, jwtVerify, SignJWT, type JWTPayload } from "jose";

import type { SocialIdentityVerifier } from "./social_identity";

const appleAudience = "https://appleid.apple.com";
const appleKeys = createRemoteJWKSet(new URL(`${appleAudience}/auth/keys`));

export type AppleAuthorizationCodeVerifierOptions = {
  authKey: string;
  clientId: string;
  teamId: string;
  keyId: string;
};

export class AppleAuthorizationCodeVerifier implements SocialIdentityVerifier {
  readonly provider = "apple" as const;

  constructor(private readonly options: AppleAuthorizationCodeVerifierOptions) {}

  async verify(code: string) {
    const tokenResponse = await this.tokenRequest("/auth/token", {
      code,
      grant_type: "authorization_code",
    });

    if (tokenResponse.isErr || !isAppleTokens(tokenResponse.value)) {
      return exception("APPLE_AUTH_FAILED", "Apple 인증에 실패했습니다.");
    }

    const identity = await this.verifyIdentityToken(tokenResponse.value.id_token);

    return identity.isErr
      ? identity
      : ok({ ...identity.value, providerRefreshToken: tokenResponse.value.refresh_token });
  }

  async revoke(refreshToken: string) {
    const response = await this.tokenRequest("/auth/revoke", {
      token: refreshToken,
      token_type_hint: "refresh_token",
    });

    return response.isErr
      ? response
      : response.value === null
        ? ok()
        : exception("APPLE_REVOKE_FAILED", "Apple 연결 해제에 실패했습니다.");
  }

  private async tokenRequest(path: string, values: Record<string, string>) {
    const secret = await resultFrom(() => this.clientSecret());

    if (secret.isErr) {
      return secret;
    }

    const response = await fetchWithResult(`${appleAudience}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: this.options.clientId,
        client_secret: secret.value,
        ...values,
      }),
    });

    if (response.isErr || !response.value.ok) {
      return exception("APPLE_AUTH_FAILED", "Apple 인증에 실패했습니다.");
    }

    if (response.value.status === 200 && path === "/auth/revoke") {
      return ok(null);
    }

    return resultFrom(() => response.value.json());
  }

  private async verifyIdentityToken(token: string) {
    const verified = await resultFrom(() => jwtVerify(token, appleKeys, {
      audience: this.options.clientId,
      issuer: appleAudience,
    }));

    if (verified.isErr || typeof verified.value.payload.sub !== "string") {
      return exception("APPLE_AUTH_FAILED", "Apple 인증에 실패했습니다.");
    }

    return ok(appleIdentity(verified.value.payload));
  }

  private async clientSecret() {
    const key = await importPKCS8(this.options.authKey, "ES256");

    return new SignJWT()
      .setProtectedHeader({ alg: "ES256", kid: this.options.keyId })
      .setIssuedAt()
      .setIssuer(this.options.teamId)
      .setExpirationTime("1h")
      .setAudience(appleAudience)
      .setSubject(this.options.clientId)
      .sign(key);
  }
}

type AppleTokens = { id_token: string; refresh_token: string };

function isAppleTokens(value: unknown): value is AppleTokens {
  return typeof value === "object" && value !== null
    && "id_token" in value && typeof value.id_token === "string"
    && "refresh_token" in value && typeof value.refresh_token === "string";
}

function appleIdentity(payload: JWTPayload) {
  return {
    provider: "apple" as const,
    id: payload.sub!,
    ...(typeof payload.email === "string" ? { email: payload.email } : {}),
  };
}

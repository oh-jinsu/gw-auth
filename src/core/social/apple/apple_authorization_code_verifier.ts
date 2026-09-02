import { ok, resultFrom } from "gw-result";
import { importPKCS8, SignJWT } from "jose";

import { authError } from "../../auth_error";
import { providerFetch } from "../provider_fetch";
import {
  invalidProviderResponse,
  providerJson,
  providerRequestError,
  providerString,
} from "../provider_response";
import { AppleIdentityTokenVerifier } from "./apple_identity_token_verifier";
import type { SocialIdentityVerifier } from "../social_identity";

const appleOrigin = "https://appleid.apple.com";

/** Sign in with Apple code-exchange configuration for one exact client. */
export type AppleAuthorizationCodeVerifierOptions = {
  authKey: string;
  clientId: string;
  teamId: string;
  keyId: string;
  redirectUri?: string;
};

/** Exchanges an Apple code, verifies identity, and retains its revocation token. */
export class AppleAuthorizationCodeVerifier implements SocialIdentityVerifier {
  private readonly identityTokens: AppleIdentityTokenVerifier;

  /** Creates the verifier for one App ID or Services ID and optional return URI. */
  constructor(private readonly options: AppleAuthorizationCodeVerifierOptions) {
    this.identityTokens = new AppleIdentityTokenVerifier(options.clientId);
  }

  /** Exchanges a one-time code and verifies the returned ID token and expected nonce. */
  async verify(code: string, expectedNonce?: string) {
    const response = await this.tokenRequest("/auth/token", {
      code,
      grant_type: "authorization_code",
      ...(this.options.redirectUri ? { redirect_uri: this.options.redirectUri } : {}),
    });

    if (response.isErr) {
      return response;
    }

    const idToken = providerString(response.value, "id_token");
    const refreshToken = providerString(response.value, "refresh_token");

    if (!idToken || !refreshToken) {
      return invalidProviderResponse("apple", { missing: "id_token or refresh_token" });
    }

    const identity = await this.identityTokens.verify(idToken, expectedNonce);

    return identity.isErr
      ? identity
      : ok({
        ...identity.value,
        providerClientId: this.options.clientId,
        providerRefreshToken: refreshToken,
      });
  }

  /** Revokes a stored Apple provider refresh token during account deletion. */
  async revoke(refreshToken: string) {
    const response = await this.tokenRequest("/auth/revoke", {
      token: refreshToken,
      token_type_hint: "refresh_token",
    }, true);

    return response.isErr ? response : ok();
  }

  /** Sends an authenticated Apple token or revocation request. */
  private async tokenRequest(
    path: string,
    values: Record<string, string>,
    expectsEmptyResponse = false,
  ) {
    const failureCode = expectsEmptyResponse ? "APPLE_REVOKE_FAILED" : "APPLE_AUTH_FAILED";
    const failureMessage = expectsEmptyResponse
      ? "Apple 연결 해제에 실패했습니다."
      : "Apple 인증에 실패했습니다.";
    const secret = await this.clientSecret();

    if (secret.isErr) {
      return secret;
    }

    const fetched = await providerFetch(`${appleOrigin}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: this.options.clientId,
        client_secret: secret.value,
        ...values,
      }),
    });

    if (fetched.isErr) {
      return providerRequestError(
        fetched.error,
        "apple",
        failureCode,
        failureMessage,
      );
    }

    if (expectsEmptyResponse) {
      return ok({});
    }

    return providerJson(
      fetched.value,
      "apple",
      failureCode,
      failureMessage,
    );
  }

  /** Signs Apple's short-lived ES256 client assertion for this exact client. */
  private async clientSecret() {
    const key = await resultFrom(() => importPKCS8(this.options.authKey, "ES256"));

    if (key.isErr) {
      return authError("APPLE_AUTH_FAILED", "Apple 인증 설정이 유효하지 않습니다.", key.error);
    }

    const signed = await resultFrom(() =>
      new SignJWT({})
        .setProtectedHeader({ alg: "ES256", kid: this.options.keyId })
        .setIssuedAt()
        .setIssuer(this.options.teamId)
        .setExpirationTime("1h")
        .setAudience(appleOrigin)
        .setSubject(this.options.clientId)
        .sign(key.value),
    );

    return signed.isErr
      ? authError("APPLE_AUTH_FAILED", "Apple 인증 설정이 유효하지 않습니다.", signed.error)
      : signed;
  }
}

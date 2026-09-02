import { fetchWithResult, ok, resultFrom } from "gw-result";
import { importPKCS8, SignJWT } from "jose";

import { authError } from "../../auth_error";
import { AppleIdentityTokenVerifier } from "./apple_identity_token_verifier";
import type {
  OAuthAuthorizationRequest,
  OAuthCodeVerification,
  OAuthProvider,
} from "../oauth/oauth_provider";
import { providerJson, providerString } from "../provider_response";

const appleOrigin = "https://appleid.apple.com";

/** Configuration for the Sign in with Apple web authorization-code flow. */
export type AppleAuthOptions = {
  authKey: string;
  clientId: string;
  teamId: string;
  keyId: string;
  redirectUri: string;
};

/** Apple browser OAuth adapter using one-time state, nonce, and verified ID tokens. */
export class AppleAuth implements OAuthProvider {
  /** Canonical provider identifier persisted with OAuth transactions. */
  readonly provider = "apple" as const;

  /** Apple's documented web flow is bound with state and nonce. */
  readonly usesPkce = false;

  /** Apple includes a supplied nonce in its signed identity token. */
  readonly usesNonce = true;

  private readonly identityTokens: AppleIdentityTokenVerifier;

  /** Creates the provider adapter from Apple Services ID configuration. */
  constructor(private readonly options: AppleAuthOptions) {
    this.identityTokens = new AppleIdentityTokenVerifier(options.clientId);
  }

  /** Builds an Apple form-post authorization URL. */
  authorizationUrl(request: OAuthAuthorizationRequest) {
    const url = new URL("/auth/authorize", appleOrigin);

    url.search = new URLSearchParams({
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      response_type: "code",
      response_mode: "form_post",
      scope: "name email",
      state: request.state,
      nonce: request.nonce ?? "",
    }).toString();

    return url;
  }

  /** Exchanges the Apple code and verifies signature, issuer, audience, and nonce. */
  async verifyAuthorizationCode(verification: OAuthCodeVerification) {
    if (!verification.nonce) {
      return authError("INVALID_OAUTH_STATE", "Apple OAuth 상태가 유효하지 않습니다.");
    }

    const secret = await this.clientSecret();

    if (secret.isErr) {
      return secret;
    }

    const fetched = await fetchWithResult(`${appleOrigin}/auth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: this.options.clientId,
        client_secret: secret.value,
        code: verification.code,
        redirect_uri: this.options.redirectUri,
        grant_type: "authorization_code",
      }),
    });

    if (fetched.isErr) {
      return authError("APPLE_AUTH_FAILED", "Apple 인증에 실패했습니다.", fetched.error);
    }

    const json = await providerJson(
      fetched.value,
      "APPLE_AUTH_FAILED",
      "Apple 인증에 실패했습니다.",
    );

    if (json.isErr) {
      return json;
    }

    const idToken = providerString(json.value, "id_token");
    const refreshToken = providerString(json.value, "refresh_token");

    if (!idToken || !refreshToken) {
      return authError("APPLE_AUTH_FAILED", "Apple 인증 토큰이 없습니다.");
    }

    const identity = await this.identityTokens.verify(idToken, verification.nonce);

    return identity.isErr
      ? identity
      : ok({ ...identity.value, providerRefreshToken: refreshToken });
  }

  /** Signs Apple's short-lived ES256 client assertion. */
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

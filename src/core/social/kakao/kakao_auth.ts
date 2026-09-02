import { authError } from "../../auth_error";
import { KakaoAccessTokenVerifier } from "./kakao_access_token_verifier";
import type {
  OAuthAuthorizationRequest,
  OAuthCodeVerification,
  OAuthProvider,
} from "../oauth/oauth_provider";
import { providerFetch } from "../provider_fetch";
import {
  invalidProviderResponse,
  providerJson,
  providerRequestError,
  providerString,
} from "../provider_response";

/** Configuration for Kakao's server-side authorization-code flow. */
export type KakaoAuthOptions = {
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
};

/** Kakao browser OAuth adapter using state and S256 PKCE. */
export class KakaoAuth implements OAuthProvider {
  /** Canonical provider identifier persisted with OAuth transactions. */
  readonly provider = "kakao" as const;

  /** Kakao publishes S256 PKCE support. */
  readonly usesPkce = true;

  /** This adapter resolves identity through userinfo instead of an ID-token nonce. */
  readonly usesNonce = false;

  private readonly accessTokens = new KakaoAccessTokenVerifier();

  /** Creates the provider adapter from a Kakao REST API client. */
  constructor(private readonly options: KakaoAuthOptions) {}

  /** Builds a Kakao authorization URL. */
  authorizationUrl(request: OAuthAuthorizationRequest) {
    const url = new URL("https://kauth.kakao.com/oauth/authorize");

    url.search = new URLSearchParams({
      response_type: "code",
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      state: request.state,
      code_challenge: request.codeChallenge ?? "",
      code_challenge_method: "S256",
    }).toString();

    return url;
  }

  /** Exchanges the bound code and resolves the Kakao identity using its access token. */
  async verifyAuthorizationCode(verification: OAuthCodeVerification) {
    if (!verification.codeVerifier) {
      return authError("INVALID_OAUTH_STATE", "Kakao OAuth 상태가 유효하지 않습니다.");
    }

    const values: Record<string, string> = {
      grant_type: "authorization_code",
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      code: verification.code,
      code_verifier: verification.codeVerifier,
    };

    if (this.options.clientSecret) {
      values.client_secret = this.options.clientSecret;
    }

    const fetched = await providerFetch("https://kauth.kakao.com/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(values),
    });

    if (fetched.isErr) {
      return providerRequestError(
        fetched.error,
        "kakao",
        "KAKAO_AUTH_FAILED",
        "Kakao 인증에 실패했습니다.",
      );
    }

    const json = await providerJson(
      fetched.value,
      "kakao",
      "KAKAO_AUTH_FAILED",
      "Kakao 인증에 실패했습니다.",
    );

    if (json.isErr) {
      return json;
    }

    const accessToken = providerString(json.value, "access_token");

    return accessToken
      ? this.accessTokens.verify(accessToken)
      : invalidProviderResponse("kakao", { missing: "access_token" });
  }
}

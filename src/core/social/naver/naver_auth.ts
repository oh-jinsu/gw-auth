import { fetchWithResult } from "gw-result";

import { authError } from "../../auth_error";
import { NaverAccessTokenVerifier } from "./naver_access_token_verifier";
import type {
  OAuthAuthorizationRequest,
  OAuthCodeVerification,
  OAuthProvider,
} from "../oauth/oauth_provider";
import { providerJson, providerString } from "../provider_response";

/** Configuration for Naver's server-side authorization-code flow. */
export type NaverAuthOptions = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
};

/** Naver browser OAuth adapter using one-time state and server-side code exchange. */
export class NaverAuth implements OAuthProvider {
  /** Canonical provider identifier persisted with OAuth transactions. */
  readonly provider = "naver" as const;

  /** Naver's documented flow is protected with state rather than PKCE. */
  readonly usesPkce = false;

  /** Naver identity is resolved through userinfo rather than an ID token. */
  readonly usesNonce = false;

  private readonly accessTokens = new NaverAccessTokenVerifier();

  /** Creates the provider adapter from Naver web-client configuration. */
  constructor(private readonly options: NaverAuthOptions) {}

  /** Builds a Naver authorization URL. */
  authorizationUrl(request: OAuthAuthorizationRequest) {
    const url = new URL("https://nid.naver.com/oauth2.0/authorize");

    url.search = new URLSearchParams({
      response_type: "code",
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      state: request.state,
    }).toString();

    return url;
  }

  /** Exchanges a state-bound Naver code and resolves the provider identity. */
  async verifyAuthorizationCode(verification: OAuthCodeVerification) {
    const fetched = await fetchWithResult("https://nid.naver.com/oauth2.0/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: this.options.clientId,
        client_secret: this.options.clientSecret,
        code: verification.code,
        state: verification.state,
      }),
    });

    if (fetched.isErr) {
      return authError("NAVER_AUTH_FAILED", "Naver 인증에 실패했습니다.", fetched.error);
    }

    const json = await providerJson(
      fetched.value,
      "NAVER_AUTH_FAILED",
      "Naver 인증에 실패했습니다.",
    );

    if (json.isErr) {
      return json;
    }

    const accessToken = providerString(json.value, "access_token");

    return accessToken
      ? this.accessTokens.verify(accessToken)
      : authError("NAVER_AUTH_FAILED", "Naver 액세스 토큰이 없습니다.");
  }
}

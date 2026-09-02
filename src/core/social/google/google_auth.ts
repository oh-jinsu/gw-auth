import { fetchWithResult } from "gw-result";

import { authError } from "../../auth_error";
import { GoogleIdTokenVerifier } from "./google_id_token_verifier";
import type {
  OAuthAuthorizationRequest,
  OAuthCodeVerification,
  OAuthProvider,
} from "../oauth/oauth_provider";
import { providerJson, providerString } from "../provider_response";

/** Configuration for Google's server-side OpenID Connect code flow. */
export type GoogleAuthOptions = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
};

/** Google browser OAuth adapter using state, S256 PKCE, nonce, and ID-token verification. */
export class GoogleAuth implements OAuthProvider {
  /** Canonical provider identifier persisted with OAuth transactions. */
  readonly provider = "google" as const;

  /** Google supports S256 PKCE for the authorization-code flow. */
  readonly usesPkce = true;

  /** Google ID tokens can be bound to the initiating transaction with nonce. */
  readonly usesNonce = true;

  private readonly idTokens: GoogleIdTokenVerifier;

  /** Creates the provider adapter from confidential web-client configuration. */
  constructor(private readonly options: GoogleAuthOptions) {
    this.idTokens = new GoogleIdTokenVerifier([options.clientId]);
  }

  /** Builds a Google OpenID Connect authorization URL. */
  authorizationUrl(request: OAuthAuthorizationRequest) {
    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");

    url.search = new URLSearchParams({
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      response_type: "code",
      scope: "openid email profile",
      state: request.state,
      nonce: request.nonce ?? "",
      code_challenge: request.codeChallenge ?? "",
      code_challenge_method: "S256",
    }).toString();

    return url;
  }

  /** Exchanges the bound authorization code and verifies the returned Google ID token. */
  async verifyAuthorizationCode(verification: OAuthCodeVerification) {
    if (!verification.codeVerifier || !verification.nonce) {
      return authError("INVALID_OAUTH_STATE", "Google OAuth 상태가 유효하지 않습니다.");
    }

    const fetched = await fetchWithResult("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code: verification.code,
        client_id: this.options.clientId,
        client_secret: this.options.clientSecret,
        redirect_uri: this.options.redirectUri,
        grant_type: "authorization_code",
        code_verifier: verification.codeVerifier,
      }),
    });

    if (fetched.isErr) {
      return authError("GOOGLE_AUTH_FAILED", "Google 인증에 실패했습니다.", fetched.error);
    }

    const json = await providerJson(
      fetched.value,
      "GOOGLE_AUTH_FAILED",
      "Google 인증에 실패했습니다.",
    );

    if (json.isErr) {
      return json;
    }

    const idToken = providerString(json.value, "id_token");

    return idToken
      ? this.idTokens.verify(idToken, verification.nonce)
      : authError("GOOGLE_AUTH_FAILED", "Google ID 토큰이 없습니다.");
  }
}

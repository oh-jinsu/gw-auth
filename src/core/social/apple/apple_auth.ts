import { authError } from "../../auth_error";
import { AppleAuthorizationCodeVerifier } from "./apple_authorization_code_verifier";
import type {
  OAuthAuthorizationRequest,
  OAuthCodeVerification,
  OAuthProvider,
} from "../oauth/oauth_provider";

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

  private readonly authorizationCodes: AppleAuthorizationCodeVerifier;

  /** Creates the provider adapter from Apple Services ID configuration. */
  constructor(private readonly options: AppleAuthOptions) {
    this.authorizationCodes = new AppleAuthorizationCodeVerifier(options);
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

    return this.authorizationCodes.verify(verification.code, verification.nonce);
  }
}

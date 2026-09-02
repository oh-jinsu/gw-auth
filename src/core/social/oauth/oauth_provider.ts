import type { Result } from "gw-result";

import type { AuthError } from "../../auth_error";
import type { SocialIdentity, SocialProvider } from "../social_identity";

/** Values supplied to a provider authorization endpoint. */
export type OAuthAuthorizationRequest = {
  state: string;
  nonce?: string;
  codeChallenge?: string;
};

/** Values bound to an authorization code during back-channel verification. */
export type OAuthCodeVerification = {
  code: string;
  state: string;
  nonce?: string;
  codeVerifier?: string;
};

/** Browser authorization-code provider that returns only a verified identity. */
export interface OAuthProvider {
  /** Canonical provider identifier persisted with OAuth transactions. */
  readonly provider: SocialProvider;

  /** Whether this provider supports S256 PKCE in the configured flow. */
  readonly usesPkce: boolean;

  /** Whether this provider returns an identity token bound to a nonce. */
  readonly usesNonce: boolean;

  /** Builds the provider authorization URL from one-time transaction values. */
  authorizationUrl(request: OAuthAuthorizationRequest): URL;

  /** Exchanges and verifies a provider authorization code. */
  verifyAuthorizationCode(
    verification: OAuthCodeVerification,
  ): Promise<Result<SocialIdentity, AuthError>>;
}

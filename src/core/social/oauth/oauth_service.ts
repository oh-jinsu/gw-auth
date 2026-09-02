import { ok, resultFrom } from "gw-result";

import { authError, authSystemError } from "../../auth_error";
import { hashCredential, isCredential, randomCredential } from "../../credential";
import { sameOriginPath } from "../../same_origin_path";
import type { SocialAuthService } from "../social_auth_service";
import type { OAuthProvider } from "./oauth_provider";
import type { OAuthTransactionRepository } from "./oauth_transaction_repository";

const defaultOAuthTransactionLifetimeMs = 10 * 60 * 1000;

/** Provider URL and browser-bound state returned when an OAuth transaction starts. */
type OAuthStart = {
  authorizationUrl: URL;
  state: string;
  expiresAt: Date;
};

/** Starts and completes browser OAuth transactions bound to state and provider. */
export class OAuthService<
  TRegistrationInput = unknown,
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> {
  /** Creates the service with an explicit short-lived transaction policy. */
  constructor(
    private readonly repository: OAuthTransactionRepository,
    private readonly provider: OAuthProvider,
    private readonly socialAuth: SocialAuthService<TRegistrationInput, TClaims>,
    private readonly transactionLifetimeMs = defaultOAuthTransactionLifetimeMs,
  ) {}

  /** Persists one-time state and returns this provider's authorization URL. */
  async start(redirectPath = "/") {
    const safeRedirect = sameOriginPath(redirectPath);

    if (!safeRedirect) {
      return authError("INVALID_REDIRECT_PATH", "로그인 후 이동 경로가 유효하지 않습니다.");
    }

    const state = randomCredential();
    const stateHash = await hashCredential(state);

    if (stateHash.isErr) {
      return stateHash;
    }

    const codeVerifier = this.provider.usesPkce ? randomCredential() : undefined;
    const codeChallenge = codeVerifier ? await pkceChallenge(codeVerifier) : ok(undefined);

    if (codeChallenge.isErr) {
      return codeChallenge;
    }

    const nonce = this.provider.usesNonce ? randomCredential() : undefined;
    const expiresAt = new Date(Date.now() + this.transactionLifetimeMs);
    const authorizationUrl = resultFrom(() => this.provider.authorizationUrl({
      state,
      nonce,
      codeChallenge: codeChallenge.value,
    }));

    if (authorizationUrl.isErr) {
      return authSystemError("create_oauth_authorization_url", authorizationUrl.error);
    }

    const created = await resultFrom(() => this.repository.createOAuthTransaction({
      stateHash: stateHash.value,
      provider: this.provider.provider,
      redirectPath: safeRedirect,
      codeVerifier,
      nonce,
      expiresAt,
    }));

    if (created.isErr) {
      return authSystemError("create_oauth_transaction", created.error);
    }

    return ok({
      authorizationUrl: authorizationUrl.value,
      state,
      expiresAt,
    } satisfies OAuthStart);
  }

  /** Verifies browser-bound state, then consumes it before exchanging the code. */
  async complete(
    code: string,
    state: string,
    browserState?: string,
  ) {
    if (!code || !isCredential(state)) {
      return invalidOAuthResponse();
    }

    if (!isCredential(browserState) || browserState !== state) {
      return authError("INVALID_OAUTH_STATE", "OAuth 요청 브라우저가 일치하지 않습니다.");
    }

    const stateHash = await hashCredential(state);

    if (stateHash.isErr) {
      return stateHash;
    }

    const consumed = await resultFrom(() =>
      this.repository.consumeOAuthTransaction(stateHash.value, new Date()),
    );

    if (consumed.isErr) {
      return authSystemError("consume_oauth_transaction", consumed.error);
    }

    if (!consumed.value || consumed.value.provider !== this.provider.provider) {
      return authError("INVALID_OAUTH_STATE", "OAuth 요청 상태가 유효하지 않습니다.");
    }

    const transaction = consumed.value;
    const verification = await resultFrom(() => this.provider.verifyAuthorizationCode({
      code,
      state,
      nonce: transaction.nonce,
      codeVerifier: transaction.codeVerifier,
    }));

    if (verification.isErr) {
      return authSystemError("verify_oauth_authorization_code", verification.error);
    }

    const identity = verification.value;

    if (identity.isErr) {
      return identity;
    }

    const continued = await this.socialAuth.continueWithIdentity(identity.value);

    return continued.isErr
      ? continued
      : ok({ ...continued.value, redirectPath: transaction.redirectPath });
  }
}

/** Produces the S256 challenge required by providers that support PKCE. */
async function pkceChallenge(codeVerifier: string) {
  const digest = await resultFrom(() =>
    crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier)),
  );

  return digest.isErr
    ? authSystemError("create_pkce_challenge", digest.error)
    : ok(Buffer.from(digest.value).toString("base64url"));
}

/** Creates a stable malformed provider-callback failure. */
function invalidOAuthResponse() {
  return authError("INVALID_OAUTH_RESPONSE", "OAuth 응답이 유효하지 않습니다.");
}

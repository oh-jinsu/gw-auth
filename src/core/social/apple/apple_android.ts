import { ok, resultFrom } from "gw-result";

import type { AuthResult } from "../../api/auth_result";
import { authError, authSystemError } from "../../auth_error";
import { hashCredential, isCredential, randomCredential } from "../../credential";
import type { MobileSocialLoginResult } from "../mobile_social";
import type { OAuthTransactionRepository } from "../oauth/oauth_transaction_repository";
import type { SocialAuthService } from "../social_auth_service";
import type { AppleAuthorizationCodeVerifier } from "./apple_authorization_code_verifier";
import {
  appleAndroidHandoff,
  assertAppleAndroidPackageId,
  type AppleAndroidHandoffInput,
  type AppleAndroidHandoffOutput,
} from "./apple_android_handoff";

const androidStateDomain = "apple-android";
const oauthTransactionLifetimeMs = 10 * 60 * 1000;

/** Values an Android client supplies to Flutter's Apple browser authorization request. */
export type AppleAndroidStartOutput = {
  serviceId: string;
  redirectUri: string;
  state: string;
  nonce: string;
};

/** Apple credential returned to Android by Flutter's browser callback bridge. */
export type AppleAndroidCompleteInput = {
  authorizationCode: string;
  state: string;
};

/** Browser-API Apple operations that return explicit mobile session tokens. */
export type AppleAndroidAuth<TClaims extends Record<string, unknown>> = {
  /** Creates server-bound state and nonce for one Flutter Android authorization request. */
  start(): Promise<AuthResult<AppleAndroidStartOutput>>;

  /** Validates Apple's callback and creates Flutter's exact callback Intent. */
  handoff(input: AppleAndroidHandoffInput): AuthResult<AppleAndroidHandoffOutput>;

  /** Consumes one state and validates the matching Apple authorization code. */
  complete(
    input: AppleAndroidCompleteInput,
  ): Promise<AuthResult<MobileSocialLoginResult<TClaims>>>;
};

/** Dependencies and public provider values for one Android Apple browser flow. */
export type CreateAppleAndroidAuthOptions<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
> = {
  transactions: OAuthTransactionRepository;
  social: SocialAuthService<TRegistrationInput, TClaims>;
  verifier: AppleAuthorizationCodeVerifier;
  packageId: string;
  serviceId: string;
  redirectUri: string;
};

/** Creates Flutter-compatible Android Apple operations with server-owned replay binding. */
export function createAppleAndroidAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  options: CreateAppleAndroidAuthOptions<TRegistrationInput, TClaims>,
): AppleAndroidAuth<TClaims> {
  assertAppleAndroidPackageId(options.packageId);

  return {
    start: () => startAndroidApple(options),
    handoff: (input) => appleAndroidHandoff(options.packageId, input),
    complete: (input) => completeAndroidApple(options, input),
  };
}

/** Persists hashed state while returning the values required by Flutter. */
async function startAndroidApple<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(options: CreateAppleAndroidAuthOptions<TRegistrationInput, TClaims>) {
  const state = randomCredential();
  const nonce = randomCredential();
  const stateHash = await androidStateHash(options, state);

  if (stateHash.isErr) {
    return stateHash;
  }

  const created = await createTransaction(options, stateHash.value, nonce);

  return created.isErr
    ? created
    : ok({ serviceId: options.serviceId, redirectUri: options.redirectUri, state, nonce });
}

/** Consumes Android-only state before exchanging and continuing a verified identity. */
async function completeAndroidApple<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  options: CreateAppleAndroidAuthOptions<TRegistrationInput, TClaims>,
  input: AppleAndroidCompleteInput,
) {
  if (!input.authorizationCode || !isCredential(input.state)) {
    return invalidAppleResponse();
  }

  const transaction = await consumeTransaction(options, input.state);

  if (transaction.isErr || !transaction.value) {
    return transaction.isErr ? transaction : invalidAppleState();
  }

  const stored = transaction.value;
  const verified = await resultFrom(() => options.verifier.verify(
    input.authorizationCode,
    stored.nonce,
  ));

  if (verified.isErr) {
    return authSystemError("verify_apple_android_authorization_code", verified.error);
  }

  return verified.value.isErr
    ? verified.value
    : options.social.continueWithIdentity(verified.value.value);
}

/** Stores one Android transaction without retaining the public state value. */
async function createTransaction<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  options: CreateAppleAndroidAuthOptions<TRegistrationInput, TClaims>,
  stateHash: string,
  nonce: string,
) {
  const created = await resultFrom(() => options.transactions.createOAuthTransaction({
    stateHash,
    provider: "apple",
    redirectPath: "/",
    nonce,
    expiresAt: new Date(Date.now() + oauthTransactionLifetimeMs),
  }));

  return created.isErr
    ? authSystemError("create_apple_android_oauth_transaction", created.error)
    : ok();
}

/** Atomically consumes one unexpired transaction from the Android state namespace. */
async function consumeTransaction<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  options: CreateAppleAndroidAuthOptions<TRegistrationInput, TClaims>,
  state: string,
) {
  const stateHash = await androidStateHash(options, state);

  if (stateHash.isErr) {
    return stateHash;
  }

  const consumed = await resultFrom(() => options.transactions.consumeOAuthTransaction(
    stateHash.value,
    new Date(),
  ));

  if (consumed.isErr) {
    return authSystemError("consume_apple_android_oauth_transaction", consumed.error);
  }

  const transaction = consumed.value;
  const valid = transaction?.provider === "apple" && typeof transaction.nonce === "string";

  return ok(valid ? transaction : undefined);
}

/** Binds Android state to its Services ID and exact Apple return URI. */
function androidStateHash<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  options: CreateAppleAndroidAuthOptions<TRegistrationInput, TClaims>,
  state: string,
) {
  return hashCredential(JSON.stringify([
    androidStateDomain,
    options.serviceId,
    options.redirectUri,
    state,
  ]));
}

/** Returns one stable failure for malformed Apple credential input. */
function invalidAppleResponse() {
  return authError("INVALID_OAUTH_RESPONSE", "Apple 인증 응답이 유효하지 않습니다.");
}

/** Returns one stable failure for missing, expired, reused, or cross-flow state. */
function invalidAppleState() {
  return authError("INVALID_OAUTH_STATE", "Apple OAuth 상태가 유효하지 않습니다.");
}

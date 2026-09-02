import type { AuthState } from "../jwt_payload";
import { PasswordAuthService } from "./password_auth_service";
import type { PasswordLoginInput, PasswordSignupInput } from "./password_input";
import type { PasswordRepository } from "./password_repository";
import type { SessionTokenPair } from "../session/session_auth_service";
import type { AuthContext } from "../api/context";
import type { AuthResult, MobileSession } from "../api/auth_result";
import type { BrowserOperation } from "../api/browser_operation";
import { browserSessionResult } from "../session/session_result";

export type { PasswordLoginInput, PasswordSignupInput } from "./password_input";

/** Framework-neutral browser password operations. */
export type BrowserPasswordAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
> = {
  /** Authenticates a password account and returns session-cookie effects. */
  login(input: PasswordLoginInput): Promise<BrowserOperation<AuthState<TClaims>>>;

  /** Atomically creates a password account and returns session-cookie effects. */
  signup(
    input: PasswordSignupInput<TRegistrationInput>,
  ): Promise<BrowserOperation<AuthState<TClaims>>>;
};

/** Explicit-token password operations intended for mobile clients. */
export type MobilePasswordAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
> = {
  /** Authenticates a password account and returns explicit bearer tokens. */
  login(input: PasswordLoginInput): Promise<AuthResult<MobileSession<TClaims>>>;

  /** Atomically creates a password account and returns explicit bearer tokens. */
  signup(
    input: PasswordSignupInput<TRegistrationInput>,
  ): Promise<AuthResult<MobileSession<TClaims>>>;
};

/** Password feature that can be projected into browser or mobile delivery. */
export type PasswordAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
> = {
  /** Selects browser-safe password results and cookie mutations. */
  browser(): BrowserPasswordAuth<TRegistrationInput, TClaims>;

  /** Selects explicit-token password results for platform secure storage. */
  mobile(): MobilePasswordAuth<TRegistrationInput, TClaims>;
};

/** Creates one password feature from its feature-specific repository. */
export function createPasswordAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: AuthContext<TClaims>,
  repository: PasswordRepository<TRegistrationInput, TClaims>,
): PasswordAuth<TRegistrationInput, TClaims> {
  const service = new PasswordAuthService(repository, context.users, context.sessions);

  return {
    browser: () => createBrowserPasswordAuth(service, context),
    mobile: () => createMobilePasswordAuth(service),
  };
}

/** Binds password operations to browser cookie effects. */
function createBrowserPasswordAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  service: PasswordAuthService<TRegistrationInput, TClaims>,
  context: AuthContext<TClaims>,
): BrowserPasswordAuth<TRegistrationInput, TClaims> {
  return {
    login: async (input) => passwordBrowserResult(await service.login(input), context),
    signup: async (input) => passwordBrowserResult(await service.signup(input), context),
  };
}

/** Exposes password operations without browser cookie conversion. */
function createMobilePasswordAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(service: PasswordAuthService<TRegistrationInput, TClaims>) {
  return {
    login: (input: PasswordLoginInput) => service.login(input),
    signup: (input: PasswordSignupInput<TRegistrationInput>) => service.signup(input),
  };
}

/** Converts a successful password session while preserving service failures. */
function passwordBrowserResult<TClaims extends Record<string, unknown>>(
  result: AuthResult<SessionTokenPair<TClaims>>,
  context: AuthContext<TClaims>,
): BrowserOperation<AuthState<TClaims>> {
  return result.isErr
    ? { result, cookies: [] }
    : browserSessionResult(result.value, context.cookies);
}

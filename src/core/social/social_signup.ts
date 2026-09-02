import type { AuthState } from "../jwt_payload";
import type { SocialAuthService } from "./social_auth_service";
import type { SocialSignupProfile } from "./social_auth_repository";
import type { AuthResult, MobileSession } from "../api/auth_result";
import type { AuthContext } from "../api/context";
import {
  deleteBrowserCookie,
  readBrowserCookie,
  type BrowserCookieValues,
} from "../api/browser_cookie";
import type { BrowserOperation } from "../api/browser_operation";
import { browserSessionResult } from "../session/session_result";

/** Input shared by browser social-signup operations. */
export type BrowserSocialSignupInput = {
  cookies: BrowserCookieValues;
};

/** Provider-independent staged social-signup operations. */
export type SocialSignupAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
> = {
  /** Selects an HttpOnly-cookie signup credential. */
  browser(): BrowserSocialSignupAuth<TRegistrationInput, TClaims>;

  /** Selects an explicit signup credential for platform secure storage. */
  mobile(): MobileSocialSignupAuth<TRegistrationInput, TClaims>;
};

/** Staged signup operations backed by an HttpOnly browser credential. */
export type BrowserSocialSignupAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
> = {
  /** Reads provider profile hints without exposing the signup credential. */
  profile(input: BrowserSocialSignupInput): Promise<AuthResult<SocialSignupProfile>>;

  /** Completes signup and replaces the attempt cookie with session cookies. */
  complete(
    input: BrowserSocialSignupInput & { registration: TRegistrationInput },
  ): Promise<BrowserOperation<AuthState<TClaims>>>;
};

/** Staged signup operations using an explicit mobile credential. */
export type MobileSocialSignupAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
> = {
  /** Reads provider profile hints for an explicit signup credential. */
  profile(input: { signupToken: string }): Promise<AuthResult<SocialSignupProfile>>;

  /** Completes signup and returns explicit bearer tokens. */
  complete(input: {
    signupToken: string;
    registration: TRegistrationInput;
  }): Promise<AuthResult<MobileSession<TClaims>>>;
};

/** Creates browser and mobile views of one staged social-signup service. */
export function createSocialSignupAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: AuthContext<TClaims>,
  service: SocialAuthService<TRegistrationInput, TClaims>,
): SocialSignupAuth<TRegistrationInput, TClaims> {
  return {
    browser: () => createBrowserSocialSignup(context, service),
    mobile: () => createMobileSocialSignup(service),
  };
}

/** Creates cookie-backed staged social-signup operations. */
function createBrowserSocialSignup<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: AuthContext<TClaims>,
  service: SocialAuthService<TRegistrationInput, TClaims>,
): BrowserSocialSignupAuth<TRegistrationInput, TClaims> {
  return {
    profile: (input) => service.signupProfile(signupToken(input, context)),
    complete: (input) => completeBrowserSignup(input, context, service),
  };
}

/** Creates explicit-token staged social-signup operations. */
function createMobileSocialSignup<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(service: SocialAuthService<TRegistrationInput, TClaims>) {
  return {
    profile: ({ signupToken }: { signupToken: string }) => service.signupProfile(signupToken),
    complete: ({ signupToken, registration }: {
      signupToken: string;
      registration: TRegistrationInput;
    }) => service.completeSignup(signupToken, registration),
  };
}

/** Completes browser signup and replaces the attempt with session cookies. */
async function completeBrowserSignup<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  input: BrowserSocialSignupInput & { registration: TRegistrationInput },
  context: AuthContext<TClaims>,
  service: SocialAuthService<TRegistrationInput, TClaims>,
): Promise<BrowserOperation<AuthState<TClaims>>> {
  const result = await service.completeSignup(signupToken(input, context), input.registration);

  if (result.isErr) {
    return { result, cookies: [] };
  }

  const session = browserSessionResult(result.value, context.cookies);

  return session.result.isErr
    ? session
    : {
      result: session.result,
      cookies: [deleteBrowserCookie(context.cookies.socialSignup), ...session.cookies],
    };
}

/** Reads the hidden signup credential selected by the root browser policy. */
function signupToken<TClaims extends Record<string, unknown>>(
  input: BrowserSocialSignupInput,
  context: AuthContext<TClaims>,
) {
  return readBrowserCookie(input.cookies, context.cookies.socialSignup) ?? "";
}

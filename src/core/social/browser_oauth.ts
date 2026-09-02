import { ok } from "gw-result";

import type { AuthState } from "../jwt_payload";
import type { OAuthService } from "./oauth/oauth_service";
import type { SessionTokenPair } from "../session/session_auth_service";
import type { SocialSignupProfile } from "./social_auth_repository";
import type { AuthContext } from "../api/context";
import {
  deleteBrowserCookie,
  readBrowserCookie,
  setBrowserCookie,
  type DeleteBrowserCookie,
  type BrowserCookieValues,
} from "../api/browser_cookie";
import type { BrowserOperation } from "../api/browser_operation";
import { browserSessionResult } from "../session/session_result";

/** Input used to create one state-bound provider authorization request. */
export type OAuthStartInput = {
  redirectPath?: string;
};

/** Provider URL returned without performing a framework redirect. */
export type OAuthStartOutput = {
  authorizationUrl: string;
};

/** Callback values and parsed cookies supplied by an external adapter. */
export type OAuthCompleteInput = {
  code: string;
  state: string;
  cookies: BrowserCookieValues;
};

/** Browser OAuth result after verified identity continuation. */
export type OAuthCompleteOutput<TClaims extends Record<string, unknown>> =
  | { status: "authenticated"; auth: AuthState<TClaims>; redirectPath: string }
  | {
      status: "signup_required";
      profile: SocialSignupProfile;
      redirectPath: string;
    };

/** Framework-neutral browser authorization-code operations. */
export type BrowserOAuth<TClaims extends Record<string, unknown>> = {
  /** Persists one-time state and returns the provider authorization URL. */
  start(input?: OAuthStartInput): Promise<BrowserOperation<OAuthStartOutput>>;

  /** Verifies and consumes one callback before continuing local authentication. */
  complete(input: OAuthCompleteInput): Promise<BrowserOperation<OAuthCompleteOutput<TClaims>>>;
};

/** Creates browser OAuth operations for one provider. */
export function createBrowserOAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  context: AuthContext<TClaims>,
  service: OAuthService<TRegistrationInput, TClaims>,
): BrowserOAuth<TClaims> {
  return {
    start: (input = {}) => startOAuth(service, input, context),
    complete: (input) => completeOAuth(service, input, context),
  };
}

/** Starts OAuth and returns its provider redirect plus state-cookie effect. */
async function startOAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  service: OAuthService<TRegistrationInput, TClaims>,
  input: OAuthStartInput,
  context: AuthContext<TClaims>,
): Promise<BrowserOperation<OAuthStartOutput>> {
  const started = await service.start(input.redirectPath);

  return started.isErr
    ? { result: started, cookies: [] }
    : {
      result: ok({ authorizationUrl: started.value.authorizationUrl.toString() }),
      cookies: [setBrowserCookie(
        context.cookies.oauthState,
        started.value.state,
        started.value.expiresAt,
      )],
    };
}

/** Completes OAuth while clearing its one-time browser binding on every outcome. */
async function completeOAuth<
  TRegistrationInput,
  TClaims extends Record<string, unknown>,
>(
  service: OAuthService<TRegistrationInput, TClaims>,
  input: OAuthCompleteInput,
  context: AuthContext<TClaims>,
): Promise<BrowserOperation<OAuthCompleteOutput<TClaims>>> {
  const browserState = readBrowserCookie(input.cookies, context.cookies.oauthState);
  const completed = await service.complete(input.code, input.state, browserState);
  const clearedState = deleteBrowserCookie(context.cookies.oauthState);

  if (completed.isErr) {
    return { result: completed, cookies: [clearedState] };
  }

  return completed.value.status === "authenticated"
    ? authenticatedOAuth(completed.value, context, clearedState)
    : signupOAuth(completed.value, context, clearedState);
}

/** Converts an authenticated OAuth result into safe state and session cookies. */
function authenticatedOAuth<TClaims extends Record<string, unknown>>(
  completed: {
    tokens: SessionTokenPair<TClaims>;
    redirectPath: string;
  },
  context: AuthContext<TClaims>,
  clearedState: DeleteBrowserCookie,
): BrowserOperation<OAuthCompleteOutput<TClaims>> {
  const session = browserSessionResult(completed.tokens, context.cookies);

  return session.result.isErr
    ? { result: session.result, cookies: [clearedState] }
    : {
      result: ok({
        status: "authenticated",
        auth: session.result.value,
        redirectPath: completed.redirectPath,
      }),
      cookies: [clearedState, ...session.cookies],
    };
}

/** Stores a signup attempt without exposing its credential to browser code. */
function signupOAuth<TClaims extends Record<string, unknown>>(
  completed: {
    signupToken: string;
    signupExpiresAt: Date;
    profile: SocialSignupProfile;
    redirectPath: string;
  },
  context: AuthContext<TClaims>,
  clearedState: DeleteBrowserCookie,
): BrowserOperation<OAuthCompleteOutput<TClaims>> {
  return {
    result: ok({
      status: "signup_required",
      profile: completed.profile,
      redirectPath: completed.redirectPath,
    }),
    cookies: [
      clearedState,
      setBrowserCookie(
        context.cookies.socialSignup,
        completed.signupToken,
        completed.signupExpiresAt,
      ),
    ],
  };
}

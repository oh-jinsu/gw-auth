import type { AuthResult } from "../api/auth_result";
import type { BrowserCookieValues } from "../api/browser_cookie";
import type { BrowserOperation } from "../api/browser_operation";
import type { AuthContext } from "../api/context";
import { readBrowserCookie } from "../api/browser_cookie";
import { authError } from "../auth_error";
import type { AccountDeletionRepository } from "./account_deletion_repository";
import {
  AccountDeletionService,
  type AccountDeletionProviders,
} from "./account_deletion_service";
import { sessionCookieDeletions } from "../session/session_result";

/** Dependencies used to configure account deletion once. */
export type AccountAuthOptions = {
  repository: AccountDeletionRepository;
  providers?: AccountDeletionProviders;
};

/** Account deletion before selecting cookie or explicit-token delivery. */
export type AccountAuth = {
  /** Selects browser-cookie account deletion. */
  browser(): BrowserAccountAuth;

  /** Selects explicit access-token account deletion. */
  mobile(): MobileAccountAuth;

  /** Resumes a pending deletion from a trusted server-side maintenance job. */
  retryPending(userId: string): Promise<AuthResult>;
};

/** Cookie-backed account deletion that clears the local session after completion. */
export type BrowserAccountAuth = {
  /** Deletes the account authenticated by the access-token cookie. */
  delete(input: { cookies: BrowserCookieValues }): Promise<BrowserOperation<void>>;
};

/** Explicit-token account deletion intended for mobile clients. */
export type MobileAccountAuth = {
  /** Deletes the account authenticated by the supplied access token. */
  delete(input: { accessToken: string }): Promise<AuthResult>;
};

/** Creates authenticated browser, mobile, and retry account-deletion operations. */
export function createAccountAuth<TClaims extends Record<string, unknown>>(
  context: AuthContext<TClaims>,
  options: AccountAuthOptions,
): AccountAuth {
  const service = new AccountDeletionService(options.repository, options.providers);

  return {
    browser: () => ({ delete: (input) => deleteBrowserAccount(input, context, service) }),
    mobile: () => ({ delete: (input) => deleteMobileAccount(input, context, service) }),
    retryPending: (userId) => service.deleteAccount(userId),
  };
}

/** Verifies the browser access cookie before deleting its represented account. */
async function deleteBrowserAccount<TClaims extends Record<string, unknown>>(
  input: { cookies: BrowserCookieValues },
  context: AuthContext<TClaims>,
  service: AccountDeletionService,
): Promise<BrowserOperation<void>> {
  const token = readBrowserCookie(input.cookies, context.cookies.accessToken);
  const verified = token
    ? await context.sessions.verifyAccessToken(token)
    : authError("ACCESS_TOKEN_REQUIRED", "액세스 토큰이 필요합니다.");

  if (verified.isErr) {
    return { result: verified, cookies: [] };
  }

  const result = await service.deleteAccount(verified.value.userId);
  const cookies = result.isOk ? sessionCookieDeletions(context.cookies) : [];

  return { result, cookies };
}

/** Verifies an explicit access token before deleting its represented account. */
async function deleteMobileAccount<TClaims extends Record<string, unknown>>(
  input: { accessToken: string },
  context: AuthContext<TClaims>,
  service: AccountDeletionService,
) {
  const verified = input.accessToken
    ? await context.sessions.verifyAccessToken(input.accessToken)
    : authError("ACCESS_TOKEN_REQUIRED", "액세스 토큰이 필요합니다.");

  return verified.isErr ? verified : service.deleteAccount(verified.value.userId);
}

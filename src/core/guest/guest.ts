import { GuestAuthService } from "./guest_auth_service";
import type { GuestRepository } from "./guest_repository";
import type { AuthState } from "../jwt_payload";
import type { AuthContext } from "../api/context";
import type { AuthResult, MobileSession } from "../api/auth_result";
import { readBrowserCookie, setBrowserCookie, type BrowserCookieValues } from "../api/browser_cookie";
import type { BrowserOperation } from "../api/browser_operation";
import { browserSessionResult } from "../session/session_result";

/** Browser input containing cookie values already parsed by an external adapter. */
export type BrowserGuestInput = {
  cookies: BrowserCookieValues;
};

/** Explicit guest credential and session returned to a mobile client. */
export type MobileGuestAuthentication<TClaims extends Record<string, unknown>> = {
  guestCredential: string;
  guestCredentialExpiresAt: Date;
  tokens: MobileSession<TClaims>;
};

/** Guest feature that can be projected into browser or mobile delivery. */
export type GuestAuth<TClaims extends Record<string, unknown>> = {
  /** Selects HttpOnly-cookie guest credential delivery. */
  browser(): {
    /** Creates a guest or rotates the credential supplied in parsed cookies. */
    authenticate(
      input: BrowserGuestInput,
    ): Promise<BrowserOperation<AuthState<TClaims>>>;
  };

  /** Selects explicit guest credential delivery for platform secure storage. */
  mobile(): {
    /** Creates a guest or rotates an explicitly supplied credential. */
    authenticate(
      input?: { guestCredential?: string },
    ): Promise<AuthResult<MobileGuestAuthentication<TClaims>>>;
  };

  /** Deletes expired guest recovery credentials. */
  deleteExpiredCredentials(before?: Date): Promise<AuthResult<number>>;
};

/** Creates one guest feature from its optional, rotating credential store. */
export function createGuestAuth<TClaims extends Record<string, unknown>>(
  context: AuthContext<TClaims>,
  repository: GuestRepository<TClaims>,
): GuestAuth<TClaims> {
  const service = new GuestAuthService(repository, context.sessions);

  return {
    browser: () => createBrowserGuestAuth(service, context),
    mobile: () => createMobileGuestAuth(service),
    deleteExpiredCredentials: (before) => service.deleteExpiredCredentials(before),
  };
}

/** Creates browser guest operations using only plain cookie values and effects. */
function createBrowserGuestAuth<TClaims extends Record<string, unknown>>(
  service: GuestAuthService<TClaims>,
  context: AuthContext<TClaims>,
) {
  return {
    authenticate: async (input: BrowserGuestInput) => {
      const current = readBrowserCookie(input.cookies, context.cookies.guest);
      const result = await service.authenticate(current);

      return browserGuestResult(result, context);
    },
  };
}

/** Creates explicit guest-credential operations for mobile callers. */
function createMobileGuestAuth<TClaims extends Record<string, unknown>>(
  service: GuestAuthService<TClaims>,
) {
  return {
    authenticate: (input: { guestCredential?: string } = {}) => {
      return service.authenticate(input.guestCredential);
    },
  };
}

/** Converts a successful guest session into browser state and cookie effects. */
function browserGuestResult<TClaims extends Record<string, unknown>>(
  result: Awaited<ReturnType<GuestAuthService<TClaims>["authenticate"]>>,
  context: AuthContext<TClaims>,
): BrowserOperation<AuthState<TClaims>> {
  if (result.isErr) {
    return { result, cookies: [] };
  }

  const session = browserSessionResult(result.value.tokens, context.cookies);

  return {
    result: session.result,
    cookies: session.result.isErr
      ? session.cookies
      : [
        ...session.cookies,
        setBrowserCookie(
          context.cookies.guest,
          result.value.guestCredential,
          result.value.guestCredentialExpiresAt,
        ),
      ],
  };
}

import type { JWTPayload } from "jose";

import {
  createAccountAuth,
  type AccountAuth,
  type AccountAuthOptions,
} from "../account/account";
import type {
  SessionAccessPayload,
  SessionRefreshPayload,
} from "../jwt_payload";
import type { GuestRepository } from "../guest/guest_repository";
import { JWTManager } from "../jwt_manager";
import type { PasswordRepository } from "../password/password_repository";
import { SessionAuthService } from "../session/session_auth_service";
import type {
  SessionRepository,
  SessionUserRepository,
} from "../session/session_repository";
import type { BrowserCookiesOptions } from "./browser_cookie";
import { resolveBrowserCookies } from "./browser_cookie";
import type { AuthContext } from "./context";
import { createGuestAuth, type GuestAuth } from "../guest/guest";
import { createPasswordAuth, type PasswordAuth } from "../password/password";
import {
  createPasswordRecoveryAuth,
  type PasswordRecoveryAuth,
  type PasswordRecoveryAuthOptions,
} from "../password/password_recovery";
import { createSessionAuth, type SessionAuth } from "../session/session";
import { createSocialAuth, type SocialAuth, type SocialOptions } from "../social/social";

/** Shared persistence required by every issued and refreshed session. */
export type AuthSessionRepository<TClaims extends Record<string, unknown>> =
  SessionRepository & SessionUserRepository<TClaims>;

/** Secret and lifetime for one token purpose managed internally by `createAuth`. */
export type AuthTokenOptions = {
  secret: string;
  expiresIn: string;
};

/** Common session, token, and optional browser policy configured once. */
export type CreateAuthOptions<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> = {
  /** Stable cookie-safe identifier reused as JWT issuer, audience, and cookie prefix. */
  serviceName: string;

  /** Shared session and current-user persistence. */
  sessions: AuthSessionRepository<TClaims>;

  /** Secrets and lifetimes for the two package-managed token purposes. */
  tokens: {
    access: AuthTokenOptions;
    refresh: AuthTokenOptions;
  };

  /** Optional browser-cookie policy overrides. */
  browser?: {
    cookies?: BrowserCookiesOptions;
  };
};

/** Public composition facade exposing feature-first, environment-second APIs. */
export type Auth<TClaims extends Record<string, unknown>> = {
  /** Enables resumable account deletion with application-owned persistence. */
  account(options: AccountAuthOptions): AccountAuth;

  /** Enables password authentication with its feature-specific repository. */
  password<TRegistrationInput>(options: {
    repository: PasswordRepository<TRegistrationInput, TClaims>;
  }): PasswordAuth<TRegistrationInput, TClaims>;

  /** Enables shared social persistence before provider configuration. */
  social<TRegistrationInput>(
    options: SocialOptions<TRegistrationInput, TClaims>,
  ): SocialAuth<TRegistrationInput, TClaims>;

  /** Enables rotating guest authentication with its feature repository. */
  guest(options: {
    repository: GuestRepository<TClaims>;
  }): GuestAuth<TClaims>;

  /** Enables one-time password recovery with application-owned mail delivery. */
  passwordRecovery(options: PasswordRecoveryAuthOptions): PasswordRecoveryAuth;

  /** Provides session verification, rotation, revocation, and cleanup. */
  session: SessionAuth<TClaims>;
};

/** Creates the package facade from only dependencies shared by all auth features. */
export function createAuth<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
>(options: CreateAuthOptions<TClaims>): Auth<TClaims> {
  const context = createContext(options);

  return {
    account: (feature) => createAccountAuth(context, feature),
    password: (feature) => createPasswordAuth(context, feature.repository),
    social: (feature) => createSocialAuth(context, feature),
    guest: (feature) => createGuestAuth(context, feature.repository),
    passwordRecovery: createPasswordRecoveryAuth,
    session: createSessionAuth(context),
  };
}

/** Creates purpose-bound token managers and the shared internal context. */
function createContext<TClaims extends Record<string, unknown>>(
  options: CreateAuthOptions<TClaims>,
): AuthContext<TClaims> {
  assertServiceName(options.serviceName);
  assertDistinctTokenSecrets(options.tokens.access.secret, options.tokens.refresh.secret);

  const common = {
    issuer: options.serviceName,
    audience: options.serviceName,
  };

  const access = new JWTManager<SessionAccessPayload<TClaims>>({
    ...options.tokens.access,
    ...common,
    tokenUse: "access",
    validatePayload: isSessionAccessPayload<TClaims>,
  });

  const refresh = new JWTManager<SessionRefreshPayload>({
    ...options.tokens.refresh,
    ...common,
    tokenUse: "refresh",
    validatePayload: isSessionRefreshPayload,
  });

  const sessions = new SessionAuthService(
    options.sessions,
    options.sessions,
    access,
    refresh,
  );

  return {
    sessions,
    users: options.sessions,
    cookies: resolveBrowserCookies(options.serviceName, options.browser?.cookies),
  };
}

/** Rejects sharing one signing key across access and refresh token purposes. */
function assertDistinctTokenSecrets(accessSecret: string, refreshSecret: string) {
  if (accessSecret === refreshSecret) {
    throw new TypeError("Access and refresh tokens must use different secrets.");
  }
}

/** Rejects names that cannot safely be reused as browser-cookie prefixes. */
function assertServiceName(serviceName: string) {
  if (!/^[A-Za-z0-9._-]+$/.test(serviceName)) {
    throw new TypeError("serviceName may contain only letters, numbers, dots, underscores, and hyphens.");
  }
}

/** Validates the access-token fields owned by the package. */
function isSessionAccessPayload<TClaims extends Record<string, unknown>>(
  payload: JWTPayload,
): payload is SessionAccessPayload<TClaims> {
  return payload.tokenUse === "access"
    && typeof payload.userId === "string"
    && typeof payload.sessionId === "string"
    && typeof payload.exp === "number";
}

/** Validates the refresh-token fields owned by the package. */
function isSessionRefreshPayload(payload: JWTPayload): payload is SessionRefreshPayload {
  return payload.tokenUse === "refresh"
    && typeof payload.userId === "string"
    && typeof payload.sessionId === "string"
    && typeof payload.jti === "string"
    && typeof payload.exp === "number";
}

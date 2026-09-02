import { err } from "gw-result";

const authenticationErrorCodes = new Set([
  "ACCESS_TOKEN_REQUIRED",
  "APPLE_AUTH_FAILED",
  "GOOGLE_AUTH_FAILED",
  "INVALID_ACCESS_TOKEN",
  "INVALID_CREDENTIAL",
  "INVALID_GUEST_CREDENTIAL",
  "INVALID_OAUTH_STATE",
  "INVALID_PROVIDER_CREDENTIAL",
  "INVALID_REFRESH_TOKEN",
  "INVALID_SOCIAL_SIGNUP_TOKEN",
  "INVALID_TOKEN",
  "KAKAO_AUTH_FAILED",
  "NAVER_AUTH_FAILED",
  "REFRESH_TOKEN_REQUIRED",
  "REFRESH_TOKEN_REUSED",
  "SESSION_USER_MISMATCH",
  "SESSION_USER_NOT_FOUND",
]);

const conflictErrorCodes = new Set([
  "CREDENTIAL_ALREADY_EXISTS",
  "IDENTITY_ALREADY_EXISTS",
]);

const systemErrorCodes = new Set([
  "AUTH_SYSTEM_FAILURE",
  "INVALID_TOKEN_EXPIRATION",
  "TOKEN_SIGNING_FAILED",
]);

const upstreamErrorCodes = new Set([
  "INVALID_PROVIDER_RESPONSE",
  "PROVIDER_UNAVAILABLE",
]);

/** Framework-neutral failure category used by transport adapters. */
export type AuthErrorCategory =
  | "authentication"
  | "conflict"
  | "request"
  | "system"
  | "upstream";

/** Stable authentication failure that can cross package boundaries structurally. */
export class AuthError<TCode extends string = string> extends Error {
  /** Structural discriminator used instead of cross-package `instanceof` checks. */
  readonly kind = "GW_AUTH_ERROR" as const;

  /** Stable machine-readable failure code. */
  readonly code: TCode;

  /** Creates a failure while preserving an optional internal cause for observability. */
  constructor(code: TCode, message: string, cause?: unknown) {
    super(message, { cause });

    this.name = "AuthError";
    this.code = code;
  }
}

/** Creates a failed result with a stable authentication error. */
export function authError<TCode extends string>(
  code: TCode,
  message: string,
  cause?: unknown,
) {
  return err(new AuthError(code, message, cause));
}

/** Creates a sanitized system failure while retaining the original internal cause. */
export function authSystemError(operation: string, cause: unknown) {
  return authError(
    "AUTH_SYSTEM_FAILURE",
    "인증 처리 중 시스템 오류가 발생했습니다.",
    { operation, cause },
  );
}

/** Classifies a stable error code without assigning a transport-specific status. */
export function authErrorCategory(error: Pick<AuthError, "code">): AuthErrorCategory {
  if (authenticationErrorCodes.has(error.code)) {
    return "authentication";
  }

  if (conflictErrorCodes.has(error.code)) {
    return "conflict";
  }

  if (systemErrorCodes.has(error.code)) {
    return "system";
  }

  return upstreamErrorCodes.has(error.code) ? "upstream" : "request";
}

/** Recognizes the public error contract without relying on constructor identity. */
export function isAuthError(value: unknown): value is AuthError {
  return typeof value === "object"
    && value !== null
    && "kind" in value
    && value.kind === "GW_AUTH_ERROR"
    && "code" in value
    && typeof value.code === "string"
    && "message" in value
    && typeof value.message === "string";
}

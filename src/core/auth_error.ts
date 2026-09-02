import { err } from "gw-result";

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
    `인증 처리 중 시스템 오류가 발생했습니다: ${operation}`,
    cause,
  );
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

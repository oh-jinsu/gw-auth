import {
  PasswordRecoveryService,
} from "./password_recovery_service";
import type { PasswordResetMailer } from "./password_reset_mailer";
import type { PasswordResetRepository } from "./password_reset_repository";
import type { AuthResult } from "../api/auth_result";
import type { AuthError } from "../auth_error";

/** Feature-specific password-recovery dependencies and link policy. */
export type PasswordRecoveryAuthOptions = {
  repository: PasswordResetRepository;
  mailer: PasswordResetMailer;
  siteOrigin: string;
  resetLifetimeMs?: number;
  resetPath?: string;
  /** Receives concealed known-account request failures for application observability. */
  onRequestError?: (error: AuthError) => void | Promise<void>;
};

/** Framework-neutral password-recovery operations. */
export type PasswordRecoveryAuth = {
  /** Creates and sends an indistinguishable reset attempt when an account exists. */
  request(input: { credentialId: string }): Promise<AuthResult>;

  /** Atomically consumes a reset attempt and replaces the password. */
  reset(input: {
    token: string;
    password: string;
    passwordConfirm: string;
  }): Promise<AuthResult>;

  /** Deletes expired password-reset attempts. */
  deleteExpired(before?: Date): Promise<AuthResult<number>>;
};

/** Creates password recovery only when the consuming service enables it. */
export function createPasswordRecoveryAuth(
  options: PasswordRecoveryAuthOptions,
): PasswordRecoveryAuth {
  const service = new PasswordRecoveryService(
    options.siteOrigin,
    options.repository,
    options.mailer,
    options,
  );

  return {
    request: ({ credentialId }) => service.requestPasswordReset(credentialId),
    reset: ({ token, password, passwordConfirm }) => {
      return service.resetPassword(token, password, passwordConfirm);
    },
    deleteExpired: (before) => service.deleteExpiredAttempts(before),
  };
}

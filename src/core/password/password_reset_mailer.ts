/** Message passed to an application-owned mail or queue adapter. */
export type PasswordResetMessage = {
  to: string;
  resetUrl: string;
  expiresAt: Date;
};

/** Side-channel port used to queue password-reset notifications. */
export interface PasswordResetMailer {
  /** Queues a password-reset message without exposing transport credentials to core. */
  sendPasswordReset(message: PasswordResetMessage): Promise<void>;
}

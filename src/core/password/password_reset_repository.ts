/** Account destination eligible for password recovery. */
export type PasswordResetAccount = {
  credentialId: string;
  userId: string;
  email: string;
};

/** Hashed one-time reset credential persisted before notification. */
export type NewPasswordResetAttempt = {
  tokenHash: string;
  credentialId: string;
  userId: string;
  expiresAt: Date;
};

/** Values required by the atomic password-reset transaction. */
export type CompletePasswordResetParams = {
  tokenHash: string;
  passwordHash: string;
  now: Date;
};

/** Expected outcome from consuming a password-reset attempt. */
export type CompletePasswordResetResult =
  | { status: "completed"; userId: string }
  | { status: "invalid_attempt" };

/** Persists and consumes password-reset attempts without exposing account existence. */
export interface PasswordResetRepository {
  /** Finds the recovery destination for a normalized credential identifier. */
  findPasswordResetAccount(credentialId: string): Promise<PasswordResetAccount | undefined>;

  /** Persists a hashed, expiring reset attempt. */
  createPasswordResetAttempt(attempt: NewPasswordResetAttempt): Promise<void>;

  /** Deletes an attempt when its side-channel notification could not be queued. */
  deletePasswordResetAttempt(tokenHash: string): Promise<void>;

  /**
   * Atomically consumes the unexpired attempt, updates the password, and revokes
   * every refresh session belonging to the returned user.
   */
  completePasswordReset(
    params: CompletePasswordResetParams,
  ): Promise<CompletePasswordResetResult>;

  /** Deletes expired or consumed reset attempts and returns the number removed. */
  deleteExpiredPasswordResetAttempts(before: Date): Promise<number>;
}

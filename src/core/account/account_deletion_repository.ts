/** Apple credential retained while an account deletion is pending. */
export type PendingAppleRevocation = {
  /** Opaque application-owned identifier for this durable revocation record. */
  id: string;

  /** Provider discriminator used by the core revocation dispatcher. */
  provider: "apple";

  /** App ID or Services ID that originally issued the refresh token. */
  providerClientId: string;

  /** Decrypted provider refresh token returned only to the deletion service. */
  providerRefreshToken: string;
};

/** Durable account-deletion state returned after local sessions are revoked. */
export type PendingAccountDeletion = {
  /** Provider credentials that still require remote revocation. */
  revocations: readonly PendingAppleRevocation[];
};

/** Application-owned persistence for atomic, resumable account deletion. */
export interface AccountDeletionRepository {
  /**
   * Atomically marks the account deletion pending and revokes all local sessions.
   * Authentication repositories must reject pending users and session creation
   * must not race ahead of this state transition.
   * Repeated calls must return the same deletion with only unfinished revocations.
   * Returns `undefined` when the account is already absent or fully deleted.
   */
  beginAccountDeletion(userId: string): Promise<PendingAccountDeletion | undefined>;

  /** Idempotently records one successfully revoked provider credential. */
  completeAccountProviderRevocation(revocationId: string): Promise<void>;

  /**
   * Atomically deletes, disables, or anonymizes the account and all authentication data.
   * Implementations must reject completion while a provider revocation remains pending
   * and treat repeated completion of an absent account as success.
   */
  completeAccountDeletion(userId: string): Promise<void>;
}

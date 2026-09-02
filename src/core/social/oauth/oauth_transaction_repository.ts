import type { SocialProvider } from "../social_identity";

/** One-time browser OAuth transaction persisted before leaving the application. */
export type OAuthTransaction = {
  stateHash: string;
  provider: SocialProvider;
  redirectPath: string;
  codeVerifier?: string;
  nonce?: string;
  expiresAt: Date;
};

/** Persistence contract for one-time OAuth state, PKCE, nonce, and redirect data. */
export interface OAuthTransactionRepository {
  /** Persists a new hashed-state OAuth transaction. */
  createOAuthTransaction(transaction: OAuthTransaction): Promise<void>;

  /** Atomically consumes and returns a matching unexpired transaction. */
  consumeOAuthTransaction(
    stateHash: string,
    now: Date,
  ): Promise<OAuthTransaction | undefined>;

  /** Deletes expired or consumed OAuth transactions and returns the number removed. */
  deleteExpiredOAuthTransactions(before: Date): Promise<number>;
}

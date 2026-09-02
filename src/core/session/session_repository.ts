/** User data loaded at refresh time so newly issued claims are never stale. */
export type SessionUser<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> = {
  id: string;
  claims: TClaims;
};

/** Persisted refresh-session state containing only a hash of the bearer token. */
export type RefreshSession = {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
};

/** New refresh-session value persisted during initial token issuance. */
export type NewRefreshSession = RefreshSession;

/** Loads the current user and authorization claims independently of session storage. */
export interface SessionUserRepository<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> {
  /** Finds the current user state used to rotate a session. */
  findSessionUser(userId: string): Promise<SessionUser<TClaims> | undefined>;
}

/** Persists and atomically rotates refresh sessions. */
export interface SessionRepository {
  /** Persists a newly issued refresh session. */
  createRefreshSession(session: NewRefreshSession): Promise<void>;

  /** Finds a refresh session by its random session identifier. */
  findRefreshSession(sessionId: string): Promise<RefreshSession | undefined>;

  /** Atomically replaces the hash only when the expected hash still matches. */
  rotateRefreshSession(
    sessionId: string,
    expectedTokenHash: string,
    nextTokenHash: string,
    expiresAt: Date,
  ): Promise<boolean>;

  /** Deletes exactly one refresh session. */
  deleteRefreshSession(sessionId: string): Promise<void>;

  /** Deletes abandoned expired rows and returns the number removed. */
  deleteExpiredRefreshSessions(before: Date): Promise<number>;
}

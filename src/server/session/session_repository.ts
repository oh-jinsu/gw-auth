export type SessionUser = {
  id: string;
  role: string;
  name: string;
};

export type RefreshSession = {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
};

export type NewRefreshSession = RefreshSession;

export interface SessionRepository {
  findSessionUser(userId: string): Promise<SessionUser | undefined>;

  createRefreshSession(session: NewRefreshSession): Promise<void>;

  findRefreshSession(sessionId: string): Promise<RefreshSession | undefined>;

  /** Atomically replaces the hash only when expectedTokenHash still matches. */
  rotateRefreshSession(
    sessionId: string,
    expectedTokenHash: string,
    nextTokenHash: string,
    expiresAt: Date,
  ): Promise<boolean>;

  deleteRefreshSession(sessionId: string): Promise<void>;

  deleteUserRefreshSessions(userId: string): Promise<void>;
}

/** User data loaded at refresh time so newly issued claims are never stale. */
export type SessionUser<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> = {
  id: string;
  claims: TClaims;
};

/** Persisted state needed to identify and reproduce one refresh token. */
export type RefreshTokenState = {
  tokenHash: string;
  tokenId: string;
  issuedAt: Date;
  expiresAt: Date;
};

/** Persisted refresh-session state containing no bearer token plaintext. */
export type RefreshSession = RefreshTokenState & {
  id: string;
  userId: string;
  previousTokenHash: string | null;
  rotatedAt: Date;
};

/** New refresh-session value persisted during initial token issuance. */
export type NewRefreshSession = RefreshSession;

/** Atomic refresh-rotation input including the accepted concurrency boundary. */
export type RotateRefreshSessionInput = {
  /** Session family and verified user binding submitted by the refresh token. */
  sessionId: string;
  userId: string;

  /** Hash of the presented bearer and metadata for the proposed replacement. */
  expectedTokenHash: string;
  next: RefreshTokenState;

  /** Exact decision time and inclusive start of the accepted overlap window. */
  now: Date;
  reuseWindowStart: Date;
};

/** Result of atomically classifying and applying one refresh attempt. */
export type RotateRefreshSessionResult =
  | { status: "rotated" }
  | { status: "concurrent"; session: RefreshSession }
  | { status: "invalid" }
  | { status: "reused" };

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

  /** Atomically rotates, accepts immediate prior-token overlap, or revokes reuse. */
  rotateRefreshSession(
    input: RotateRefreshSessionInput,
  ): Promise<RotateRefreshSessionResult>;

  /** Deletes exactly one refresh session. */
  deleteRefreshSession(sessionId: string): Promise<void>;

  /** Deletes abandoned expired rows and returns the number removed. */
  deleteExpiredRefreshSessions(before: Date): Promise<number>;
}

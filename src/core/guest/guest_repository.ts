import type { SessionUser } from "../session/session_repository";

/** Hashed guest recovery credential created together with a random guest user. */
export type NewGuestCredential = {
  tokenHash: string;
  expiresAt: Date;
};

/** Compare-and-swap values used to rotate a guest recovery credential. */
export type RotateGuestCredentialParams = {
  expectedTokenHash: string;
  nextTokenHash: string;
  nextExpiresAt: Date;
  now: Date;
};

/** Atomically persists guest users and their rotating recovery credentials. */
export interface GuestRepository<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> {
  /** Atomically creates a random guest user and its first recovery credential. */
  createGuestAccount(credential: NewGuestCredential): Promise<SessionUser<TClaims>>;

  /** Finds the guest belonging to a matching unexpired credential hash. */
  findGuestByCredential(
    tokenHash: string,
    now: Date,
  ): Promise<SessionUser<TClaims> | undefined>;

  /** Atomically rotates a valid unexpired credential after session issuance. */
  rotateGuestCredential(
    params: RotateGuestCredentialParams,
  ): Promise<boolean>;

  /** Deletes expired guest credentials and returns the number removed. */
  deleteExpiredGuestCredentials(before: Date): Promise<number>;
}

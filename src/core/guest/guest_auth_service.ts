import { ok, resultFrom, type Err } from "gw-result";

import { authError, authSystemError, type AuthError } from "../auth_error";
import { hashCredential, isCredential, randomCredential } from "../credential";
import type { SessionAuthService } from "../session/session_auth_service";
import type { GuestRepository } from "./guest_repository";

const defaultGuestCredentialLifetimeMs = 365 * 24 * 60 * 60 * 1000;

/** Replaces client-provided device identifiers with server-issued guest credentials. */
export class GuestAuthService<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> {
  /** Creates the service with an explicit rotating guest-credential lifetime. */
  constructor(
    private readonly repository: GuestRepository<TClaims>,
    private readonly sessions: SessionAuthService<TClaims>,
    private readonly credentialLifetimeMs = defaultGuestCredentialLifetimeMs,
  ) {}

  /** Creates a guest or rotates an existing high-entropy guest credential. */
  async authenticate(currentCredential?: string) {
    if (currentCredential !== undefined && !isCredential(currentCredential)) {
      return invalidGuestCredential();
    }

    const nextCredential = randomCredential();
    const nextHash = await hashCredential(nextCredential);

    if (nextHash.isErr) {
      return nextHash;
    }

    const nextExpiresAt = new Date(Date.now() + this.credentialLifetimeMs);
    const user = currentCredential
      ? await this.findGuest(currentCredential)
      : await this.createGuest(nextHash.value, nextExpiresAt);

    if (user.isErr) {
      return user;
    }

    const tokens = await this.sessions.issueTokenPair(user.value);

    if (tokens.isErr) {
      return tokens;
    }

    if (currentCredential) {
      const rotated = await this.rotateGuest(
        currentCredential,
        nextHash.value,
        nextExpiresAt,
      );

      if (rotated.isErr) {
        return this.revokeUnrecoverableSession(tokens.value.refreshToken, rotated);
      }
    }

    return ok({
      guestCredential: nextCredential,
      guestCredentialExpiresAt: nextExpiresAt,
      tokens: tokens.value,
    });
  }

  /** Removes expired guest recovery credentials through a maintenance operation. */
  async deleteExpiredCredentials(before = new Date()) {
    const deleted = await resultFrom(() =>
      this.repository.deleteExpiredGuestCredentials(before),
    );

    return deleted.isErr
      ? authSystemError("delete_expired_guest_credentials", deleted.error)
      : deleted;
  }

  /** Creates the random user and credential as one repository transaction. */
  private async createGuest(tokenHash: string, expiresAt: Date) {
    const created = await resultFrom(() =>
      this.repository.createGuestAccount({ tokenHash, expiresAt }),
    );

    return created.isErr
      ? authSystemError("create_guest_account", created.error)
      : created;
  }

  /** Validates the old hash without consuming it before session creation succeeds. */
  private async findGuest(currentCredential: string) {
    const currentHash = await hashCredential(currentCredential);

    if (currentHash.isErr) {
      return currentHash;
    }

    const found = await resultFrom(() =>
      this.repository.findGuestByCredential(currentHash.value, new Date()),
    );

    if (found.isErr) {
      return authSystemError("find_guest_credential", found.error);
    }

    return found.value ? ok(found.value) : invalidGuestCredential();
  }

  /** Rotates the recovery credential using compare-and-swap semantics. */
  private async rotateGuest(
    currentCredential: string,
    nextTokenHash: string,
    nextExpiresAt: Date,
  ) {
    const currentHash = await hashCredential(currentCredential);

    if (currentHash.isErr) {
      return currentHash;
    }

    const rotated = await resultFrom(() => this.repository.rotateGuestCredential({
      expectedTokenHash: currentHash.value,
      nextTokenHash,
      nextExpiresAt,
      now: new Date(),
    }));

    if (rotated.isErr) {
      return authSystemError("rotate_guest_credential", rotated.error);
    }

    return rotated.value ? ok() : invalidGuestCredential();
  }

  /** Revokes a session that cannot be paired with a successfully rotated credential. */
  private async revokeUnrecoverableSession(
    refreshToken: string,
    rotationFailure: Err<AuthError>,
  ) {
    const revoked = await this.sessions.revokeSession(refreshToken);

    return revoked.isErr
      ? authSystemError("rollback_guest_session", {
        rotationError: rotationFailure.error,
        rollbackError: revoked.error,
      })
      : rotationFailure;
  }
}

/** Returns one rejection for malformed, missing, expired, or replayed guest credentials. */
function invalidGuestCredential() {
  return authError("INVALID_GUEST_CREDENTIAL", "게스트 인증 정보가 유효하지 않습니다.");
}

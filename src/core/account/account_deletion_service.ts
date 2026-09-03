import { ok, resultFrom } from "gw-result";

import { authError, authSystemError } from "../auth_error";
import type { AuthResult } from "../api/auth_result";
import type { AppleTokenRevocation } from "../social/apple/apple";
import type {
  AccountDeletionRepository,
  PendingAccountDeletion,
  PendingAppleRevocation,
} from "./account_deletion_repository";

/** Provider operations configured for account deletion. */
export type AccountDeletionProviders = {
  /** Revokes Apple refresh tokens with their persisted issuing client IDs. */
  apple?: AppleTokenRevocation;
};

/** Coordinates durable local deletion state with provider-specific revocation. */
export class AccountDeletionService {
  /** Creates account deletion from application persistence and configured providers. */
  constructor(
    private readonly repository: AccountDeletionRepository,
    private readonly providers: AccountDeletionProviders = {},
  ) {}

  /** Begins or resumes one account deletion and completes it after all revocations. */
  async deleteAccount(userId: string): Promise<AuthResult> {
    const pending = await resultFrom(() => this.repository.beginAccountDeletion(userId));

    if (pending.isErr) {
      return authSystemError("begin_account_deletion", pending.error);
    }

    if (!pending.value) {
      return ok();
    }

    return this.completePending(userId, pending.value);
  }

  /** Revokes every remaining provider token before final local deletion. */
  private async completePending(userId: string, pending: PendingAccountDeletion) {
    for (const revocation of pending.revocations) {
      const revoked = await this.revokeApple(revocation);

      if (revoked.isErr) {
        return revoked;
      }

      const recorded = await this.recordRevocation(revocation.id);

      if (recorded.isErr) {
        return recorded;
      }
    }

    return this.completeAccount(userId);
  }

  /** Executes one Apple revocation without exposing provider internals to repositories. */
  private async revokeApple(revocation: PendingAppleRevocation) {
    if (!this.providers.apple) {
      return authSystemError("missing_apple_account_revoker", { revocationId: revocation.id });
    }

    const revoked = await this.providers.apple.revoke({
      providerClientId: revocation.providerClientId,
      providerRefreshToken: revocation.providerRefreshToken,
    });

    return revoked.isErr
      ? authError(
        "ACCOUNT_PROVIDER_REVOCATION_FAILED",
        "연결된 외부 계정을 해제하지 못했습니다.",
        { provider: revocation.provider, cause: revoked.error },
      )
      : ok();
  }

  /** Persists successful remote revocation so a retry skips completed work. */
  private async recordRevocation(revocationId: string) {
    const recorded = await resultFrom(() =>
      this.repository.completeAccountProviderRevocation(revocationId),
    );

    return recorded.isErr
      ? authSystemError("complete_account_provider_revocation", recorded.error)
      : ok();
  }

  /** Finalizes application-owned deletion only after provider work is complete. */
  private async completeAccount(userId: string) {
    const completed = await resultFrom(() => this.repository.completeAccountDeletion(userId));

    return completed.isErr
      ? authSystemError("complete_account_deletion", completed.error)
      : ok();
  }
}

import bcryptjs from "bcryptjs";
import { ok, resultFrom } from "gw-result";

import { authError, authSystemError } from "../auth_error";
import { hashCredential, isCredential, randomCredential } from "../credential";
import type { PasswordResetMailer } from "./password_reset_mailer";
import type { PasswordResetRepository } from "./password_reset_repository";
import { sameOriginPath } from "../same_origin_path";

const defaultResetLifetimeMs = 60 * 60 * 1000;
const defaultResetPath = "/reset-password";

/** Optional lifetime and UI route configuration for password recovery. */
export type PasswordRecoveryOptions = {
  resetLifetimeMs?: number;
  resetPath?: string;
};

/** Coordinates opaque one-time password reset attempts with an injected mail adapter. */
export class PasswordRecoveryService {
  /** Creates a recovery service with an explicit public reset-page origin. */
  constructor(
    private readonly siteOrigin: string,
    private readonly repository: PasswordResetRepository,
    private readonly mailer: PasswordResetMailer,
    options: PasswordRecoveryOptions = {},
  ) {
    assertSiteOrigin(siteOrigin);
    assertResetPath(options.resetPath ?? defaultResetPath);

    this.resetLifetimeMs = options.resetLifetimeMs ?? defaultResetLifetimeMs;
    this.resetPath = options.resetPath ?? defaultResetPath;
  }

  private readonly resetLifetimeMs: number;

  private readonly resetPath: string;

  /** Requests recovery while returning the same success result for unknown accounts. */
  async requestPasswordReset(credentialId: string) {
    const account = await resultFrom(() =>
      this.repository.findPasswordResetAccount(credentialId),
    );

    if (account.isErr) {
      return authSystemError("find_password_reset_account", account.error);
    }

    if (!account.value) {
      return ok();
    }

    return this.createAndSendAttempt(account.value);
  }

  /** Consumes a reset attempt atomically with password update and session revocation. */
  async resetPassword(token: string, password: string, passwordConfirm: string) {
    if (!isCredential(token)) {
      return invalidResetToken();
    }

    if (typeof password !== "string" || !password.trim()) {
      return authError("INVALID_PASSWORD", "비밀번호가 유효하지 않습니다.");
    }

    if (password !== passwordConfirm) {
      return authError("PASSWORD_MISMATCH", "비밀번호가 일치하지 않습니다.");
    }

    const [tokenHash, passwordHash] = await Promise.all([
      hashCredential(token),
      resultFrom(() => bcryptjs.hash(password, 12)),
    ]);

    if (tokenHash.isErr) {
      return tokenHash;
    }

    if (passwordHash.isErr) {
      return authSystemError("hash_reset_password", passwordHash.error);
    }

    const completed = await resultFrom(() => this.repository.completePasswordReset({
      tokenHash: tokenHash.value,
      passwordHash: passwordHash.value,
      now: new Date(),
    }));

    if (completed.isErr) {
      return authSystemError("complete_password_reset", completed.error);
    }

    return completed.value.status === "completed" ? ok() : invalidResetToken();
  }

  /** Removes expired or consumed recovery attempts through a maintenance operation. */
  async deleteExpiredAttempts(before = new Date()) {
    const deleted = await resultFrom(() =>
      this.repository.deleteExpiredPasswordResetAttempts(before),
    );

    return deleted.isErr
      ? authSystemError("delete_expired_password_reset_attempts", deleted.error)
      : deleted;
  }

  /** Persists a hashed credential before sending its plaintext through the side channel. */
  private async createAndSendAttempt(account: {
    credentialId: string;
    userId: string;
    email: string;
  }) {
    const token = randomCredential();
    const tokenHash = await hashCredential(token);

    if (tokenHash.isErr) {
      return tokenHash;
    }

    const expiresAt = new Date(Date.now() + this.resetLifetimeMs);
    const created = await resultFrom(() => this.repository.createPasswordResetAttempt({
      tokenHash: tokenHash.value,
      credentialId: account.credentialId,
      userId: account.userId,
      expiresAt,
    }));

    if (created.isErr) {
      return authSystemError("create_password_reset_attempt", created.error);
    }

    const sent = await resultFrom(() => this.mailer.sendPasswordReset({
      to: account.email,
      resetUrl: resetUrl(this.siteOrigin, this.resetPath, token),
      expiresAt,
    }));

    if (sent.isOk) {
      return ok();
    }

    const cleaned = await resultFrom(() =>
      this.repository.deletePasswordResetAttempt(tokenHash.value),
    );

    return authSystemError(
      "send_password_reset",
      cleaned.isErr ? { sendError: sent.error, cleanupError: cleaned.error } : sent.error,
    );
  }
}

/** Validates the configured origin before it is used in security-sensitive links. */
function assertSiteOrigin(siteOrigin: string) {
  const parsed = new URL(siteOrigin);
  const isLocalhost = ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname);
  const secure = parsed.protocol === "https:"
    || (parsed.protocol === "http:" && isLocalhost);

  if (parsed.origin !== siteOrigin || !secure) {
    throw new TypeError("Password reset siteOrigin must be an HTTPS origin or localhost origin.");
  }
}

/** Rejects cross-origin and malformed reset-page paths at composition time. */
function assertResetPath(resetPath: string) {
  if (!sameOriginPath(resetPath)) {
    throw new TypeError("Password reset path must be a same-origin relative path.");
  }
}

/** Builds a reset URL with URL encoding rather than string interpolation. */
function resetUrl(siteOrigin: string, resetPath: string, token: string) {
  const url = new URL(resetPath, siteOrigin);

  url.searchParams.set("token", token);

  return url.toString();
}

/** Returns one rejection for malformed, expired, consumed, or unknown reset credentials. */
function invalidResetToken() {
  return authError(
    "INVALID_PASSWORD_RESET_TOKEN",
    "비밀번호 재설정 정보가 유효하지 않습니다.",
  );
}

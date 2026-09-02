import bcryptjs from "bcryptjs";
import { ok, resultFrom } from "gw-result";

import { authError, authSystemError } from "../auth_error";
import type { PasswordLoginInput, PasswordSignupInput } from "./password_input";
import type { PasswordRepository } from "./password_repository";
import type { SessionAuthService } from "../session/session_auth_service";
import type { SessionUserRepository } from "../session/session_repository";

const dummyPasswordHash = "$2b$12$v2xG5utpRXRHT.ZyifQE3OPZGvEE8fEGgvqvzRf6bTz7KPry5nI2S";

/** Coordinates password authentication without owning any transport behavior. */
export class PasswordAuthService<
  TRegistrationInput = unknown,
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> {
  /** Creates the service from password, user, and session ports. */
  constructor(
    private readonly repository: PasswordRepository<TRegistrationInput, TClaims>,
    private readonly users: SessionUserRepository<TClaims>,
    private readonly sessions: SessionAuthService<TClaims>,
  ) {}

  /** Authenticates a password without revealing whether the credential exists. */
  async login({ id, password }: PasswordLoginInput) {
    if (!id || !password) {
      return invalidCredential();
    }

    const credential = await resultFrom(() => this.repository.findCredentialById(id));

    if (credential.isErr) {
      return authSystemError("find_password_credential", credential.error);
    }

    const compared = await resultFrom(() =>
      bcryptjs.compare(password, credential.value?.passwordHash ?? dummyPasswordHash),
    );

    if (compared.isErr) {
      return authSystemError("compare_password", compared.error);
    }

    if (!credential.value || !compared.value) {
      return invalidCredential();
    }

    const user = await this.findUser(credential.value.userId);

    return user.isErr ? user : this.sessions.issueTokenPair(user.value);
  }

  /** Atomically creates a password account and starts its first session. */
  async signup(input: PasswordSignupInput<TRegistrationInput>) {
    if (!input.id.trim() || !input.password.trim()) {
      return authError("INVALID_PASSWORD", "아이디와 비밀번호가 필요합니다.");
    }

    if (input.password !== input.passwordConfirm) {
      return authError("PASSWORD_MISMATCH", "비밀번호가 일치하지 않습니다.");
    }

    const hashed = await resultFrom(() => bcryptjs.hash(input.password, 12));

    if (hashed.isErr) {
      return authSystemError("hash_password", hashed.error);
    }

    const created = await resultFrom(() => this.repository.createPasswordAccount({
      credentialId: input.id,
      passwordHash: hashed.value,
      registration: input.registration,
    }));

    if (created.isErr) {
      return authSystemError("create_password_account", created.error);
    }

    if (created.value.status === "credential_exists") {
      return authError("CREDENTIAL_ALREADY_EXISTS", "이미 존재하는 계정입니다.");
    }

    return this.sessions.issueTokenPair(created.value.user);
  }

  /** Loads current user claims and preserves repository failures for observability. */
  private async findUser(userId: string) {
    const user = await resultFrom(() => this.users.findSessionUser(userId));

    if (user.isErr) {
      return authSystemError("find_authenticated_user", user.error);
    }

    return user.value
      ? ok(user.value)
      : authError("SESSION_USER_NOT_FOUND", "인증된 사용자를 찾을 수 없습니다.");
  }
}

/** Returns one indistinguishable response for unknown identifiers and wrong passwords. */
function invalidCredential() {
  return authError(
    "INVALID_CREDENTIAL",
    "아이디 또는 비밀번호가 올바르지 않습니다.",
  );
}

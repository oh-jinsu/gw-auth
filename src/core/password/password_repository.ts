import type { SessionUser } from "../session/session_repository";

/** Stored password credential returned only to the password authentication core. */
export type PasswordCredential = {
  id: string;
  passwordHash: string;
  userId: string;
};

/** Input for the repository's atomic password-account creation operation. */
export type CreatePasswordAccountParams<TRegistrationInput> = {
  credentialId: string;
  passwordHash: string;
  registration: TRegistrationInput;
};

/** Explicit expected outcomes from atomic password-account creation. */
export type CreatePasswordAccountResult<TClaims extends Record<string, unknown>> =
  | { status: "created"; user: SessionUser<TClaims> }
  | { status: "credential_exists" };

/** Account persistence required only when password authentication is enabled. */
export interface PasswordRepository<
  TRegistrationInput = unknown,
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> {
  /** Finds a password credential by its normalized external identifier. */
  findCredentialById(id: string): Promise<PasswordCredential | undefined>;

  /**
   * Atomically creates the random internal user and password credential.
   * Implementations must enforce a unique normalized credential identifier.
   */
  createPasswordAccount(
    params: CreatePasswordAccountParams<TRegistrationInput>,
  ): Promise<CreatePasswordAccountResult<TClaims>>;
}

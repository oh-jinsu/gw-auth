import type { Result } from "gw-result";

import type { AuthState } from "../jwt_payload";
import type { AuthError } from "../auth_error";

/** Stable result type returned by every public authentication operation. */
export type AuthResult<TValue = void> = Result<TValue, AuthError>;

/** Access and refresh bearer tokens returned only by mobile operations. */
export type MobileSession<TClaims extends Record<string, unknown>> = {
  accessToken: string;
  refreshToken: string;
  auth: AuthState<TClaims>;
};

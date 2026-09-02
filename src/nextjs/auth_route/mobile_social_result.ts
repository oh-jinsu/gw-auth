import type { MobileSocialLoginResult } from "gw-auth/core";

/** Converts a mobile staged-signup expiration to its JSON representation. */
export function serializeMobileSocialLogin<TClaims extends Record<string, unknown>>(
  result: MobileSocialLoginResult<TClaims>,
) {
  return result.status === "authenticated"
    ? result
    : { ...result, signupExpiresAt: result.signupExpiresAt.toISOString() };
}

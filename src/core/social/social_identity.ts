import type { Result } from "gw-result";

import type { AuthError } from "../auth_error";

/** Social providers supported by the bundled verifier adapters. */
export type SocialProvider = "apple" | "google" | "kakao" | "naver";

/** Provider-verified identity normalized before local account decisions. */
export type SocialIdentity = {
  provider: SocialProvider;
  id: string;
  email?: string;
  name?: string;
  picture?: string;
  providerRefreshToken?: string;
};

/** Verifies one provider credential and returns only normalized identity data. */
export interface SocialIdentityVerifier {
  /** Verifies a short-lived provider credential without issuing local tokens. */
  verify(credential: string): Promise<Result<SocialIdentity, AuthError>>;
}

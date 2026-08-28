import type { Result } from "gw-result";

export type SocialProvider = "google" | "kakao" | "apple";

export type SocialIdentity = {
  provider: SocialProvider;
  id: string;
  email?: string;
  name?: string;
  picture?: string;
  providerRefreshToken?: string;
};

export interface SocialIdentityVerifier {
  readonly provider: SocialProvider;

  verify(credential: string): Promise<Result<SocialIdentity, unknown>>;
}

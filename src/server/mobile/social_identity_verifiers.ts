import { exception } from "gw-result";

import type {
  SocialIdentity,
  SocialIdentityVerifier,
  SocialProvider,
} from "./social_identity";

export class SocialIdentityVerifiers {
  private readonly verifiers: Map<SocialProvider, SocialIdentityVerifier>;

  constructor(verifiers: SocialIdentityVerifier[]) {
    this.verifiers = new Map(verifiers.map((verifier) => [verifier.provider, verifier]));
  }

  verify(provider: SocialProvider, credential: string) {
    const verifier = this.verifiers.get(provider);

    return verifier
      ? verifier.verify(credential)
      : Promise.resolve(exception("UNSUPPORTED_AUTH_PROVIDER", "지원하지 않는 로그인 방식입니다."));
  }
}

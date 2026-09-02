import { fetchWithResult, ok, resultFrom } from "gw-result";

import { authError } from "../../auth_error";
import type { SocialIdentityVerifier } from "../social_identity";

/** Resolves and validates a Kakao access token through Kakao's user API. */
export class KakaoAccessTokenVerifier implements SocialIdentityVerifier {
  /** Verifies a Kakao bearer token and normalizes its user identity. */
  async verify(accessToken: string) {
    const fetched = await fetchWithResult("https://kapi.kakao.com/v2/user/me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (fetched.isErr || !fetched.value.ok) {
      return authError("KAKAO_AUTH_FAILED", "Kakao 인증에 실패했습니다.");
    }

    const parsed = await resultFrom(() => fetched.value.json());

    if (parsed.isErr || !isKakaoUser(parsed.value)) {
      return authError("KAKAO_AUTH_FAILED", "Kakao 인증에 실패했습니다.");
    }

    return ok(kakaoIdentity(parsed.value));
  }
}

/** Runtime shape used only after parsing Kakao's untrusted JSON response. */
type KakaoUser = {
  id: string | number;
  kakao_account?: {
    email?: string;
    profile?: { nickname?: string; thumbnail_image_url?: string };
  };
};

/** Validates the minimum Kakao user-response fields required for identity. */
function isKakaoUser(value: unknown): value is KakaoUser {
  return typeof value === "object" && value !== null && "id" in value
    && ["string", "number"].includes(typeof value.id);
}

/** Converts a validated Kakao response to the canonical identity contract. */
function kakaoIdentity(user: KakaoUser) {
  const account = user.kakao_account;

  return {
    provider: "kakao" as const,
    id: String(user.id),
    ...optional("email", account?.email),
    ...optional("name", account?.profile?.nickname),
    ...optional("picture", account?.profile?.thumbnail_image_url),
  };
}

/** Includes one optional non-empty Kakao profile field. */
function optional(key: string, value: string | undefined) {
  return value ? { [key]: value } : {};
}

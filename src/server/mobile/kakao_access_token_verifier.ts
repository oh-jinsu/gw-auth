import { exception, fetchWithResult, ok, resultFrom } from "gw-result";

import type { SocialIdentityVerifier } from "./social_identity";

export class KakaoAccessTokenVerifier implements SocialIdentityVerifier {
  readonly provider = "kakao" as const;

  async verify(accessToken: string) {
    const fetched = await fetchWithResult("https://kapi.kakao.com/v2/user/me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (fetched.isErr || !fetched.value.ok) {
      return exception("KAKAO_AUTH_FAILED", "카카오 인증에 실패했습니다.");
    }

    const parsed = await resultFrom(() => fetched.value.json());

    if (parsed.isErr || !isKakaoUser(parsed.value)) {
      return exception("KAKAO_AUTH_FAILED", "카카오 인증에 실패했습니다.");
    }

    return ok(kakaoIdentity(parsed.value));
  }
}

type KakaoUser = {
  id: string | number;
  kakao_account?: {
    email?: string;
    profile?: { nickname?: string; thumbnail_image_url?: string };
  };
};

function isKakaoUser(value: unknown): value is KakaoUser {
  return typeof value === "object" && value !== null && "id" in value
    && ["string", "number"].includes(typeof value.id);
}

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

function optional(key: string, value: string | undefined) {
  return value ? { [key]: value } : {};
}

import { exception, fetchWithResult } from "gw-result";
import type { AuthProvider, BaseAuthProvider } from "./auth_provider";

export class KakaoAuth implements AuthProvider {
  provider = "kakao";

  thirdpartyAuth: BaseAuthProvider;

  constructor({ thirdpartyAuth }: { thirdpartyAuth: BaseAuthProvider }) {
    this.thirdpartyAuth = thirdpartyAuth;
  }

  async login(kakaoAccessToken: string) {
    const fetchResult = await fetchWithResult(
      "https://kapi.kakao.com/v2/user/me",
      {
        headers: {
          Authorization: `Bearer ${kakaoAccessToken}`,
        },
      },
    );

    if (fetchResult.isErr) {
      return fetchResult;
    }

    const userRes = fetchResult.value;

    if (!userRes.ok) {
      return exception("KAKAO_AUTH_FAILED", "카카오 인증에 실패했습니다.");
    }

    const json = await userRes.json();

    const { id, kakao_account } = json;

    const { email, profile } = kakao_account || {};

    const { nickname, thumbnail_image_url } = profile || {};

    const payload = {
      id,
      email,
      name: nickname,
      picture: thumbnail_image_url,
    };

    return this.thirdpartyAuth.issueTokensIfUserFound("kakao", payload);
  }
}

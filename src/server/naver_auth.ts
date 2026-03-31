import { exception, fetchWithResult } from "gw-result";
import type { AuthProvider, BaseAuthProvider } from "./auth_provider";

export class NaverAuth implements AuthProvider {
  provider = "naver";

  thirdpartyAuth: BaseAuthProvider;

  constructor({ thirdpartyAuth }: { thirdpartyAuth: BaseAuthProvider }) {
    this.thirdpartyAuth = thirdpartyAuth;
  }

  async login(naverAccessToken: string) {
    const fetchResult = await fetchWithResult(
      "https://openapi.naver.com/v1/nid/me",
      {
        headers: {
          Authorization: `Bearer ${naverAccessToken}`,
        },
      },
    );

    if (fetchResult.isErr) {
      return fetchResult;
    }

    const userRes = fetchResult.value;

    if (!userRes.ok) {
      return exception("NAVER_AUTH_FAILED", "네이버 인증에 실패했습니다.");
    }

    const json = await userRes.json();

    const { id, email, nickname, profile_image } = json.response || {};

    const payload = {
      id,
      email,
      name: nickname,
      picture: profile_image,
    };

    return this.thirdpartyAuth.issueTokensIfUserFound("naver", payload);
  }
}

import { exception, fetchWithResult } from "gw-result";
import type { AuthProvider, BaseAuthProvider } from "./auth_provider";

export class GoogleAuth implements AuthProvider {
  provider = "google";

  thirdpartyAuth: BaseAuthProvider;
  googleClientId: string;
  googleClientSecret: string;
  googleRedirectUri: string;

  constructor({
    thirdpartyAuth,
    googleClientId,
    googleClientSecret,
    googleRedirectUri,
  }: {
    thirdpartyAuth: BaseAuthProvider;
    googleClientId: string;
    googleClientSecret: string;
    googleRedirectUri: string;
  }) {
    this.thirdpartyAuth = thirdpartyAuth;
    this.googleClientId = googleClientId;
    this.googleClientSecret = googleClientSecret;
    this.googleRedirectUri = googleRedirectUri;
  }

  async login(code: string) {
    // this comes from firebase web client

    const fetchResult = await fetchWithResult(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          code,
          client_id: this.googleClientId,
          client_secret: this.googleClientSecret,
          redirect_uri: this.googleRedirectUri,
          grant_type: "authorization_code",
        }),
      },
    );

    if (fetchResult.isErr) {
      return fetchResult;
    }

    const tokenRes = fetchResult.value;

    if (!tokenRes.ok) {
      return exception("GOOGLE_AUTH_FAILED", "구글 인증에 실패했습니다.");
    }

    const { access_token } = await tokenRes.json();

    const fetchUserResult = await fetchWithResult(
      "https://www.googleapis.com/oauth2/v1/userinfo",
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
      },
    );

    if (fetchUserResult.isErr) {
      return exception(
        "FETCH_GOOGLE_USER_API_FAILED",
        "구글 사용자 정보 API 호출에 실패했습니다.",
      );
    }

    const userRes = fetchUserResult.value;

    if (!userRes.ok) {
      return exception(
        "GOOGLE_USER_INFO_FAILED",
        "구글 사용자 정보를 가져오지 못했습니다.",
      );
    }

    const { id, email, name, picture } = await userRes.json();

    const payload = {
      id,
      email,
      name,
      picture,
    };

    return this.thirdpartyAuth.issueTokensIfUserFound("google", payload);
  }
}

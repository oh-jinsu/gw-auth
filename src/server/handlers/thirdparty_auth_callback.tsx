import type { AuthService } from "../auth_service";
import { UserNotFoundException, type AuthProvider } from "../auth_provider";
import { httpBadRequest, httpExceptionFromErr } from "gw-response";

export const thirdpartyAuthCallbackHandler = async (
  request: Request,
  {
    provider,
    authService,
    authProviders,
  }: {
    provider: string;
    authService: AuthService;
    authProviders: AuthProvider[];
  },
) => {
  const url = new URL(request.url);

  const code = url.searchParams.get("code");

  if (!code) {
    return httpBadRequest({
      code: "CODE_REQUIRED",
      message: "코드가 없습니다.",
    });
  }

  const authProvider = authProviders.find((p) => p.provider === provider);

  if (!authProvider) {
    return httpBadRequest({
      code: "PROVIDER_NOT_SUPPORTED",
      message: "지원하지 않는 플랫폼입니다.",
    });
  }

  const loginResult = await authProvider.login(code);

  if (loginResult.isErr) {
    if (loginResult.error instanceof UserNotFoundException) {
      const token = loginResult.error.token;

      const headers = new Headers();

      headers.append(
        "Location",
        new URL(`/signup?token=${token}`, request.url).toString(),
      );

      return new Response("Temporary Redirect", {
        status: 307,
        headers,
      });
    }

    return httpExceptionFromErr(500, loginResult);
  }

  const { accessToken, refreshToken } = loginResult.value;

  const [accessTokenSetCookie, refreshTokenSetCookie] = await Promise.all([
    authService.getAccessTokenSetCookie(accessToken),
    authService.getRefreshTokenSetCookie(refreshToken),
  ]);

  const headers = new Headers();

  headers.append("Set-Cookie", accessTokenSetCookie);
  headers.append("Set-Cookie", refreshTokenSetCookie);

  const redirectUrl = url.searchParams.get("state") || "/";

  headers.append(
    "Location",
    new URL(
      `/r?redirectUrl=${encodeURIComponent(redirectUrl)}`,
      request.url,
    ).toString(),
  );

  return new Response("Temporary Redirect", {
    status: 307,
    headers,
  });
};

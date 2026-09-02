import { httpBadRequest, httpCreated, httpExceptionFromErr } from "gw-response";
import type { AuthService } from "../auth_service";

export const refreshHandler = async (
  request: Request,
  {
    authService,
  }: {
    authService: AuthService;
  },
) => {
  const refreshToken =
    request?.headers.get("Authorization")?.replace("Bearer ", "") ||
    (await authService.getRefreshTokenFromCookies(request));

  if (!refreshToken) {
    return httpBadRequest({
      code: "REFRESH_TOKEN_REQUIRED",
      message: "리프레시 토큰이 없습니다.",
    });
  }

  const refreshResult = await authService.refreshTokenPair(refreshToken);

  if (refreshResult.isErr) {
    return httpExceptionFromErr(401, refreshResult);
  }

  const { accessToken, refreshToken: nextRefreshToken } = refreshResult.value;
  const headers = new Headers();
  const cookies = await Promise.all([
    authService.getAccessTokenSetCookie(accessToken),
    authService.getRefreshTokenSetCookie(nextRefreshToken),
  ]);

  cookies.forEach((cookie) => headers.append("Set-Cookie", cookie));

  return httpCreated(
    { accessToken, refreshToken: nextRefreshToken },
    { headers },
  );
};

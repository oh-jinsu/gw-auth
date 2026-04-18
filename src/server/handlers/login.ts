import { httpCreated, httpExceptionFromErr } from "gw-response";
import type { AuthService } from "../auth_service";

export const loginHandler = async (
  request: Request,
  {
    authService,
  }: {
    authService: AuthService;
  },
) => {
  const { id, password } = await request.json();

  const result = await authService.login({
    id,
    password,
  });

  if (result.isErr) {
    return httpExceptionFromErr(500, result);
  }

  const { accessToken, refreshToken } = result.value;

  const [accessTokenSetCookie, refreshTokenSetCookie] = await Promise.all([
    authService.getAccessTokenSetCookie(accessToken),
    authService.getRefreshTokenSetCookie(refreshToken),
  ]);

  const headers = new Headers();

  headers.append("Set-Cookie", accessTokenSetCookie);
  headers.append("Set-Cookie", refreshTokenSetCookie);

  return httpCreated(
    { accessToken, refreshToken },
    {
      headers,
    },
  );
};

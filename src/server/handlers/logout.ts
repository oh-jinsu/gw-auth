import type { AuthService } from "../auth_service";
import { httpNoContent } from "gw-response";

export const logoutHandler = async (
  request: Request,
  { authService }: { authService: AuthService },
) => {
  const refreshToken =
    (await authService.getRefreshTokenFromCookies(request)) ||
    request.headers.get("Authorization")?.replace("Bearer ", "");

  if (refreshToken) {
    await authService.revokeSession(refreshToken);
  }

  const headers = new Headers();

  const cookies = await Promise.all([
    authService.getAccessTokenSetCookie(undefined),
    authService.getRefreshTokenSetCookie(undefined),
  ]);

  cookies.forEach((cookie) => headers.append("Set-Cookie", cookie));

  return httpNoContent({ headers });
};

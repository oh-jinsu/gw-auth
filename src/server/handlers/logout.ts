import type { AuthService } from "../auth_service";
import type { AccessTokenPayload } from "../../jwt_payload";
import { httpNoContent } from "gw-response";

export const logoutHandler =
  ({ authService }: { authService: AuthService }) =>
  (auth: AccessTokenPayload | undefined) =>
  async (request: Request) => {
    await authService.authRepository.updateUserRefreshToken(
      auth?.userId as string,
      null,
    );

    const headers = new Headers();

    const [accessTokenSetCookie, refreshTokenSetCookie] = await Promise.all([
      authService.getAccessTokenSetCookie(undefined),
      authService.getRefreshTokenSetCookie(undefined),
    ]);

    headers.append("Set-Cookie", accessTokenSetCookie);
    headers.append("Set-Cookie", refreshTokenSetCookie);

    return httpNoContent({
      headers,
    });
  };

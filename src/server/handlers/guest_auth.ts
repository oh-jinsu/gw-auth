import { v5 } from "uuid";
import type { AuthService } from "../auth_service";
import {
  httpBadRequest,
  httpCreated,
  httpExceptionFromErr,
  httpInternalServerError,
} from "gw-response";

export const guestAuthHandler =
  ({ authService }: { authService: AuthService }) =>
  async (request: Request) => {
    const { deviceId } = await request.json();

    if (!deviceId) {
      return httpBadRequest({
        code: "DEVICE_ID_REQUIRED",
        message: "디바이스 ID가 필요합니다.",
      });
    }

    const userId = v5(deviceId, v5.DNS);

    let user = await authService.authRepository.findUserById(userId);

    if (!user) {
      user = await authService.authRepository.createUser({
        id: userId,
        name: "게스트",
        role: "guest",
      });
    }

    if (!user) {
      return httpInternalServerError({
        code: "INTERNAL_SERVER_ERROR",
        message: "알 수 없는 오류가 발생했습니다.",
      });
    }

    const issueResult = await authService.issueTokenPair(user);

    if (issueResult.isErr) {
      return httpExceptionFromErr(500, issueResult);
    }

    const { accessToken, refreshToken } = issueResult.value;

    return httpCreated({ accessToken, refreshToken });
  };

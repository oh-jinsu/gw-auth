import { httpBadRequest, httpOk } from "gw-response";
import type { AccessTokenPayload } from "../../jwt_payload";

export const findAuthHandler =
  (auth: AccessTokenPayload | undefined) => async () => {
    if (!auth) {
      return httpBadRequest({
        code: "AUTH_NOT_FOUND",
        message: "인증 정보를 찾을 수 없습니다.",
      });
    }

    return httpOk(auth);
  };

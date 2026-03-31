import { httpBadRequest, httpCreated, httpExceptionFromErr } from "gw-response";
import type { AuthProvider } from "../auth_provider";

export const loginWithThirdPartyHandler = async (
  request: Request,
  {
    provider,
    authProviders,
  }: {
    provider: string;
    authProviders: AuthProvider[];
  },
) => {
  const { code } = await request.json();

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

  const result = await authProvider.login(code);

  if (result.isErr) {
    return httpExceptionFromErr(500, result);
  }

  return httpCreated({
    accessToken: result.value.accessToken,
    refreshToken: result.value.refreshToken,
  });
};

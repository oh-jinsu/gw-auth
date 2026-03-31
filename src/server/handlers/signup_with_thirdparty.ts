import type { AuthService } from "../auth_service";
import type { FileService } from "gw-file/server";
import type { JWTManager } from "../jwt_manager";
import type { ThirdpartyAuthPayload } from "../auth_provider";
import { signupWithThirdparty } from "../signup_with_thirdparty";
import { httpCreated, httpExceptionFromErr } from "gw-response";

export const signUpWithThirdpartyHandler = async <TFile>(
  request: Request,
  {
    authService,
    fileService,
    signupTokenManager,
  }: {
    authService: AuthService<TFile>;
    fileService: FileService<TFile>;
    signupTokenManager: JWTManager<ThirdpartyAuthPayload>;
  },
) => {
  const { token } = await request.json();

  const result = await signupWithThirdparty({
    signupTokenManager,
    authService,
    fileService,
  })(token);

  if (result.isErr) {
    return httpExceptionFromErr(500, result);
  }

  return httpCreated(result.value);
};

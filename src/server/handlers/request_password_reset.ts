import { httpCreated, httpExceptionFromErr } from "gw-response";
import type { PasswordRecoveryService } from "../password_recovery";

export const requestPasswordResetHandler = async (
  request: Request,
  {
    passwordRecoveryService,
  }: {
    passwordRecoveryService: PasswordRecoveryService;
  },
) => {
  const { email } = await request.json();

  const result = await passwordRecoveryService.requestPasswordReset(email);

  if (result.isErr) {
    return httpExceptionFromErr(500, result);
  }

  return httpCreated({
    message: "비밀번호 재설정 이메일을 전송했습니다.",
  });
};

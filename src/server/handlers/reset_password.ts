import { httpExceptionFromErr, httpNoContent } from "gw-response";
import type { PasswordRecoveryService } from "../password_recovery";

export const resetPasswordHandler = async (
  request: Request,
  {
    passwordRecoveryService,
  }: {
    passwordRecoveryService: PasswordRecoveryService;
  },
) => {
  const { token, password, passwordConfirm } = await request.json();

  const result = await passwordRecoveryService.resetPassword(
    token,
    password,
    passwordConfirm,
  );

  if (result.isErr) {
    return httpExceptionFromErr(500, result);
  }

  return httpNoContent();
};

import { v5 } from "uuid";
import * as bcrypt from "bcryptjs";
import type { AuthService } from "../auth_service";
import type { FileRepository } from "gw-file/server";
import {
  httpBadRequest,
  httpConflict,
  httpCreated,
  httpException,
  httpExceptionFromErr,
  httpResponse,
} from "gw-response";

export const signupHandler = async <TFile>(
  request: Request,
  {
    authService,
    fileRepository,
  }: {
    authService: AuthService<TFile>;
    fileRepository: FileRepository<TFile>;
  },
) => {
  const body = await request.json();

  const { email, password, passwordConfirm, name, profileImageId } = body;

  if (!email) {
    return httpBadRequest({
      code: "EMAIL_REQUIRED",
      message: "이메일을 입력해주세요.",
    });
  }

  if (!password) {
    return httpBadRequest({
      code: "PASSWORD_REQUIRED",
      message: "비밀번호를 입력해주세요.",
    });
  }

  if (!passwordConfirm) {
    return httpBadRequest({
      code: "PASSWORD_CONFIRM_REQUIRED",
      message: "비밀번호 확인을 입력해주세요.",
    });
  }

  const existing = await authService.authRepository.findCredentialById(email);

  if (existing) {
    return httpConflict({
      code: "EMAIL_ALREADY_EXISTS",
      message: "이미 가입한 이메일입니다.",
    });
  }

  if (password !== passwordConfirm) {
    return httpBadRequest({
      code: "PASSWORD_MISMATCH",
      message: "비밀번호가 일치하지 않습니다.",
    });
  }

  const profileImage = profileImageId
    ? await fileRepository.findFileById(profileImageId)
    : undefined;

  const userId = v5(email, v5.DNS);

  const user = await authService.authRepository.createUser({
    id: userId,
    name,
    role: "user",
    email,
    profileImage,
  });

  await authService.authRepository.createCredential({
    id: email,
    userId,
    password: bcrypt.hashSync(password, 10),
  });

  const issueResult = await authService.issueTokenPair(user);

  if (issueResult.isErr) {
    return httpExceptionFromErr(500, issueResult);
  }

  const { accessToken, refreshToken } = issueResult.value;

  const contentType = request.headers.get("Content-Type") || "";

  if (contentType.includes("application/json")) {
    return httpCreated({ accessToken, refreshToken });
  }

  const [accessTokenSetCookie, refreshTokenSetCookie] = await Promise.all([
    authService.getAccessTokenSetCookie(accessToken),
    authService.getRefreshTokenSetCookie(refreshToken),
  ]);

  const payload = authService.accessTokenManager.decode(accessToken);

  const headers = new Headers();

  headers.append("Set-Cookie", accessTokenSetCookie);
  headers.append("Set-Cookie", refreshTokenSetCookie);

  return httpCreated(payload, {
    headers,
  });
};

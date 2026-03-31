import { v5 } from "uuid";
import type { AuthService, JWTManager, ThirdpartyAuthPayload } from ".";
import type { FileService } from "gw-file/server";
import { exception, fetchWithResult, ok } from "gw-result";

export function signupWithThirdparty<TFile = unknown>({
  signupTokenManager,
  authService,
  fileService,
}: {
  signupTokenManager: JWTManager<ThirdpartyAuthPayload>;
  authService: AuthService<TFile>;
  fileService: FileService<TFile>;
}) {
  return async (token: string) => {
    const verifyResult = await signupTokenManager.verify(token);

    if (verifyResult.isErr) {
      return verifyResult;
    }

    const payload = verifyResult.value;

    if (!payload) {
      return exception(
        "INVALID_SIGNUP_TOKEN",
        "가입 인증이 유효하지 않습니다.",
      );
    }

    const { provider, id: thirdpartyId, email, name, picture } = payload;

    const existing = await authService.authRepository.findThirdPartyAuth(
      provider,
      thirdpartyId,
    );

    if (existing) {
      return exception("USER_ALREADY_EXISTS", "이미 가입된 사용자입니다.");
    }

    const userId = v5(thirdpartyId, v5.DNS);

    const uploadProfileImage = async () => {
      if (!picture) {
        return ok(undefined);
      }

      const fetchResult = await fetchWithResult(picture);

      if (fetchResult.isErr) {
        return fetchResult;
      }

      const response = fetchResult.value;

      if (!response.ok) {
        return exception(
          "PICTURE_FETCH_FAILED",
          "프로필 사진을 가져오는데 실패했습니다.",
        );
      }

      const arrayBuffer = await response.arrayBuffer();

      const file = await fileService.put(Buffer.from(arrayBuffer), {
        name: "profile.jpg",
        type: "image/jpeg",
        size: arrayBuffer.byteLength,
      });

      return file;
    };

    const profileImageResult = await uploadProfileImage();

    if (profileImageResult.isErr) {
      return profileImageResult;
    }

    const profileImage = profileImageResult.value;

    const user = await authService.authRepository.createUser({
      id: userId,
      name: name,
      role: "user",
      email,
      profileImage,
    });

    await authService.authRepository.createThirdPartyAuth({
      id: thirdpartyId,
      provider,
      userId,
    });

    return authService.issueTokenPair(user);
  };
}

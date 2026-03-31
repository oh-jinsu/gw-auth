import bcryptjs from "bcryptjs";
import { JWTManager } from "./jwt_manager";
import type { AuthRepository } from "./auth_repository";
import { CookieManager } from "./cookie_manager";
import type { AccessTokenPayload, RefreshTokenPayload } from "../jwt_payload";
import { exception, ok, resultFrom } from "gw-result";

export class AuthService<TFile = unknown> {
  authRepository: AuthRepository<TFile>;
  accessTokenManager: JWTManager<AccessTokenPayload>;
  accessTokenCookieManager: CookieManager;
  refreshTokenManager: JWTManager<RefreshTokenPayload>;
  refreshTokenCookieManager: CookieManager;

  constructor({
    authRepository,
    accessTokenManager,
    accessTokenCookieStore,
    refreshTokenManager,
    refreshTokenCookieStore,
  }: {
    authRepository: AuthRepository<TFile>;
    accessTokenManager: JWTManager<AccessTokenPayload>;
    accessTokenCookieStore: CookieManager;
    refreshTokenManager: JWTManager<RefreshTokenPayload>;
    refreshTokenCookieStore: CookieManager;
  }) {
    this.authRepository = authRepository;
    this.accessTokenManager = accessTokenManager;
    this.accessTokenCookieManager = accessTokenCookieStore;
    this.refreshTokenManager = refreshTokenManager;
    this.refreshTokenCookieManager = refreshTokenCookieStore;
  }

  async verify(request: Request) {
    const accessToken = await this.getAccessTokenFromRequest(request);

    if (accessToken) {
      return this.accessTokenManager.verify(accessToken);
    }
  }

  async getAccessTokenFromRequest(request: Request) {
    if (request.headers.get("Authorization")) {
      return request.headers.get("Authorization")?.replace("Bearer ", "");
    }

    return this.getAccessTokenFromCookies(request);
  }

  async getAccessTokenFromCookies(request: Request) {
    const accessToken =
      await this.accessTokenCookieManager.parseFromRequest(request);

    return accessToken;
  }

  async getRefreshTokenFromCookies(request: Request) {
    const refreshToken =
      await this.refreshTokenCookieManager.parseFromRequest(request);

    return refreshToken;
  }

  async login({ id, password }: { id: string; password: string }) {
    const credential = await this.authRepository.findCredentialById(id);

    if (!credential) {
      return exception("CREDENTIAL_NOT_FOUND", "계정이 존재하지 않습니다.");
    }

    if (!(await bcryptjs.compare(password, credential.password))) {
      return exception(
        "INVALID_CREDENTIAL",
        "아이디 또는 비밀번호가 올바르지 않습니다.",
      );
    }

    const user = await this.authRepository.findUserById(credential.userId);

    if (!user) {
      return exception("USER_NOT_FOUND", "사용자를 찾을 수 없습니다.");
    }

    return await this.issueTokenPair(user);
  }

  async issueAccessToken(user: { id: string; role: string; name: string }) {
    return this.accessTokenManager.sign({
      userId: user.id,
      role: user.role,
      name: user.name,
    });
  }

  async issueTokenPair(user: { id: string; role: string; name: string }) {
    const signingResult = await this.refreshTokenManager.sign({
      userId: user.id,
      role: user.role,
      name: user.name,
    });

    if (signingResult.isErr) {
      return signingResult;
    }

    const refreshToken = signingResult.value;

    const hashedRefreshToken = bcryptjs.hashSync(refreshToken, 10);

    const updateResult = await resultFrom(() =>
      this.authRepository.updateUserRefreshToken(user.id, hashedRefreshToken),
    );

    if (updateResult.isErr) {
      return updateResult;
    }

    const accessTokenResult = await this.issueAccessToken(user);

    if (accessTokenResult.isErr) {
      return accessTokenResult;
    }

    const accessToken = accessTokenResult.value;

    return ok({ refreshToken, accessToken });
  }

  async refreshAccessToken(refreshToken: string) {
    const verifyResult = await this.refreshTokenManager.verify(refreshToken);

    if (verifyResult.isErr) {
      return verifyResult;
    }

    const payload = verifyResult.value;

    const { userId } = payload;

    if (typeof userId !== "string") {
      return exception("INVALID_TOKEN", "토큰이 유효하지 않습니다.");
    }

    const user = await this.authRepository.findUserById(userId);

    if (!user) {
      return exception("USER_NOT_FOUND", "사용자를 찾을 수 없습니다.");
    }

    if (!user.refreshToken) {
      return exception(
        "REFRESH_TOKEN_NOT_FOUND",
        "인증 정보가 존재하지 않습니다.",
      );
    }

    if (!(await bcryptjs.compare(refreshToken, user.refreshToken))) {
      return exception(
        "INVALID_REFRESH_TOKEN",
        "인증 정보가 유효하지 않습니다.",
      );
    }

    return this.issueAccessToken(user);
  }

  async getAccessTokenSetCookie(accessToken: string | undefined) {
    return this.accessTokenCookieManager.serialize(accessToken, {
      expires: accessToken
        ? JWTManager.getExpirationTime(accessToken)
        : new Date(0),
    });
  }

  async getRefreshTokenSetCookie(refreshToken: string | undefined) {
    return this.refreshTokenCookieManager.serialize(refreshToken, {
      expires: refreshToken
        ? JWTManager.getExpirationTime(refreshToken)
        : new Date(0),
    });
  }
}

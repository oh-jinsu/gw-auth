import bcryptjs from "bcryptjs";
import { JWTManager } from "./jwt_manager";
import type { AuthRepository } from "./auth_repository";
import { CookieManager } from "./cookie_manager";
import { exception } from "gw-result";
import { SessionAuthService } from "./session/session_auth_service";
import type { SessionAccessPayload, SessionRefreshPayload } from "./session/session_payload";
import type { SessionRepository } from "./session/session_repository";

export class AuthService<TFile = unknown> {
  authRepository: AuthRepository<TFile>;
  accessTokenManager: JWTManager<SessionAccessPayload>;
  accessTokenCookieManager: CookieManager;
  refreshTokenManager: JWTManager<SessionRefreshPayload>;
  refreshTokenCookieManager: CookieManager;
  sessionAuthService: SessionAuthService;

  constructor({
    authRepository,
    accessTokenManager,
    accessTokenCookieStore,
    refreshTokenManager,
    refreshTokenCookieStore,
    sessionRepository,
  }: {
    authRepository: AuthRepository<TFile>;
    accessTokenManager: JWTManager<SessionAccessPayload>;
    accessTokenCookieStore: CookieManager;
    refreshTokenManager: JWTManager<SessionRefreshPayload>;
    refreshTokenCookieStore: CookieManager;
    sessionRepository: SessionRepository;
  }) {
    this.authRepository = authRepository;
    this.accessTokenManager = accessTokenManager;
    this.accessTokenCookieManager = accessTokenCookieStore;
    this.refreshTokenManager = refreshTokenManager;
    this.refreshTokenCookieManager = refreshTokenCookieStore;
    this.sessionAuthService = new SessionAuthService(
      sessionRepository,
      accessTokenManager,
      refreshTokenManager,
    );
  }

  async verify(request: Request) {
    const accessToken = await this.getAccessTokenFromRequest(request);

    if (!accessToken) {
      return exception(
        "ACCESS_TOKEN_NOT_FOUND",
        "액세스 토큰이 존재하지 않습니다.",
      );
    }

    return this.accessTokenManager.verify(accessToken);
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
    return this.sessionAuthService.issueTokenPair(user);
  }

  refreshTokenPair(refreshToken: string) {
    return this.sessionAuthService.refreshTokenPair(refreshToken);
  }

  revokeSession(refreshToken: string) {
    return this.sessionAuthService.revokeSession(refreshToken);
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

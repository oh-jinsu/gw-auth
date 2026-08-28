import { err, Exception, exception, ok, type Result } from "gw-result";
import type { AuthService, JWTManager } from ".";

export class UserNotFoundException<
  TCode extends string = string,
> extends Exception<TCode> {
  token: string;

  constructor(exception: Exception<TCode>, token: string) {
    super(exception.code, exception.message);

    this.token = token;
  }
}

export interface AuthProvider {
  provider: string;
  login(code: string): Promise<
    Result<
      {
        accessToken: string;
        refreshToken: string;
      },
      unknown
    >
  >;
}

export type ThirdpartyAuthPayload = {
  provider: string;
  id: string;
  email?: string;
  name?: string;
  picture?: string;
};

export class BaseAuthProvider {
  authService: AuthService;
  signupTokenManager: JWTManager<ThirdpartyAuthPayload>;

  constructor({
    authService,
    signupTokenManager,
  }: {
    authService: AuthService;
    signupTokenManager: JWTManager<ThirdpartyAuthPayload>;
  }) {
    this.authService = authService;
    this.signupTokenManager = signupTokenManager;
  }

  async generateSignupToken(
    provider: string,
    payload: Omit<ThirdpartyAuthPayload, "provider">,
  ) {
    return this.signupTokenManager.sign({
      ...payload,
      provider,
    });
  }

  async issueTokensIfUserFound(
    provider: string,
    payload: Omit<ThirdpartyAuthPayload, "provider">,
  ) {
    const userResult = await this.findUser(provider, payload);

    if (userResult.isErr) {
      const tokenResult = await this.generateSignupToken(provider, payload);

      if (tokenResult.isErr) {
        return tokenResult;
      }

      const token = tokenResult.value;

      return err(new UserNotFoundException(userResult.error, token));
    }

    const user = userResult.value;

    const issueResult = await this.authService.issueTokenPair(user);

    if (issueResult.isErr) {
      return issueResult;
    }

    const { accessToken, refreshToken } = issueResult.value;

    return ok({
      user,
      accessToken,
      refreshToken,
    });
  }

  async findUser(
    provider: string,
    info: Omit<ThirdpartyAuthPayload, "provider">,
  ) {
    const auth = await this.authService.authRepository.findThirdPartyAuth(
      provider,
      info.id,
    );

    if (!auth) {
      return exception("AUTH_NOT_FOUND", "인증 정보를 찾을 수 없습니다.");
    }

    const user = await this.authService.authRepository.findUserById(
      auth.userId,
    );

    if (!user) {
      return exception("USER_NOT_FOUND", "사용자를 찾을 수 없습니다.");
    }

    return ok(user);
  }
}

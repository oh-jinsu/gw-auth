import { createContext, useContext, type ReactNode } from "react";
import type { AccessTokenPayload } from "../jwt_payload";
import {
  Exception,
  exception,
  exceptionFromResponse,
  fetchWithResult,
  ok,
  type Result,
} from "gw-result";

export type AuthContextValue = {
  auth: AccessTokenPayload | undefined;
  isLoggedIn: () => boolean;
  login: (
    id: string,
    password: string,
  ) => Promise<Result<AccessTokenPayload, Exception | Error>>;
  loginWithGoogle: (
    redirectUrl?: string,
  ) => Promise<Result<void, Exception | Error>>;
  logout: () => Promise<Result<void, Exception | Error>>;
  signup: (
    email: string,
    password: string,
    passwordConfirm: string,
  ) => Promise<Result<AccessTokenPayload, Exception | Error>>;
  requestResetPassword: (
    email: string,
  ) => Promise<Result<void, Exception | Error>>;
  resetPassword: (
    token: string,
    password: string,
    passwordConfirm: string,
  ) => Promise<Result<void, Exception | Error>>;
};

export const AuthContext = createContext<AuthContextValue>({} as any);

export const useAuth = () => {
  return useContext(AuthContext);
};

export function AuthProvider({
  auth,
  children,
  googleAuth,
}: {
  auth?: AccessTokenPayload;
  children: ReactNode;
  googleAuth?: {
    googleClientId: string;
    googleRedirectUrl: string;
  };
}) {
  const login = async (id: string, password: string) => {
    const fetchResult = await fetchWithResult("/api/auth/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ id, password }),
    });

    if (fetchResult.isErr) {
      return fetchResult;
    }

    const res = fetchResult.value;

    if (!res.ok) {
      return exceptionFromResponse(res);
    }

    const payload = await res.json();

    return ok(payload as AccessTokenPayload);
  };

  const loginWithGoogle = async (redirectUrl = "/") => {
    if (!googleAuth) {
      return exception(
        "GOOGLE_AUTH_NOT_CONFIGURED",
        "구글 인증이 설정되지 않았습니다.",
      );
    }

    const { googleClientId, googleRedirectUrl } = googleAuth;

    const href = new URL("https://accounts.google.com/o/oauth2/v2/auth");

    href.searchParams.append("client_id", googleClientId);

    href.searchParams.append("redirect_uri", googleRedirectUrl);

    href.searchParams.append("response_type", "code");

    href.searchParams.append("scope", "email profile");

    href.searchParams.append("state", redirectUrl);

    window.location.href = href.toString();

    return ok();
  };

  const logout = async () => {
    const sure = confirm("정말 로그아웃 하시겠습니까?");

    if (!sure) {
      return ok();
    }

    const fetchResult = await fetchWithResult("/api/auth/logout", {
      method: "POST",
    });

    if (fetchResult.isErr) {
      return fetchResult;
    }

    const res = fetchResult.value;

    if (!res.ok) {
      return exceptionFromResponse(res);
    }

    return ok();
  };

  const signup = async (
    email: string,
    password: string,
    passwordConfirm: string,
  ) => {
    const fetchResult = await fetchWithResult("/api/auth/signup", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password, passwordConfirm }),
    });

    if (fetchResult.isErr) {
      return fetchResult;
    }

    const res = fetchResult.value;

    if (!res.ok) {
      return exceptionFromResponse(res);
    }

    return ok(await res.json());
  };

  const requestResetPassword = async (email: string) => {
    const fetchResult = await fetchWithResult(
      "/api/auth/request-password-reset",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email }),
      },
    );

    if (fetchResult.isErr) {
      return fetchResult;
    }

    const res = fetchResult.value;

    if (!res.ok) {
      return exceptionFromResponse(res);
    }

    return ok();
  };

  const resetPassword = async (
    token: string,
    password: string,
    passwordConfirm: string,
  ) => {
    const fetchResult = await fetchWithResult("/api/auth/reset-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ token, password, passwordConfirm }),
    });

    if (fetchResult.isErr) {
      return fetchResult;
    }

    const res = fetchResult.value;

    if (!res.ok) {
      return exceptionFromResponse(res);
    }

    return ok();
  };

  const isLoggedIn = () => {
    return !!auth && auth.role !== "guest";
  };

  const authContextValue: AuthContextValue = {
    auth,
    isLoggedIn,
    login,
    logout,
    loginWithGoogle,
    signup,
    requestResetPassword,
    resetPassword,
  };

  return (
    <AuthContext.Provider value={authContextValue}>
      {children}
    </AuthContext.Provider>
  );
}

"use client";

import type { PropsWithChildren } from "react";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

import type { AuthResult, AuthState } from "gw-auth/core";
import { authRequest } from "./auth_request";

/** Authentication state and route-agnostic client operations exposed to React. */
export type AuthContextValue<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> = {
  /** Current browser-safe auth state, if an access session is active. */
  auth?: AuthState<TClaims>;

  /** Whether any password, social, or guest session is currently authenticated. */
  isAuthenticated: boolean;

  /** Calls an application route that returns authenticated browser state. */
  authenticate(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<AuthResult<AuthState<TClaims>>>;

  /** Calls an application logout route and clears confirmed local state. */
  logout(input: RequestInfo | URL, init?: RequestInit): Promise<AuthResult>;
};

/** Initial server-resolved authentication state supplied to `AuthProvider`. */
export type AuthProviderProps<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> = PropsWithChildren<{
  initialAuth?: AuthState<TClaims>;
}>;

type DefaultAuthContext = AuthContextValue<Record<string, unknown>>;

const AuthContext = createContext<DefaultAuthContext | undefined>(undefined);

const unconfirmedLogoutCodes = new Set([
  "AUTH_NETWORK_FAILURE",
  "INVALID_AUTH_RESPONSE",
]);

/** Provides reactive auth state without owning application route names. */
export function AuthProvider<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
>({ initialAuth, children }: AuthProviderProps<TClaims>) {
  const value = useAuthValue(initialAuth);

  return (
    <AuthContext.Provider value={value as DefaultAuthContext}>
      {children}
    </AuthContext.Provider>
  );
}

/** Reads the nearest typed authentication context. */
export function useAuth<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
>() {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used within AuthProvider.");
  }

  return context as AuthContextValue<TClaims>;
}

/** Creates the context value and synchronizes Server Component auth changes. */
function useAuthValue<TClaims extends Record<string, unknown>>(
  initialAuth?: AuthState<TClaims>,
): AuthContextValue<TClaims> {
  const [auth, setAuth] = useState(initialAuth);

  useEffect(() => setAuth(initialAuth), [initialAuth]);

  const authenticate = useAuthenticate(setAuth);
  const logout = useLogout(setAuth);

  return useMemo(() => ({
    auth,
    isAuthenticated: auth !== undefined,
    authenticate,
    logout,
  }), [auth, authenticate, logout]);
}

/** Creates an authentication request that updates state only on success. */
function useAuthenticate<TClaims extends Record<string, unknown>>(
  setAuth: (auth?: AuthState<TClaims>) => void,
) {
  return useCallback(async (input: RequestInfo | URL, init?: RequestInit) => {
    const result = await authRequest<AuthState<TClaims>>(input, init);

    if (result.isOk) {
      setAuth(result.value);
    }

    return result;
  }, [setAuth]);
}

/** Clears local state whenever the server was reached and processed logout. */
function useLogout<TClaims extends Record<string, unknown>>(
  setAuth: (auth?: AuthState<TClaims>) => void,
) {
  return useCallback(async (input: RequestInfo | URL, init?: RequestInit) => {
    const result = await authRequest(input, init);

    if (result.isOk || !unconfirmedLogoutCodes.has(result.error.code)) {
      setAuth(undefined);
    }

    return result;
  }, [setAuth]);
}

# gw-auth

A small TypeScript authentication toolkit for apps that use the Web
`Request`/`Response` API on the server and React on the client.

`gw-auth` provides:

- JWT signing and verification helpers
- Cookie helpers for access and refresh tokens
- A repository-driven auth service
- Reusable HTTP handlers for login, logout, signup, refresh, password reset,
  guest auth, and third-party auth
- OAuth provider adapters for Google, Kakao, Naver, and Apple
- A React auth context/provider for client-side auth actions

## Install

```sh
npm install gw-auth
```

React is a peer dependency for the client package:

```sh
npm install react react-dom
```

## Exports

```ts
import type { AccessTokenPayload, RefreshTokenPayload } from "gw-auth";

import {
  AuthService,
  JWTManager,
  CookieManager,
  loginHandler,
} from "gw-auth/server";

import { AuthProvider, useAuth } from "gw-auth/client";
```

## Core Concepts

`gw-auth` does not own your database. Instead, you provide an
`AuthRepository` implementation that knows how to find and create users,
credentials, third-party auth records, and refresh tokens.

The server service issues:

- an access token for short-lived authentication
- a refresh token stored as a bcrypt hash in your user record
- optional `Set-Cookie` headers for browser-based sessions

The exported handlers are framework-agnostic functions built around standard
Web `Request` and `Response` objects, so they fit route handlers in frameworks
such as Next.js, Remix, Hono, and similar runtimes.

## Recommended Mobile Session Architecture (0.2+)

Mobile apps should use `SessionAuthService` rather than storing a third-party
Google, Kakao, or Apple token as the application's bearer token. The provider
credential is exchanged once, then the application issues its own short-lived
access token and rotating refresh token.

```ts
import {
  JWTManager,
  SessionAuthService,
  type SessionAccessPayload,
  type SessionRefreshPayload,
  type SessionRepository,
} from "gw-auth/server";

const accessTokens = new JWTManager<SessionAccessPayload>({
  secret: process.env.ACCESS_TOKEN_SECRET!,
  expiresIn: "30m",
  issuer: "my-app",
});

const refreshTokens = new JWTManager<SessionRefreshPayload>({
  secret: process.env.REFRESH_TOKEN_SECRET!,
  expiresIn: "30d",
  issuer: "my-app",
});

export const sessions = new SessionAuthService(
  sessionRepository satisfies SessionRepository,
  accessTokens,
  refreshTokens,
);
```

The repository stores one row per device session. Its
`rotateRefreshSession` implementation must update only when both the session
id and `expectedTokenHash` match, and return `false` otherwise. This
compare-and-swap rule makes concurrent replay of an already rotated token fail.

The 0.2 session service guarantees these invariants:

- refresh tokens contain a new JWT `jti` on every issue and rotation
- the complete refresh token is stored as a SHA-256 hash, never plaintext
- a refresh operation rotates both tokens and invalidates the previous refresh token
- logout can revoke one device session; account deletion can revoke every session
- configured JWT issuers are checked during verification, not only written during signing

Refresh tokens are high-entropy signed credentials, so SHA-256 is intentional.
Password hashes should still use a slow password hashing function. bcrypt is
not used for refresh tokens because it only considers the first 72 input bytes,
which is unsafe for comparing long JWTs that share a prefix.

### Native Social Credential Verification

Use the mobile verifiers for a one-time provider exchange:

```ts
import {
  AppleAuthorizationCodeVerifier,
  GoogleIdTokenVerifier,
  KakaoAccessTokenVerifier,
  SocialIdentityVerifiers,
} from "gw-auth/server";

const social = new SocialIdentityVerifiers([
  new GoogleIdTokenVerifier(googleClientIds),
  new KakaoAccessTokenVerifier(),
  new AppleAuthorizationCodeVerifier(appleOptions),
]);

const identity = await social.verify(provider, credential);
```

Google verifies the ID-token signature, issuer, and audience. Kakao resolves
the access token through Kakao's user API. Apple exchanges the native
authorization code server-side, verifies the returned identity-token signature,
and returns the provider refresh token needed for account-deletion revocation.
Store that Apple refresh token encrypted at rest in the consuming application.

See [MIGRATION.md](./MIGRATION.md) for the 0.1 to 0.2 migration boundary.

## Legacy Single-Session Repository Interface

`AuthService` remains available for existing browser and cookie integrations.
It stores one refresh-token hash on the user row, so a new login replaces any
previous login. New mobile integrations should use `SessionAuthService`.

Implement this interface against your database:

```ts
import type { AuthRepository } from "gw-auth/server";

export const authRepository: AuthRepository = {
  async findCredentialById(id) {
    // Return { id, password, userId } or undefined.
  },

  async createCredential({ id, password, userId }) {
    // Store a login credential. Password is already hashed by signupHandler.
  },

  async updatePassword(id, hashedPassword) {
    // Replace the credential password hash.
  },

  async findUserById(userId) {
    // Return { id, role, name, refreshToken } or undefined.
  },

  async updateUserRefreshToken(userId, hashedRefreshToken) {
    // Store the hashed refresh token, or null on logout.
  },

  async createUser(userData) {
    // Create and return { id, role, name, refreshToken }.
  },

  async findThirdPartyAuth(provider, providerId) {
    // Return { userId } or undefined.
  },

  async createThirdPartyAuth({ id, provider, userId }) {
    // Link a provider account to a local user.
  },
};
```

## Server Setup

Create token managers, cookie managers, and the auth service:

```ts
import {
  AuthService,
  CookieManager,
  JWTManager,
} from "gw-auth/server";
import type {
  AccessTokenPayload,
  RefreshTokenPayload,
} from "gw-auth";
import { authRepository } from "./auth-repository";

const accessTokenManager = new JWTManager<AccessTokenPayload>({
  secret: process.env.ACCESS_TOKEN_SECRET!,
  expiresIn: "30m",
  issuer: "my-app",
});

const refreshTokenManager = new JWTManager<RefreshTokenPayload>({
  secret: process.env.REFRESH_TOKEN_SECRET!,
  expiresIn: "30d",
  issuer: "my-app",
});

export const authService = new AuthService({
  authRepository,
  accessTokenManager,
  accessTokenCookieStore: new CookieManager("access_token"),
  refreshTokenManager,
  refreshTokenCookieStore: new CookieManager("refresh_token"),
});
```

### Verify a Request

```ts
const authResult = await authService.verify(request);

if (authResult.isErr) {
  return new Response("Unauthorized", { status: 401 });
}

const auth = authResult.value;
```

`verify` checks the `Authorization: Bearer <token>` header first, then the
configured access-token cookie.

## Route Handlers

The package exports handlers that accept a `Request` and the services they
need:

```ts
import {
  loginHandler,
  logoutHandler,
  refreshHandler,
  signupHandler,
} from "gw-auth/server";
import { authService } from "./auth-service";
import { fileRepository } from "./file-repository";

export async function login(request: Request) {
  return loginHandler(request, { authService });
}

export async function signup(request: Request) {
  return signupHandler(request, { authService, fileRepository });
}

export async function refresh(request: Request) {
  return refreshHandler(request, { authService });
}

export async function logout(request: Request) {
  const authResult = await authService.verify(request);
  const auth = authResult.isErr ? undefined : authResult.value;

  return logoutHandler({ authService })(auth)(request);
}
```

Common handlers:

| Handler | Purpose |
| --- | --- |
| `loginHandler` | Email/id and password login |
| `logoutHandler` | Clears refresh token and auth cookies |
| `refreshHandler` | Issues a new access token from a refresh token |
| `signupHandler` | Creates a user, credential, and token pair |
| `findAuthHandler` | Returns the current access-token payload |
| `guestAuthHandler` | Creates or finds a guest user from a device id |
| `requestPasswordResetHandler` | Sends a password-reset email |
| `resetPasswordHandler` | Verifies reset token and updates password |
| `loginWithThirdPartyHandler` | Logs in with an OAuth provider result |
| `signUpWithThirdpartyHandler` | Creates a user from a third-party signup token |
| `thirdpartyAuthCallbackHandler` | Handles browser OAuth redirects |

### Express

Install Express in the consuming server, then adapt any Web handler without
changing the handler itself:

```ts
import express from "express";
import { loginHandler } from "gw-auth/server";
import { expressHandler } from "gw-auth/server/express";
import { authService } from "./auth-service";

const app = express();

app.use(express.json());
app.post(
  "/api/auth/login",
  expressHandler((request) => loginHandler(request, { authService })),
);
```

The adapter preserves the status, body, headers, and multiple `Set-Cookie`
values returned by the Web handler. Thrown errors are forwarded to Express
error middleware through `next(error)`.

## React Client

Wrap your app with `AuthProvider` and pass the current auth payload from your
server-rendering layer, loader, or API response.

```tsx
import { AuthProvider } from "gw-auth/client";
import type { AccessTokenPayload } from "gw-auth";

export function App({
  auth,
  children,
}: {
  auth?: AccessTokenPayload;
  children: React.ReactNode;
}) {
  return <AuthProvider auth={auth}>{children}</AuthProvider>;
}
```

Use the auth hook inside client components:

```tsx
import { useAuth } from "gw-auth/client";

export function AccountButton() {
  const { auth, isLoggedIn, login, logout } = useAuth();

  if (!isLoggedIn()) {
    return (
      <button onClick={() => login("user@example.com", "password")}>
        Log in
      </button>
    );
  }

  return <button onClick={() => logout()}>Log out {auth?.name}</button>;
}
```

The client provider calls these default endpoints:

| Client method | Endpoint |
| --- | --- |
| `login` | `POST /api/auth/login` |
| `logout` | `POST /api/auth/logout` |
| `signup` | `POST /api/auth/signup` |
| `requestResetPassword` | `POST /api/auth/request-password-reset` |
| `resetPassword` | `POST /api/auth/reset-password` |

## Google Login Redirects

Configure Google auth in the client provider:

```tsx
<AuthProvider
  auth={auth}
  googleAuth={{
    googleClientId: process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID!,
    googleRedirectUrl: "https://example.com/api/auth/google/callback",
  }}
>
  {children}
</AuthProvider>
```

Then call:

```ts
const { loginWithGoogle } = useAuth();

await loginWithGoogle("/dashboard");
```

On the server, create a provider:

```ts
import {
  BaseAuthProvider,
  GoogleAuth,
  JWTManager,
} from "gw-auth/server";
import type { ThirdpartyAuthPayload } from "gw-auth/server";

const signupTokenManager = new JWTManager<ThirdpartyAuthPayload>({
  secret: process.env.SIGNUP_TOKEN_SECRET!,
  expiresIn: "1h",
});

const thirdpartyAuth = new BaseAuthProvider({
  authService,
  signupTokenManager,
});

export const googleAuth = new GoogleAuth({
  thirdpartyAuth,
  googleClientId: process.env.GOOGLE_CLIENT_ID!,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  googleRedirectUri: "https://example.com/api/auth/google/callback",
});
```

Use it with the callback handler:

```ts
import { thirdpartyAuthCallbackHandler } from "gw-auth/server";
import { authService } from "./auth-service";
import { googleAuth } from "./google-auth";

export async function googleCallback(request: Request) {
  return thirdpartyAuthCallbackHandler(request, {
    provider: "google",
    authService,
    authProviders: [googleAuth],
  });
}
```

## Password Recovery

```ts
import {
  JWTManager,
  PasswordRecoveryService,
  requestPasswordResetHandler,
  resetPasswordHandler,
} from "gw-auth/server";

const passwordRecoveryService = new PasswordRecoveryService({
  siteOrigin: "https://example.com",
  siteName: "Example",
  authRepository,
  emailCredentials: {
    service: "gmail",
    user: process.env.EMAIL_USER!,
    pass: process.env.EMAIL_PASS!,
  },
  passwordRecoveryTokenManager: new JWTManager({
    secret: process.env.PASSWORD_RECOVERY_TOKEN_SECRET!,
    expiresIn: "1h",
  }),
});

export async function requestPasswordReset(request: Request) {
  return requestPasswordResetHandler(request, { passwordRecoveryService });
}

export async function resetPassword(request: Request) {
  return resetPasswordHandler(request, { passwordRecoveryService });
}
```

## Cookie Defaults

`CookieManager` defaults to:

```ts
{
  path: "/",
  httpOnly: process.env.NODE_ENV === "production",
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict"
}
```

Pass cookie options to override them:

```ts
new CookieManager("access_token", {
  path: "/",
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  domain: ".example.com",
});
```

Use `SessionCookieManager` for session cookies without explicit `maxAge` or
`expires` values.

## Token Payloads

Access and refresh tokens contain:

```ts
export type AccessTokenPayload = {
  userId: string;
  role: string;
  name: string;
  iat: number;
  exp: number;
};
```

Refresh tokens use the same payload shape.

## Development

```sh
npm install
npm run build
```

Watch mode:

```sh
npm run dev
```

## Notes

- Store token secrets in environment variables.
- Use different secrets for access, refresh, signup, and password-recovery
  tokens.
- Implement rate limiting on public auth routes.
- Validate request bodies at your application boundary.
- The package is intentionally repository-driven so it can work with any
  database or ORM.

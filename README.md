# gw-auth

`gw-auth/core` centralizes authentication and its security invariants without
knowing which application framework consumes it. It supports password, social,
guest, password-recovery, and rotating-session flows.

`gw-auth/nextjs` converts those plain operations to App Router Route Handlers
and Server Actions. `gw-auth/nextjs/client` provides the matching client-side
request helpers without choosing application routes.

## Installation

```sh
npm install gw-auth
```

Node.js 20 or newer is required.

## Package exports

```ts
import {
  createAuth,
  type AuthState,
  type PasswordRepository,
  type SocialRepository,
} from "gw-auth/core";

import { getAuth, routeHandler, serverAction, withAuth } from "gw-auth/nextjs";
import {
  AuthProvider,
  authRequest,
  startOAuth,
  useAuth,
} from "gw-auth/nextjs/client";
```

- `gw-auth/core` contains the framework-neutral facade, operation types, and storage ports.
- `gw-auth/nextjs` contains server-only App Router adapters.
- `gw-auth/nextjs/client` is the explicit client-module boundary.

## Common setup

Only session infrastructure, token policy, and shared browser-cookie policy are
configured initially.

```ts
import { createAuth } from "gw-auth/core";

export const auth = createAuth({
  serviceName: "my-service",
  sessions: sessionRepository,

  tokens: {
    access: {
      secret: process.env.ACCESS_TOKEN_SECRET!,
      expiresIn: "15m",
    },
    refresh: {
      secret: process.env.REFRESH_TOKEN_SECRET!,
      expiresIn: "30d",
    },
  },
});
```

`serviceName` is the stable identifier for this authentication boundary. The
package uses it as both JWT issuer and audience and prefixes every default
cookie name with it. It may contain letters, numbers, dots, underscores, and
hyphens.

Each token secret must contain at least 32 UTF-8 bytes. The package validates
the issuer, audience, expiration, token purpose, user, session, and refresh
rotation fields internally.

Cookie configuration is optional. Defaults are `Secure`, `HttpOnly`,
`SameSite=Lax`, and `Path=/`. OAuth state defaults to `SameSite=None` so Apple
`form_post` callbacks remain bound to the initiating browser. `HttpOnly` cannot
be disabled. For example, `serviceName: "my-service"` produces
`my-service_access_token` and `my-service_refresh_token`.

Existing services may override a cookie name during migration:

```ts
browser: {
  cookies: {
    accessToken: { name: "legacy_access_token" },
  },
}
```

## Composition order

Authentication features are configured before selecting their delivery
environment:

```text
auth.<feature>(feature dependencies).<browser|mobile>(environment options)
```

Examples:

```ts
auth.password({ repository }).browser();
auth.password({ repository }).mobile();

auth
  .social({ repository })
  .google({ clientId, clientSecret })
  .browser({ redirectUri });
```

Feature repositories are required only when their feature is enabled.

## Password authentication

```ts
const password = auth.password({
  repository: passwordRepository,
});

const browserPassword = password.browser();
const mobilePassword = password.mobile();
```

Both projections accept the same typed input:

```ts
await browserPassword.login({
  id: "member@example.com",
  password: "secret",
});

await mobilePassword.signup({
  id: "member@example.com",
  password: "secret",
  passwordConfirm: "secret",
  registration: {
    displayName: "Member",
    gender: "other",
  },
});
```

Browser success returns only `AuthState` plus cookie mutations. Mobile success
returns the access and refresh tokens explicitly. The application must validate
its `registration` value before calling `signup`.

`PasswordRepository.createPasswordAccount` must atomically create the random
internal user and password credential, and must enforce uniqueness for the
normalized credential identifier.

## Social authentication

Configure social persistence once and reuse it across providers:

```ts
const social = auth.social({
  repository: socialRepository,
});
```

For browser OAuth, the same object may implement both `SocialRepository` and
`OAuthTransactionRepository`. When transaction storage is separate, pass it
once:

```ts
const social = auth.social({
  repository: socialRepository,
  transactions: oauthTransactionRepository,
});
```

Mobile-only social authentication does not require OAuth transaction storage.

### Browser Google OAuth

```ts
const google = social.google({
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
}).browser({
  redirectUri: "https://app.example.com/auth/google/callback",
});
```

`start` and `complete` are framework-neutral operations:

```ts
const started = await google.start({
  redirectPath: "/settings",
});

if (started.result.isErr) {
  // Map started.result.error at the application boundary.
  return;
}

await applyCookieMutations(started.cookies);
await redirect(started.result.value.authorizationUrl);
```

The callback adapter parses its request and cookies before calling the package:

```ts
const completed = await google.complete({
  code,
  state,
  cookies: parsedCookies,
});

await applyCookieMutations(completed.cookies);
```

`completed.result.value` is one of:

```ts
type OAuthCompleteOutput =
  | {
      status: "authenticated";
      auth: AuthState;
      redirectPath: string;
    }
  | {
      status: "signup_required";
      profile: SocialSignupProfile;
      redirectPath: string;
    };
```

The package never chooses an application signup route or constructs a redirect
from an incoming host. The adapter owns navigation and may use only the already
validated relative `redirectPath` returned by the package.

### Other browser providers

```ts
social.kakao({ clientId, clientSecret }).browser({ redirectUri });
social.naver({ clientId, clientSecret }).browser({ redirectUri });
social.apple({ authKey, clientId, teamId, keyId }).browser({ redirectUri });
```

### Mobile providers

```ts
const google = social.google({ clientId }).mobile({
  clientIds: [iosClientId, androidClientId],
});

await google.login({ idToken });
await social.kakao().mobile().login({ accessToken });
await social.naver().mobile().login({ accessToken });

const apple = social.apple({ authKey, clientId, teamId, keyId }).mobile();
await apple.login({ authorizationCode });
```

Provider credentials are verified before any local account action. Google and
Apple verify signed identity tokens. Kakao and Naver resolve access tokens
through their official profile endpoints.

## Staged social signup

An unknown provider identity does not create a partial account. It creates a
short-lived, hashed, single-use signup attempt so the application can collect
fields such as gender, nickname, and terms acceptance.

Browser adapters read the configured HttpOnly signup cookie and supply parsed
cookie values:

```ts
const signup = social.signup.browser();

const profile = await signup.profile({ cookies: parsedCookies });

const completed = await signup.complete({
  cookies: parsedCookies,
  registration: validatedRegistration,
});
```

Mobile clients receive and return an explicit `signupToken`:

```ts
await social.signup.mobile().complete({
  signupToken,
  registration: validatedRegistration,
});
```

`SocialRepository.completeSocialSignup` must atomically consume the attempt,
create the random internal user, and link the unique
`(provider, providerUserId)` identity. Never link accounts based only on equal
email addresses.

## Sessions

Session behavior is shared by every authentication feature.

```ts
const browserSession = auth.session.browser();

await browserSession.verify({ cookies: parsedCookies });
await browserSession.refresh({ cookies: parsedCookies });
await browserSession.logout({ cookies: parsedCookies });
```

```ts
const mobileSession = auth.session.mobile();

await mobileSession.verify({ accessToken });
await mobileSession.refresh({ refreshToken });
await mobileSession.logout({ refreshToken });
```

Refresh tokens rotate using repository compare-and-swap. Reusing a rotated
token revokes its session family. Browser logout returns matching cookie
deletions even when no refresh cookie is present.

## Guest authentication

```ts
const browserGuest = auth.guest({ repository: guestRepository }).browser();
const operation = await browserGuest.authenticate({ cookies: parsedCookies });
```

```ts
const mobileGuest = auth.guest({ repository: guestRepository }).mobile();
const result = await mobileGuest.authenticate({ guestCredential });
```

Guest credentials are server-generated, stored only as hashes, and rotated on
use. Never use a client device identifier as a guest credential.

## Password recovery

```ts
const recovery = auth.passwordRecovery({
  repository: passwordResetRepository,
  mailer,
  siteOrigin: "https://app.example.com",
  resetPath: "/reset-password",
});

await recovery.request({ credentialId });
await recovery.reset({ token, password, passwordConfirm });
```

Password-reset discovery returns the same public result for known and unknown
accounts. Completion must atomically consume the attempt, update the password,
and revoke all user sessions.

## Browser operation contract

Browser methods return data rather than framework responses:

```ts
type BrowserOperation<T> = {
  result: Result<T, AuthError>;
  cookies: readonly BrowserCookieMutation[];
};
```

Adapters must apply `cookies` on both success and failure. OAuth completion, for
example, deletes its state cookie even when provider verification fails. An
adapter then decides how to express the result as a route response, redirect,
or server action. HTTP adapters must add `Cache-Control: no-store` to every
authentication or credential-bearing response.

## Next.js App Router

The Next.js adapter owns only framework conversion. The application still owns
route locations, request validation, redirects, and feature composition.

### Route Handler

`routeHandler` wraps a core browser operation, applies cookie mutations on both
success and failure, sanitizes errors, and adds `Cache-Control: no-store`.

```ts
import { routeHandler } from "gw-auth/nextjs";

const password = auth.password({ repository: passwordRepository }).browser();

export const POST = routeHandler(async (request) => {
  const input = await request.json();

  return password.login(validatedLoginInput(input));
});
```

OAuth routes may replace the default JSON success response while keeping the
adapter-managed cookies:

```ts
import { routeHandler } from "gw-auth/nextjs";
import { NextResponse } from "next/server";

export const GET = routeHandler(
  async (request) => google.start({
    redirectPath: request.nextUrl.searchParams.get("redirectPath") ?? "/",
  }),
  {
    success: ({ authorizationUrl }) => NextResponse.redirect(authorizationUrl),
  },
);
```

For callbacks and other cookie-consuming operations, convert the request once:

```ts
import { nextRequestCookies, routeHandler } from "gw-auth/nextjs";

export const GET = routeHandler(async (request) => google.complete({
  code: request.nextUrl.searchParams.get("code") ?? "",
  state: request.nextUrl.searchParams.get("state") ?? "",
  cookies: nextRequestCookies(request),
}));
```

### Server Action

Call `serverAction` from an application-owned Server Action. It awaits the core
operation, writes its cookies through Next.js `cookies()`, and returns a
serializable `{ ok, value | error }` result.

```ts
"use server";

import { serverAction } from "gw-auth/nextjs";

export async function loginAction(formData: FormData) {
  return serverAction(() => password.login({
    id: String(formData.get("id") ?? ""),
    password: String(formData.get("password") ?? ""),
  }));
}
```

The callback receives current cookie values for session operations:

```ts
export async function logoutAction() {
  return serverAction((cookies) => session.logout({ cookies }));
}
```

### Server auth and Proxy

Use `getAuth` when a Server Component needs verified access-token state. This
replaces decoding a cookie directly in application code.

```tsx
import { getAuth } from "gw-auth/nextjs";
import { AuthProvider } from "gw-auth/nextjs/client";

export default async function Layout({ children }: { children: React.ReactNode }) {
  const current = await getAuth(auth.session.browser());

  return (
    <AuthProvider initialAuth={current.isOk ? current.value : undefined}>
      {children}
    </AuthProvider>
  );
}
```

`withAuth` gives an application-owned Proxy callback the verified access
payload. It attempts refresh only for GET and HEAD requests, then redirects once
to the same URL with rotated cookies. Server Actions and other mutations must
authenticate and authorize again inside their own execution boundary.

```ts
import { NextResponse } from "next/server";
import { withAuth } from "gw-auth/nextjs";

export const proxy = withAuth(
  auth.session.browser(),
  async (request, _event, currentAuth) => {
    if (request.nextUrl.pathname.startsWith("/admin") && !currentAuth) {
      return NextResponse.redirect(new URL("/login", request.url));
    }

    return NextResponse.next();
  },
);

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|.*\\..*).*)"],
};
```

### Client

`AuthProvider` keeps server-resolved auth state synchronized and exposes
`authenticate` and `logout` without owning endpoint paths. Both operations use
`authRequest`, which sends cookies, disables caching, validates the adapter
envelope, and returns the same `Result` style as core operations. It expects the
default JSON response produced by `routeHandler`.

```ts
"use client";

import type { AuthState } from "gw-auth/core";
import { authRequest, startOAuth, useAuth } from "gw-auth/nextjs/client";

const { auth, isAuthenticated, authenticate, logout } = useAuth();

const loggedIn = await authenticate("/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ id, password }),
});

const current = await authRequest<AuthState>("/auth/current");

startOAuth("/auth/google?redirectPath=%2Fsettings");
```

## Maintenance

Schedule cleanup according to traffic and retention policy:

```ts
await auth.session.deleteExpired();
await social.deleteExpiredSignupAttempts();
await oauthTransactionRepository.deleteExpiredOAuthTransactions(new Date());
await auth.guest({ repository: guestRepository }).deleteExpiredCredentials();
await recovery.deleteExpired();
```

See [MIGRATION.md](./MIGRATION.md) before upgrading. Release changes are listed
in [CHANGELOG.md](./CHANGELOG.md). The package is licensed under the
[MIT License](./LICENSE).

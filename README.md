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

import {
  createAuthRoute,
  getAuth,
  routeHandler,
  serverAction,
  withAuth,
} from "gw-auth/nextjs";
import {
  AuthProvider,
  authRequest,
  startOAuth,
  useAuth,
} from "gw-auth/nextjs/client";

import {
  assertOAuthTransactionRepositoryConformance,
  assertPasswordResetRepositoryConformance,
  assertSessionRepositoryConformance,
  assertSocialRepositoryConformance,
} from "gw-auth/testing";
```

- `gw-auth/core` contains the framework-neutral facade, operation types, and storage ports.
- `gw-auth/nextjs` contains server-only App Router adapters.
- `gw-auth/nextjs/client` is the explicit client-module boundary.
- `gw-auth/testing` contains Node.js repository-contract assertions for consumer test suites.

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

Create this facade once for a service. Browser and mobile clients of the same
service must share the same `auth`, repositories, token policy, issuer, and
audience. Do not create `webAuth` and `mobileAuth`, and do not put a platform
name in `serviceName` merely to separate delivery environments.

Each token secret must contain at least 32 UTF-8 bytes, and the access and
refresh secrets must be different. The package validates
the issuer, audience, expiration, token purpose, user, session, and refresh
rotation fields internally.

Application claims cannot override JWT-managed `aud`, `exp`, `iat`, `iss`,
`jti`, `nbf`, `sub`, `tokenUse`, `userId`, or `sessionId` fields. These names
are removed before token issuance and are omitted from `AuthState` at the type
level.

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

Configure a feature once, then project that same object where needed:

```ts
const password = auth.password({ repository });

const browserPassword = password.browser();
const mobilePassword = password.mobile();

const social = auth.social({ repository });
const google = social.google({ clientId, clientSecret });

const browserGoogle = google.browser({ redirectUri });
const mobileGoogle = google.mobile();
```

Apple first selects the provider API because Android uses Apple's Browser API,
while iOS uses its Native API:

```ts
const apple = social.apple({ authKey, teamId, keyId });

const webApple = apple.browser({
  serviceId: webServiceId,
  redirectUri: webRedirectUri,
}).web();
const androidApple = apple.browser({
  serviceId: androidServiceId,
  redirectUri: androidRedirectUri,
}).android();

const iosApple = apple.native({ appId }).ios();
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

Password login, signup, and recovery reject inputs that bcrypt would truncate
after 72 UTF-8 bytes. Applications still own product rules such as minimum
length and character requirements.

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

Native-token-only social authentication does not require OAuth transaction
storage. Browser OAuth and Apple on Android do require it.

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
```

### Mobile providers

```ts
const google = social.google({ clientId }).mobile({
  clientIds: [iosClientId, androidClientId],
});

await google.login({ idToken });
await social.kakao().mobile().login({ accessToken });
await social.naver().mobile().login({ accessToken });
```

Provider credentials are verified before any local account action. Google and
Apple verify signed identity tokens. Kakao and Naver resolve access tokens
through their official profile endpoints. Bundled provider HTTP calls and
remote-key downloads use a 10-second timeout. Invalid credentials retain their
provider-specific error code; transport failures, throttling, and upstream 5xx
responses use `PROVIDER_UNAVAILABLE`, while malformed successful responses use
`INVALID_PROVIDER_RESPONSE`.

### Apple Browser and Native APIs

Apple signing credentials are shared, but the client identifier and callback
contract depend on the Apple API being used:

```ts
const apple = social.apple({
  authKey: process.env.APPLE_AUTH_KEY!,
  teamId: process.env.APPLE_TEAM_ID!,
  keyId: process.env.APPLE_KEY_ID!,
});

const web = apple.browser({
  serviceId: process.env.APPLE_SERVICE_ID!,
  redirectUri: "https://app.example.com/api/auth/apple/callback",
}).web();

const ios = apple.native({
  appId: process.env.APPLE_APP_ID!,
}).ios();

await ios.login({ authorizationCode });
```

Apple returns a provider refresh token only during the initial authorization.
Persist it encrypted together with the `providerClientId` returned in the
verified `SocialIdentity`, then use both values during account deletion:

```ts
await apple.revoke({
  providerRefreshToken: storedEncryptedToken,
  providerClientId: storedIssuingClientId,
});
```

Revocation belongs to the base `apple` feature because the stored client ID
selects the correct Services ID or App ID; it is not available on `.web()`,
`.android()`, or `.ios()` projections.

- Website login uses Apple's Browser API, a Services ID, and an exact HTTPS
  return URI.
- Native iOS login uses Apple's Native API and the app's App ID. Its token
  exchange does not send `redirect_uri`.
- Android login through Flutter's
  [`sign_in_with_apple`](https://pub.dev/packages/sign_in_with_apple) package
  also uses the Browser API. It therefore needs a Services ID and HTTPS return
  URI, but returns explicit application session tokens rather than browser
  cookies.

The Android flow starts on the server so state and nonce remain bound to one
single-use transaction:

```ts
const android = apple.browser({
  serviceId: process.env.APPLE_SERVICE_ID!,
  redirectUri: "https://app.example.com/api/auth/mobile/apple/callback",
}).android();

const attempt = await android.start();

if (attempt.isOk) {
  // Give serviceId, redirectUri, state, and nonce to getAppleIDCredential.
}
```

For Flutter Android, the HTTPS callback must relay Apple's original callback
fields to the plugin's exact Intent URI. The prebuilt Next.js AuthRoute below
does that automatically. A custom adapter must return an external redirect of
this form without consuming or replacing `code`, `state`, or `id_token`:

```text
intent://callback?<apple-callback-fields>#Intent;package=<android-package-id>;scheme=signinwithapple;end
```

The Android app must also register the plugin callback activity under
`<application>` as documented by `sign_in_with_apple`:

```xml
<activity
    android:name="com.aboutyou.dart_packages.sign_in_with_apple.SignInWithAppleCallback"
    android:exported="true">
  <intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="signinwithapple" />
    <data android:path="callback" />
  </intent-filter>
</activity>
```

The Flutter client passes the server-issued values to the plugin, checks the
returned state, and sends the authorization code and original state back to
the completion endpoint:

```dart
final credential = await SignInWithApple.getAppleIDCredential(
  scopes: [AppleIDAuthorizationScopes.email],
  webAuthenticationOptions: WebAuthenticationOptions(
    clientId: attempt.serviceId,
    redirectUri: Uri.parse(attempt.redirectUri),
  ),
  state: attempt.state,
  nonce: attempt.nonce,
);

if (credential.state != attempt.state) {
  throw StateError('Apple OAuth state mismatch');
}

await completeAppleLogin(
  authorizationCode: credential.authorizationCode,
  state: attempt.state,
);
```

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
  onRequestError: (error) => logger.error({ error }, "password reset request failed"),
});

await recovery.request({ credentialId });
await recovery.reset({ token, password, passwordConfirm });
```

Password-reset discovery returns the same public success for known and unknown
accounts, including known-account attempt-storage and mail-delivery failures.
Use `onRequestError` for internal reporting; a failure in that observer is also
concealed. Account-lookup infrastructure failure remains an explicit system
error because it affects every request. Completion must atomically consume the
attempt, update the password, and revoke all sessions for that user only.

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

Use the fixed AuthRoute for the shortest setup. Use the lower-level adapters
when the application needs different paths, body schemas, validation, or
redirect behavior. Both choices keep Next.js outside the core package.

### Prebuilt AuthRoute

`createAuthRoute` turns the same unprojected feature objects into browser and
mobile routes. Do not call `.browser()` or `.mobile()` before passing a feature
to it. For Google, Kakao, and Naver, explicitly select each enabled delivery so
a mobile-only provider never requires browser credentials.

```ts
// src/auth.ts
import { createAuth } from "gw-auth/core";
import { createAuthRoute } from "gw-auth/nextjs";

export const auth = createAuth({
  serviceName: "my-service",
  sessions: sessionRepository,
  tokens: tokenOptions,
});

const password = auth.password({ repository: passwordRepository });
const social = auth.social({
  repository: socialRepository,
  transactions: oauthTransactionRepository,
});
const apple = social.apple({
  authKey: process.env.APPLE_AUTH_KEY!,
  teamId: process.env.APPLE_TEAM_ID!,
  keyId: process.env.APPLE_KEY_ID!,
});

export const authRoute = createAuthRoute({
  siteOrigin: "https://app.example.com",
  session: auth.session,
  password,
  social: {
    signup: social.signup,
    google: {
      feature: social.google({
        clientId: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      }),
      browser: true,
      mobile: {
        clientIds: [
          process.env.GOOGLE_IOS_CLIENT_ID!,
          process.env.GOOGLE_ANDROID_CLIENT_ID!,
        ],
      },
    },
    apple: {
      feature: apple,
      web: { serviceId: process.env.APPLE_WEB_SERVICE_ID! },
      android: {
        serviceId: process.env.APPLE_ANDROID_SERVICE_ID!,
        packageId: "com.example.app",
      },
      ios: { appId: process.env.APPLE_APP_ID! },
    },
  },
});
```

The catch-all Route Handler only re-exports the two generated methods:

```ts
// app/api/auth/[...auth]/route.ts
import { authRoute } from "@/auth";

export const { GET, POST } = authRoute;
```

The preset owns these contracts:

| Client | Method and path | Body or query |
| --- | --- | --- |
| Browser | `GET /api/auth/session` | none |
| Browser | `POST /api/auth/login` | `{ id, password }` |
| Browser | `POST /api/auth/signup` | `{ id, password, passwordConfirm, registration }` |
| Browser | `POST /api/auth/refresh` | none; refresh token comes from cookies |
| Browser | `POST /api/auth/logout` | none; refresh token comes from cookies |
| Browser | `POST /api/auth/guest` | none; guest credential comes from cookies |
| Browser | `GET /api/auth/:provider` | optional `redirectPath` query |
| Browser | `GET` or `POST /api/auth/:provider/callback` | provider callback fields |
| Browser | `GET /api/auth/social-signup` | staged profile from cookies |
| Browser | `POST /api/auth/social-signup` | `{ registration }` |
| Shared | `POST /api/auth/password-reset/request` | `{ credentialId }` |
| Shared | `POST /api/auth/password-reset/complete` | `{ token, password, passwordConfirm }` |
| Mobile | `POST /api/auth/mobile/password/login` | `{ id, password }` |
| Mobile | `POST /api/auth/mobile/password/signup` | `{ id, password, passwordConfirm, registration }` |
| Mobile | `POST /api/auth/mobile/refresh` | `{ refreshToken }` |
| Mobile | `POST /api/auth/mobile/logout` | `{ refreshToken }` |
| Mobile | `POST /api/auth/mobile/guest` | `{ guestCredential? }` |
| Mobile | `POST /api/auth/mobile/:provider` | Google `{ idToken }`; Kakao or Naver `{ accessToken }` |
| iOS | `POST /api/auth/mobile/apple/native` | `{ authorizationCode }` |
| Android | `POST /api/auth/mobile/apple/browser/start` | none; returns Services ID, return URI, state, and nonce |
| Android callback | `POST /api/auth/mobile/apple/callback` | Apple `form_post`; redirects to the Flutter plugin Intent |
| Android | `POST /api/auth/mobile/apple/browser` | `{ authorizationCode, state }` |
| Mobile | `POST /api/auth/mobile/social-signup` | `{ signupToken, registration }` |

Only enabled features and providers register their routes. All JSON responses
use `{ ok: true, value? }` or `{ ok: false, error }` and send
`Cache-Control: no-store`.
`GET /api/auth/session` returns only the normalized `AuthState`; JWT transport
metadata such as `iat`, `exp`, `iss`, `aud`, and `tokenUse` is never part of
that client contract.
Browser OAuth callbacks are derived from `siteOrigin`; successful sign-in uses
the validated `redirectPath`, while an unknown identity goes to `/signup` and
a provider error goes to `/login`. Register
`<siteOrigin>/api/auth/apple/callback` for website Apple login and
`<siteOrigin>/api/auth/mobile/apple/callback` for Android Apple login.

The preset accepts JSON bodies only with `application/json` or an
`application/*+json` Content-Type. A present `Origin` header must exactly equal
`siteOrigin`; clients such as native apps and server-to-server callers that do
not send `Origin` remain supported. Provider-owned OAuth and Apple form-post
callbacks are the only cross-origin exception.

`registration` remains application-owned, untrusted input. If it needs runtime
validation, if paths or bodies differ, or if one provider needs different
credentials from the fixed configuration above, define that specific
application Route Handler with `routeHandler` instead. A specific App Router
route takes precedence over the catch-all route.

### Route Handler

`routeHandler` accepts either a cookie-aware `BrowserOperation<T>` or a
cookie-free `AuthResult<T>`. It applies browser cookie mutations when present,
sanitizes errors, maps authentication failures to HTTP status codes, serializes
the standard JSON envelope, and adds `Cache-Control: no-store`.

The default status policy uses 400 for malformed inputs and password-policy
failures, 401 for rejected local or provider credentials, 409 for existing
identities, 502 for unavailable or malformed provider responses, and 500 for
internal system failures. Applications can override this with `errorStatus`.

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

Mobile and password-recovery results use the same adapter without a wrapper:

```ts
// app/api/mobile/login/route.ts
export const POST = routeHandler(async () => mobilePassword.login(input));
```

```ts
// app/api/password-reset/request/route.ts
export const POST = routeHandler(async () => recovery.request({
  credentialId,
}));
```

### Server Action

Call `serverAction` from an application-owned Server Action. It accepts either
a `BrowserOperation<T>` or a cookie-free `AuthResult<T>`, writes any cookie
mutations through Next.js `cookies()`, and returns a serializable
`{ ok, value | error }` result.

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

A cookie-free recovery or mobile operation needs no cookie argument:

```ts
export async function requestPasswordReset(credentialId: string) {
  return serverAction(() => recovery.request({ credentialId }));
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
envelope (including non-OK HTTP responses), and returns the same `Result` style
as core operations. It expects the default JSON response produced by
`routeHandler`.
Logout clears local state after any server-processed response, including an
already-invalid refresh credential, because the browser logout operation still
deletes its cookies. Network failures and invalid response envelopes preserve
the existing local state.

```ts
"use client";

import type { AuthState } from "gw-auth/core";
import { authRequest, startOAuth, useAuth } from "gw-auth/nextjs/client";

const { auth, isAuthenticated, authenticate, logout } = useAuth();

const loggedIn = await authenticate("/api/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ id, password }),
});

const current = await authRequest<AuthState>("/api/auth/session");

startOAuth("/api/auth/google?redirectPath=%2Fsettings");
```

## Repository conformance tests

`gw-auth/testing` checks the security-sensitive behavior required from
consumer-owned repositories without choosing an ORM, database, or user schema.
Each assertion creates its own isolated fixture and exercises real concurrent
calls:

```ts
import test from "node:test";
import {
  assertOAuthTransactionRepositoryConformance,
  assertPasswordResetRepositoryConformance,
  assertSessionRepositoryConformance,
  assertSocialRepositoryConformance,
} from "gw-auth/testing";

test("session repository", () => assertSessionRepositoryConformance(
  createIsolatedSessionFixture,
));

test("OAuth transaction repository", () =>
  assertOAuthTransactionRepositoryConformance(createIsolatedOAuthFixture));

test("social repository", () =>
  assertSocialRepositoryConformance(createIsolatedSocialFixture));

test("password-reset repository", () =>
  assertPasswordResetRepositoryConformance(createIsolatedPasswordResetFixture));
```

Every factory must return a fresh repository namespace and may return a
`dispose` callback. The social fixture also provides valid application
`registration` data. Its assertion races both one token and two different
tokens for the same provider identity. The password-reset fixture seeds one
account, its active refresh sessions, and at least one unrelated user's active
session. It exposes password-hash, target-session, and unrelated-session
readers so the assertion can verify atomic completion without over-revocation.
This entry point is intended for Node.js test environments only.

## Application boundary requirements

`gw-auth` validates credentials and protects token and attempt lifecycles, but
it does not know an application's abuse policy. Every consuming HTTP boundary
must rate-limit login, signup, password-reset request/completion, guest creation,
OAuth starts/callbacks, social signup, refresh, and other credential-bearing
operations using appropriate account, IP, device, and global controls. Keep
application authorization and runtime validation of `registration` inputs at
that same boundary.

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

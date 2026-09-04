# Migrating gw-auth

## Migrating from 0.9.0 to 0.10.0

`SessionRepository` now owns the complete atomic decision for concurrent
refreshes and stale-token replay. Add the following non-secret fields to each
refresh-session row:

```ts
type RefreshSession = {
  id: string;
  userId: string;
  tokenHash: string;
  tokenId: string;
  issuedAt: Date;
  expiresAt: Date;
  previousTokenHash: string | null;
  rotatedAt: Date;
};
```

The bearer token remains hash-only. `tokenId`, `issuedAt`, and `expiresAt` are
the current refresh JWT's exact `jti`, `iat`, and `exp` values, allowing
`gw-auth` to reproduce the same signed winner without storing plaintext.
`rotatedAt` records the exact successful rotation time used for the 10-second
overlap decision.

Replace the boolean compare-and-swap method with the object-based
`rotateRefreshSession(input)`. In one transaction or equivalent atomic
operation, implement these branches in order:

1. Return `invalid` when the row is absent, expired, or belongs to another user.
2. When the current hash matches `expectedTokenHash`, persist `input.next`, move
   the current hash to `previousTokenHash`, set `rotatedAt` to `input.now`, and
   return `rotated`.
3. When only `previousTokenHash` matches and `rotatedAt` is on or after
   `reuseWindowStart`, return `concurrent` with that current row unchanged.
4. Otherwise delete the row and return `reused`.

Run `assertSessionRepositoryConformance` against the real implementation. Since
existing rows do not have reproducible current-token metadata, revoke them
during the schema rollout unless the application implements an explicit
transition. Newly issued refresh JWTs omit application claims; this does not
change access-token or `AuthState` claims.

## Migrating from 0.8.0 to 0.9.0

Next.js applications can bind the shared session facade once instead of
projecting it at every server authentication call:

```ts
import { createAuthResolver } from "gw-auth/nextjs";

const authResolver = createAuthResolver(auth.session);

await authResolver.cookies({ refresh: false });
await authResolver.cookies();
await authResolver.request();
```

The existing `getAuth` and `getAuthWithRefresh` functions remain supported.
`request()` is intended for Route Handlers: a present `Authorization` header
must contain exactly one Bearer credential and takes precedence over cookies.
Malformed or invalid bearer authentication never falls back to ambient browser
cookies. Without the header, it verifies cookies and attempts browser refresh,
including replacement or terminal cleanup cookie effects.

## Migrating from 0.7.0 to 0.8.0

Next.js Server Actions and Route Handlers can now recover an expired access
cookie before running protected application logic:

```ts
import { getAuthWithRefresh } from "gw-auth/nextjs";

const current = await getAuthWithRefresh(auth.session.browser());
```

The helper verifies first and refreshes only when access verification fails. It
applies replacement cookies after a successful rotation and applies core-owned
cleanup cookies after a terminal refresh failure. Use the existing `getAuth`
inside Server Components because render-time code cannot write cookies.

Proxy behavior is unchanged: `withAuth` performs redirect-based refresh only
for GET and HEAD requests. Mutations must call `getAuthWithRefresh` inside their
own Server Action or Route Handler before executing application logic.

## Migrating from 0.6.0 to 0.7.0

Account deletion is now an optional feature configured from an
`AccountDeletionRepository` and any linked provider revokers:

```ts
const account = auth.account({
  repository: accountDeletionRepository,
  providers: { apple },
});
```

Implement `beginAccountDeletion` as an idempotent transaction that marks the
user pending, prevents new authentication, and revokes all refresh sessions.
Return unfinished Apple revocations with their stored issuing client IDs and
decrypted refresh tokens. `completeAccountProviderRevocation` must be
idempotent, and `completeAccountDeletion` must reject remaining provider work.

The Next.js preset accepts this feature as `account` and adds
`POST /api/auth/account/delete` for cookie-backed browsers and
`POST /api/auth/mobile/account/delete` for mobile clients using an
`Authorization: Bearer <accessToken>` header. Custom routes can use the same
browser and mobile operations through `routeHandler`.

## Migrating from 0.5.0 to 0.6.0

Direct Flutter Android Apple composition now supplies its package identifier
when selecting the Android delivery:

```ts
const android = apple.browser({
  serviceId: androidServiceId,
  redirectUri: androidRedirectUri,
}).android({ packageId: "com.example.app" });
```

Custom callback adapters must pass parsed text form fields to
`android.handoff(values)` and redirect to the returned `redirectUrl`. Package
validation, Apple callback filtering and bounds, and the exact
`signinwithapple` Intent format are no longer adapter responsibilities. The
fixed Next.js `createAuthRoute` configuration is unchanged.

Failed browser refresh operations now include access and refresh cookie
deletions for invalid, reused, mismatched, and missing-user sessions. Custom
adapters must continue applying `BrowserOperation.cookies` on both success and
failure; they should remove any error-code-specific logout logic.

Core now exports `authStateFromAccessPayload` for client-safe projections and
`authErrorCategory` for transport-neutral failure classification. Direct
session verification still returns the full access-token payload. Precise JWT
signing and expiration failures remain available as internal causes, while
authentication workflows expose them as `AUTH_SYSTEM_FAILURE`.

## Migrating from 0.4.1 to 0.5.0

The Next.js `routeHandler` and `serverAction` functions now accept
cookie-free `AuthResult<T>` operations directly. Existing browser-operation
calls are unchanged:

```ts
export const POST = routeHandler(() => mobilePassword.login(input));

export async function requestPasswordReset(credentialId: string) {
  return serverAction(() => recovery.request({ credentialId }));
}
```

The fixed `GET /api/auth/session` route and Next.js `getAuth` now return only
normalized `AuthState`. Remove dependencies on JWT metadata such as `iat`,
`exp`, `iss`, `aud`, and `tokenUse` from those client-facing paths. Direct
server-side session verification still returns its typed access payload.

Application claims named `aud`, `exp`, `iat`, `iss`, `jti`, `nbf`, `sub`,
`tokenUse`, `userId`, or `sessionId` are now removed before issuance and omitted
from `AuthState`. Rename any application data using those reserved names.
`createAuth` also rejects equal access and refresh secrets; rotate one key if a
service reused the same value.

Password login, signup, and recovery now reject values that bcrypt would
truncate after 72 UTF-8 bytes. Add an application-facing maximum rule if a
consumer previously accepted longer passwords.

Consumer repository implementations can import the new Node.js-only
assertions from `gw-auth/testing` to verify CAS, single-consumption, replay,
expiration, and password-reset/session-revocation behavior. Each assertion
requires a fresh isolated fixture; no repository implementation moved into
`gw-auth`.

The password-reset conformance fixture now also requires
`countOtherActiveRefreshSessions()`. Seed at least one unrelated user's session
so the assertion can prove reset completion revokes only the target user's
sessions. The social assertion now races two different attempts for the same
provider identity as well as two consumers of one attempt.

Apple configuration now follows Apple's actual Browser and Native API
boundaries. Remove `clientId` from the shared Apple signing options and remove
the old `.browser(...)` and `.mobile()` projections:

```ts
const apple = social.apple({ authKey, teamId, keyId });

const web = apple.browser({
  serviceId: webServiceId,
  redirectUri: webRedirectUri,
}).web();
const android = apple.browser({
  serviceId: androidServiceId,
  redirectUri: androidRedirectUri,
}).android({ packageId: "com.example.app" });
const ios = apple.native({ appId }).ios();
```

Website and Android flows require a Services ID and exact HTTPS return URI.
Native iOS requires an App ID and omits `redirect_uri` during code exchange.
No public `clientType` selector replaces the old API.

Apple revocation moved from each delivery projection to the base feature. Add a
`providerClientId` column beside the encrypted provider refresh token, populate
both from the verified `SocialIdentity`, and revoke with the issuing identifier:

```ts
await apple.revoke({
  providerRefreshToken: storedProviderRefreshToken,
  providerClientId: storedProviderClientId,
});
```

Backfill existing Apple identity rows with the App ID or Services ID used by
their original flow before switching account deletion to the new revoker.

The fixed Next.js AuthRoute now accepts Apple configuration by delivery:

```ts
social: {
  signup: social.signup,
  apple: {
    feature: apple,
    web: { serviceId: process.env.APPLE_WEB_SERVICE_ID! },
    android: {
      serviceId: process.env.APPLE_ANDROID_SERVICE_ID!,
      packageId: "com.example.app",
    },
    ios: { appId: process.env.APPLE_APP_ID! },
  },
}
```

Replace the old Apple mobile endpoint with the appropriate fixed route:

- Native iOS: `POST /api/auth/mobile/apple/native` with
  `{ authorizationCode }`.
- Flutter Android: call `POST /api/auth/mobile/apple/browser/start`, pass its
  Services ID, return URI, state, and nonce to `getAppleIDCredential`, then call
  `POST /api/auth/mobile/apple/browser` with `{ authorizationCode, state }`.
- Register `POST /api/auth/mobile/apple/callback` as Apple's Android return URI;
  it relays the form post to Flutter's `signinwithapple` callback Intent.

Android Apple authentication now requires the social OAuth transaction
repository so state and nonce can be consumed once on the server.

Google, Kakao, and Naver entries in the fixed AuthRoute now wrap the feature and
explicit delivery selection. This prevents a mobile-only configuration from
constructing a browser projection:

```ts
social: {
  signup: social.signup,
  google: {
    feature: social.google({ clientId, clientSecret }),
    browser: true,
    mobile: { clientIds: [iosClientId, androidClientId] },
  },
}
```

Omit `browser` and its secret for mobile-only use; omit `mobile` for
browser-only use. The preset now rejects requests with a present foreign
`Origin` header except provider form-post callbacks, and accepts JSON bodies
only with a JSON Content-Type. Origin-less native and server clients remain
supported.

Password-recovery requests now conceal attempt-storage and notification errors
for known accounts. Supply `onRequestError` if those failures must be reported
to logging or monitoring. Provider transport/429/5xx failures now use
`PROVIDER_UNAVAILABLE`, malformed successful responses use
`INVALID_PROVIDER_RESPONSE`, and the Next.js adapter maps both to 502.
The Next.js client now preserves structured auth errors from non-OK HTTP
responses instead of reporting every 4xx/5xx as `AUTH_NETWORK_FAILURE`.
Public `AUTH_SYSTEM_FAILURE` messages no longer include an internal operation
name. Observability code can read `error.cause.operation` before the HTTP
adapter removes causes.

All consuming HTTP routes remain responsible for rate limiting authentication,
recovery, OAuth, guest, refresh, and other credential-bearing endpoints.

## Migrating from 0.3 to 0.4

Version 0.4 replaces constructor and HTTP-handler composition with one
framework-neutral facade. It also changes session, OAuth, social-signup, guest,
and password-reset persistence for stronger replay protection and atomicity.

Migrate one consuming service first and exercise every enabled authentication
path before updating the remaining services.

### 1. Replace manual service construction

Remove direct construction of `JWTManager`, `SessionAuthService`, `AuthService`,
`OAuthService`, `OAuthProviders`, and `CookieManager`.

Create the shared facade instead:

```ts
import { createAuth } from "gw-auth/core";

const auth = createAuth({
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

JWT secrets must contain at least 32 UTF-8 bytes. Use different access and
refresh secrets. `serviceName` becomes the JWT issuer and audience and prefixes
all default cookie names. Keep it stable across every instance of the same
service.

Existing 0.3 tokens do not satisfy the new issuer, audience, purpose, and
session requirements, so plan a forced sign-in. To keep an existing cookie name
during a gradual migration, override only that name:

```ts
browser: {
  cookies: {
    accessToken: { name: "access_token" },
    refreshToken: { name: "refresh_token" },
  },
}
```

Legacy `AccessTokenPayload`, `RefreshTokenPayload`, `isAccessTokenPayload`, and
`isRefreshTokenPayload` exports were removed. Use `SessionAccessPayload`,
`SessionRefreshPayload`, and the typed results from `auth.session` instead.
Claims no longer default to application-specific `role` and `name` fields.

### 2. Implement the common session repository

The object passed as `sessions` implements both `SessionRepository` and
`SessionUserRepository`.

Each refresh session stores:

```ts
type RefreshSession = {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
};
```

`rotateRefreshSession` must be one compare-and-swap update whose predicate
contains both the session id and expected token hash. A stale-token replay
revokes that session family.

Remove `deleteUserRefreshSessions` from this repository. Password reset owns
all-session revocation inside its separate atomic `PasswordResetRepository`
operation.

`findSessionUser` returns current claims independently of the feature that
originally authenticated the user:

```ts
{
  id: "random-internal-user-id",
  claims: { role: "member", name: "Member" },
}
```

### 3. Configure only enabled features

Password authentication:

```ts
const password = auth.password({
  repository: passwordRepository,
});

const browserPassword = password.browser();
const mobilePassword = password.mobile();
```

Social authentication:

```ts
const social = auth.social({
  repository: socialRepository,
  transactions: oauthTransactionRepository,
});
```

Guest authentication:

```ts
const guest = auth.guest({ repository: guestRepository });
```

Do not implement repositories for features the service does not enable.
Mobile-only social authentication may omit `transactions`.

### 4. Replace HTTP handlers with plain operations

The following exports were removed:

- every `*Handler` function;
- `gw-auth/server/express`;
- Express request and response conversion helpers.

Public operations no longer accept `Request` or return `Response`. The
application or an external adapter parses its framework request, invokes the
operation, applies cookie mutations, and builds the framework response.

Before:

```ts
return loginHandler(request, {
  authService,
});
```

After:

```ts
const operation = await auth
  .password({ repository: passwordRepository })
  .browser()
  .login({ id, password });

await applyCookieMutations(operation.cookies);

return mapResult(operation.result);
```

Apply `BrowserOperation.cookies` on failure as well as success. OAuth callback
failures include the state-cookie deletion required to end that attempt.

### 5. Replace browser and native names

All `native` public names were removed. Use the feature's explicit projection:

```ts
auth.password({ repository }).browser();
auth.password({ repository }).mobile();

auth.social({ repository }).google({ clientId }).mobile();
```

Browser operations expose only browser-safe `AuthState` and structured
HttpOnly cookie effects. Mobile operations return access and refresh tokens for
platform secure storage.

### 6. Migrate social providers

Provider registries and verifier classes are now internal. Configure the shared
social repository once, followed by a provider and environment:

```ts
const social = auth.social({
  repository: socialRepository,
  transactions: oauthTransactionRepository,
});

const google = social.google({
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
}).browser({
  redirectUri: "https://app.example.com/auth/google/callback",
});
```

Start OAuth without constructing an HTTP response:

```ts
const started = await google.start({ redirectPath: "/settings" });
```

Complete it with callback fields and cookies parsed by the application:

```ts
const completed = await google.complete({
  code,
  state,
  cookies: parsedCookies,
});
```

`oauthService`, `authService`, `oauthStateCookies`,
`signupAttemptCookies`, `siteOrigin`, and `signupPath` are no longer passed to
each callback. Cookie policy is derived from `serviceName` or overridden once in
`createAuth`; the application owns its redirect and signup routes.

### 7. Add one-time OAuth transaction persistence

Browser social authentication requires `OAuthTransactionRepository`. It stores
only a state hash plus provider, validated relative redirect path, optional PKCE
verifier, optional nonce, and expiration.

`consumeOAuthTransaction` must atomically return and delete one matching,
unexpired transaction. Google and Kakao use S256 PKCE. Google and Apple bind ID
tokens to a nonce. Every provider uses one-time state bound to the initiating
browser's HttpOnly cookie.

### 8. Add staged social-signup persistence

Unknown social identities now create a short-lived, hashed, single-use signup
attempt instead of a partial user.

```ts
const signup = social.signup.browser();

await signup.profile({ cookies: parsedCookies });
await signup.complete({
  cookies: parsedCookies,
  registration: validatedRegistration,
});
```

`completeSocialSignup` must be one transaction that consumes the attempt,
creates a random internal user id, and links a unique
`(provider, providerUserId)` identity. Do not auto-link accounts solely because
provider and local email addresses match.

### 9. Replace password and guest persistence

`PasswordRepository.createPasswordAccount` replaces separate user and
credential creation calls. It must atomically create both records and enforce a
unique normalized credential id.

Guest authentication no longer accepts a public device identifier as a secret.
`GuestRepository` stores hashes of server-generated credentials and rotates
them with compare-and-swap after successful session issuance.

### 10. Replace password-reset JWTs

Use `auth.passwordRecovery` with an injected repository and mailer:

```ts
const recovery = auth.passwordRecovery({
  repository: passwordResetRepository,
  mailer,
  siteOrigin: "https://app.example.com",
});
```

Reset attempts are opaque, hashed, expiring, and single-use. Completion must
atomically consume the attempt, update the password, and revoke every refresh
session belonging to the user.

### 11. Choose an explicit package boundary

The legacy root React bindings, Express adapter, and route-opinionated
`AuthClient` were removed. Import the framework-neutral API from
`gw-auth/core`.

Next.js App Router applications may use `gw-auth/nextjs` for Route Handlers and
Server Actions, verified server auth, and Proxy composition. Use
`gw-auth/nextjs/client` for `AuthProvider`, `useAuth`, and client requests. These
low-level adapters do not choose route paths or validate application request
bodies.

For the fixed `/api/auth/[...auth]` convention, pass unprojected features to
`createAuthRoute` and re-export its methods:

```ts
import { createAuthRoute } from "gw-auth/nextjs";

const password = auth.password({ repository: passwordRepository });
const authRoute = createAuthRoute({
  siteOrigin: "https://app.example.com",
  session: auth.session,
  password,
});

export const { GET, POST } = authRoute;
```

Create only one `auth` facade for an authentication boundary. Do not create
separate `webAuth` and `mobileAuth` facades: the AuthRoute selects
`password.browser()` and `password.mobile()` internally. Keep direct Route
Handlers for any nonstandard path, request body, validation, or redirect.

Other framework bindings remain in their consuming application or adapter
package.

### 12. Verify rollout

Before switching traffic, verify:

- password login and atomic signup;
- browser cookie creation, refresh, and deletion;
- mobile token rotation and secure-storage replacement;
- every configured social provider;
- staged social signup and replay rejection;
- OAuth state mismatch and callback replay rejection;
- guest credential rotation and replay rejection;
- password-reset replay rejection and all-session revocation;
- storage failures remain distinguishable from expected auth failures.

## Migrating from earlier versions

Upgrade to 0.3 first when migrating from 0.1 or 0.2, then follow the 0.3-to-0.4
steps above. Version 0.3 introduced independent refresh sessions and removed
refresh-token hashes from user rows; those schema changes remain required.

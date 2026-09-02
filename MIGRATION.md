# Migrating gw-auth

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
adapters do not choose route paths or validate application request bodies.
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

# Changelog

## 0.4.1

- Added a fixed Next.js catch-all `createAuthRoute` preset that projects one
  session, password, guest, social, and recovery composition into browser and
  mobile endpoints.
- Documented that browser and mobile delivery share one `createAuth` facade and
  that custom endpoint contracts remain application-owned direct routes.

## 0.4.0

- Added the feature-first `createAuth` facade with
  `auth.social(...).google(...).browser(...)` composition.
- Derived JWT issuer, audience, and default cookie-name prefixes from one
  required `serviceName`, removing per-token validators and identity settings
  from the common setup.
- Removed legacy token-payload aliases, public payload validators, and the
  application-specific `role`/`name` default claim shape.
- Replaced public HTTP handlers with framework-neutral operations that accept
  plain inputs and return `Result` values plus structured browser-cookie
  mutations.
- Removed the built-in Express and legacy route-opinionated React integrations.
  Framework bindings now use explicit adapter subpaths.
- Published the framework-neutral API through `gw-auth/core` and added explicit
  `gw-auth/nextjs` and `gw-auth/nextjs/client` App Router boundaries.
- Added Route Handler conversion with sanitized errors, scoped cookie writes,
  and `Cache-Control: no-store`, plus Server Action cookie application.
- Added a route-agnostic client request helper that preserves core `Result`
  behavior, a local OAuth-route navigation helper, and a React auth provider.
- Added verified Server Component auth lookup and Proxy composition with
  access-token state plus GET/HEAD-only refresh rotation.
- Added structurally identifiable `AuthError` failures, removing cross-version
  `gw-result` `instanceof` checks.
- Required JWT algorithm, issuer, audience, purpose, expiration, and runtime
  payload validation with minimum 32-byte secrets.
- Added current user/session binding, refresh-token `jti`, compare-and-swap
  rotation, replay-family revocation, and explicit expired-session cleanup.
- Split browser cookie operations from mobile explicit-token operations so
  browser results never expose bearer token values.
- Replaced multi-step password signup with one atomic repository operation and
  random internal user ids.
- Added verified, hashed, expiring, single-use social signup attempts for flows
  that collect application profile fields after provider login.
- Added one-time hashed OAuth state persistence, initiating-browser `HttpOnly`
  state binding, trusted-origin redirects, PKCE where supported, nonce
  validation for Google and Apple, and verified Apple ID tokens.
- Bound each browser and mobile flow directly to its selected provider,
  removing the obsolete provider registries and unsupported-provider branches.
- Added a Naver mobile access-token verifier and normalized numeric provider
  identifiers before persistence.
- Replaced device-id guest authentication with rotating, server-generated,
  high-entropy recovery credentials that rotate only after session issuance.
- Replaced reusable password-reset JWTs and built-in SMTP configuration with
  opaque one-time attempts, an atomic password/session transaction, and an
  injected mailer port.
- Removed session and OAuth methods that were unreachable from the facade,
  including the unused bulk-session deletion requirement.
- Replaced the route-opinionated browser client and legacy provider; consuming
  applications still own endpoint shapes used by the Next.js client adapter.
- Removed runtime dependencies on `gw-file`, `gw-response`, `nodemailer`, and
  `uuid`, plus all Express package dependencies. React and Next.js are optional
  peers used only by their explicit adapter entry points.
- Reduced published core runtime exports and added
  MIT license, package metadata, Node engine requirements, tests, and detailed
  repository documentation.
- Required external HTTP adapters to mark authentication and credential
  responses with `Cache-Control: no-store`.

## 0.3.0

- Changed browser `AuthService` sessions to use `SessionRepository` rows rather
  than a single refresh-token hash on each user.
- Rotated both access and refresh cookies during browser refresh.
- Revoked only the current browser session during logout.
- Removed `refreshToken` and `updateUserRefreshToken` from `AuthRepository`.

## 0.2.1

- Fixed Apple client-secret creation with jose 6 by providing an explicit empty
  JWT payload.

## 0.2.0

- Added `SessionAuthService` and `SessionRepository` for independent,
  per-device rotating refresh sessions.
- Added Google ID-token, Kakao access-token, and Apple authorization-code
  verification for native applications.
- Added Apple provider-token revocation support.
- Added an Express 5 adapter for Web `Request`/`Response` handlers.
- Enforced configured JWT issuers during verification.
- Required the current refresh-token hash for both rotation and session revocation.
- Upgraded `gw-result` to 0.3 and migrated client HTTP errors to
  `httpException`.
- Documented the 0.1-to-0.2 migration and security invariants.

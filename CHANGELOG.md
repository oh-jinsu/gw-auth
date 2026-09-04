# Changelog

## 0.10.0 - 2026-09-04

- Made refresh rotation idempotent for requests that reuse the immediately
  previous token within 10 seconds, returning the exact persisted winning
  refresh token instead of revoking a healthy session during RSC/API races.
- Expanded `SessionRepository` with the current token's non-secret issuance
  metadata, previous token hash, and one atomic rotation classification result.
- Removed application claims from newly issued refresh-token payloads; current
  user claims remain loaded at refresh time and are carried only by access
  tokens and browser-safe auth state.

## 0.9.0 - 2026-09-03

- Added `createAuthResolver` with configurable `cookies()` and mixed-transport
  `request()` lookups bound to one shared session facade.
- Made request authentication prefer an exact Bearer header without cookie
  fallback and normalize both transports to the same `AuthState` contract.

## 0.8.0 - 2026-09-03

- Added `getAuthWithRefresh` for access verification, refresh-session rotation,
  and cookie application inside Next.js Server Actions and Route Handlers.
- Reused the Server Action cookie adapter for successful replacement cookies
  and terminal refresh cleanup without changing Proxy or mobile behavior.

## 0.7.0 - 2026-09-03

- Added authenticated browser and mobile account deletion with resumable,
  repository-backed pending state and core-owned Apple token revocation.
- Added fixed Next.js account-deletion routes and a repository conformance
  assertion for session revocation, provider ordering, and idempotent cleanup.

## 0.6.0 - 2026-09-03

- Moved terminal browser-refresh cleanup into core cookie effects so every
  adapter clears invalid sessions consistently without matching error codes.
- Added core-owned access-payload normalization and semantic error
  classification for reuse by framework adapters.
- Moved Flutter Android Apple package validation, callback filtering, and
  `signinwithapple` Intent construction from the Next.js adapter into the core
  `.android({ packageId })` projection and its `handoff` operation.
- Preserved precise JWT signing and expiration failures as internal causes
  while exposing issued-token workflow failures as `AUTH_SYSTEM_FAILURE`.

## 0.5.0 - 2026-09-03

- Rejected backslash-based external redirect bypasses, stripped all JWT-managed
  claims from application auth state, and rejected shared access/refresh keys.
- Normalized Next.js `getAuth` to `AuthState`, made logout clear stale local
  state after server-processed failures, preserved non-OK auth envelopes in the
  client, and corrected 400/401/502 status maps.
- Added fixed-route Origin and JSON Content-Type checks while preserving
  provider form-post callbacks and Origin-less native/server clients.
- Made fixed-route Google, Kakao, and Naver delivery explicit with
  `{ feature, browser, mobile }`, including mobile Google audience options.
- Kept password-reset discovery uniform across known-account storage and mail
  failures with an internal `onRequestError` observability hook.
- Added 10-second provider request and remote-key timeouts and separated invalid
  credentials, provider unavailability, and malformed successful responses.
- Bound stored Apple refresh tokens to their issuing client ID and moved
  revocation to `apple.revoke({ providerRefreshToken, providerClientId })`.
- Strengthened repository conformance assertions for duplicate social identity
  races, returned reset user IDs, and preservation of unrelated sessions.
- Documented mandatory application-owned rate limiting for every auth boundary.
- Removed internal operation names from public system-error messages while
  retaining them in the private error cause.
- Fixed the Next.js default HTTP mapping so invalid credentials, invalid
  refresh tokens, and session-user mismatches return 401 instead of 400.
- Extended the existing `routeHandler` and `serverAction` adapters to accept
  cookie-free `AuthResult<T>` operations as well as browser operations.
- Normalized the fixed `/api/auth/session` response to browser-safe `AuthState`
  without JWT metadata.
- Rejected passwords that bcrypt would truncate after 72 UTF-8 bytes during
  password login, signup, and reset.
- Added `gw-auth/testing` repository conformance assertions for refresh-session
  CAS, OAuth and social-signup single consumption, and atomic password reset
  with complete refresh-session revocation.
- Split Apple configuration into its Browser API for website and Android
  delivery and its Native API for iOS delivery, requiring the correct Services
  ID, App ID, and return URI at each boundary.
- Added server-owned, single-use state and nonce for Flutter Android Apple
  login and fixed Next.js routes that relay Apple's callback to the
  `sign_in_with_apple` Intent before completing token exchange.
- Replaced the ambiguous Apple mobile projection with `.browser(...).web()`,
  `.browser(...).android()`, and `.native(...).ios()`; no caller-selected
  client type is exposed.

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

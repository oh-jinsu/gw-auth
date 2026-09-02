# gw-auth Repository Instructions

## Purpose

- Keep authentication behavior and security invariants centralized so fixes apply consistently to every consuming service.
- Keep application-specific profile fields and database implementations outside the package.

## Architecture

- Put authentication decisions and workflows in server-side core services.
- Keep the core unaware of application frameworks. Framework code belongs in
  explicit adapter boundaries such as `gw-auth/nextjs` or in consuming apps.
- Keep framework-neutral source under `src/core` and Next.js-specific source
  under `src/nextjs`; publish them as explicit package subpaths.
- Co-locate each social provider's public composition, browser OAuth adapter,
  and mobile credential verifier under `src/core/social/<provider>`.
- Create one `createAuth` facade per authentication boundary. A `serviceName`
  identifies that boundary, not a delivery environment; never create separate
  `webAuth` and `mobileAuth` facades for the same users and sessions.
- Select `.browser()` and `.mobile()` from the same configured feature object.
  The prebuilt Next.js AuthRoute accepts those unprojected feature objects and
  owns their projections; callers must not pass `.browser()` results to it.
  Google, Kakao, and Naver entries must wrap `feature` and explicitly enable
  `browser`, `mobile`, or both so one delivery never forces the other's config.
  ```ts
  const password = auth.password({ repository });
  const authRoute = createAuthRoute({
    siteOrigin,
    session: auth.session,
    password,
  });
  ```
- Treat Apple as the provider-API exception to the ordinary projection names.
  Select Apple's Browser API before website or Android delivery, and its Native
  API before iOS delivery:
  ```ts
  const apple = auth.social({ repository, transactions }).apple(signing);
  apple.browser({ serviceId: webServiceId, redirectUri: webRedirectUri }).web();
  apple.browser({ serviceId: androidServiceId, redirectUri: androidRedirectUri }).android();
  apple.native({ appId }).ios();
  ```
  Do not expose a caller-selected `clientType`; each operation must request the
  identifier and callback values required by the Apple API it actually uses.
- Keep custom route-specific clients and endpoint conventions in consuming
  applications. The optional Next.js AuthRoute may own only its documented,
  fixed catch-all paths and bodies; customization uses direct Route Handlers.
- Keep the Next.js Proxy adapter route-agnostic. It may refresh GET and HEAD
  requests, but mutation boundaries must authenticate and authorize themselves.
- Expose feature-first composition such as
  `auth.social({ repository }).google(credentials).browser(options)`.
- Configure only shared session, token, and browser-cookie policy in
  `createAuth`; accept password, social, guest, and recovery repositories when
  their corresponding features are enabled.
- Derive JWT issuer, audience, and default browser-cookie prefixes from the
  required stable `serviceName`; keep individual cookie names as migration-only
  overrides.
- Keep public authentication operations independent of `Request`, `Response`,
  and framework types. Browser operations return structured cookie mutations
  for an external adapter to apply.
- Keep the existing Next.js `routeHandler` and `serverAction` adapters usable
  with both cookie-aware `BrowserOperation<T>` and cookie-free `AuthResult<T>`;
  do not create transport-specific wrapper names for the same mapping.
- Normalize the fixed browser session route to `AuthState`. JWT metadata is an
  internal transport detail and must not enter its client response contract.
  Apply the same normalization to Next.js `getAuth`; direct session verification
  remains the server-only API for full access-token payloads.
- Keep repositories as explicit ports. Operations that create an account and attach credentials or social identities must be atomic repository operations.
- Keep provider credential verification separate from local account creation and session issuance.
- Use server-side, hashed, single-use attempts for OAuth transactions, social signup, and password reset.
- Use random internal user identifiers. Never derive a user identifier from an email address, device identifier, or provider identifier.
- Keep browser cookie transports and mobile explicit-token transports separate.
- Keep mail, file, framework, and UI integrations in adapters rather than core services.

## Security Invariants

- Require JWT issuer, audience, token use, and runtime payload validation.
- Use distinct access and refresh token purposes and keys.
- Strip JWT-managed and identity/session claims from application claims before
  token issuance and omit them from the `AuthState` type.
- Store only SHA-256 hashes of high-entropy refresh tokens and one-time credentials.
- Rotate refresh tokens with compare-and-swap and revoke the session when reuse is detected.
- Bind browser OAuth callbacks to one-time state and an initiating-browser `HttpOnly` cookie. Use PKCE and nonce when supported by the provider.
- Start Android Apple Browser API requests with server-generated state and
  nonce stored as a hashed, single-use transaction. Relay Apple's callback
  fields to Flutter's exact `signinwithapple` Intent, then consume state and
  validate nonce when the app submits the authorization code.
- Build browser callback redirects from a configured trusted origin, never an unvalidated request `Host` header.
- Reject relative redirects containing backslashes as well as protocol-relative
  or absolute values.
- Require the fixed Next.js JSON routes to receive a JSON Content-Type and
  reject present foreign Origin headers. Allow absent Origin for native/server
  clients and exempt only provider-owned form-post callbacks.
- Never expose browser refresh tokens in response bodies or browser-readable storage.
- Never use a client-provided device identifier as a guest credential.
- Return the same public password-reset request response whether an account exists or not.
- Conceal known-account attempt-storage and mail-delivery failures while
  reporting them through the optional internal `onRequestError` observer.
- Consume password-reset attempts atomically with the password update and refresh-session revocation.
- Reject any password that bcrypt would truncate after 72 UTF-8 bytes before
  hashing or comparison. Applications continue to own product password rules.
- Never auto-link accounts solely because provider and local email addresses match.
- Require HTTP adapters to mark authentication and credential-bearing responses
  with `Cache-Control: no-store`.
- Encrypt recoverable provider refresh tokens at rest.
- Persist Apple's issuing client ID beside its encrypted provider refresh token
  and revoke through the base Apple feature using both stored values.
- Bound bundled provider HTTP and remote-key calls with timeouts. Distinguish
  invalid credentials from transport, throttling, upstream, and malformed-response failures.
- Keep rate limiting at the consuming HTTP boundary; require it for every
  authentication, recovery, OAuth, guest, refresh, and credential-bearing route.

## Errors and Observability

- Use `gw-result` for expected failures and throwing boundaries.
- Preserve infrastructure failures and their causes through core services.
- Keep public system-error messages generic and place operation names only in
  the internal cause used for observability.
- Convert errors to sanitized HTTP responses only in HTTP adapters.
- Do not use `instanceof` across package boundaries to recognize public error contracts; use stable structural discriminants.

## Documentation and Tests

- Add JSDoc to every function, method, class, interface, and exported type. Document security-sensitive assumptions and repository atomicity requirements.
- Test success, malformed input, expected failures, concurrency, replay, transport secrecy, ESM/CJS exports, and packaged artifacts.
- Keep reusable repository-contract assertions under `gw-auth/testing`. They
  test consumer-owned repositories and must not introduce an ORM or app schema.
- Update `README.md`, `MIGRATION.md`, and `CHANGELOG.md` whenever a public contract or security invariant changes.
- Review the complete diff and run build, type checks, tests, audit, and a dry-run package before release.

## Release

- Do not run `npm publish` manually.
- Commit release changes and push `main`; the repository workflow publishes the package.
- Verify the publish workflow and registry version before updating consuming services.

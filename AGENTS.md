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
- Keep route-specific browser clients and endpoint conventions in consuming
  applications or separate adapter packages.
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
- Keep repositories as explicit ports. Operations that create an account and attach credentials or social identities must be atomic repository operations.
- Keep provider credential verification separate from local account creation and session issuance.
- Use server-side, hashed, single-use attempts for OAuth transactions, social signup, and password reset.
- Use random internal user identifiers. Never derive a user identifier from an email address, device identifier, or provider identifier.
- Keep browser cookie transports and mobile explicit-token transports separate.
- Keep mail, file, framework, and UI integrations in adapters rather than core services.

## Security Invariants

- Require JWT issuer, audience, token use, and runtime payload validation.
- Use distinct access and refresh token purposes and keys.
- Store only SHA-256 hashes of high-entropy refresh tokens and one-time credentials.
- Rotate refresh tokens with compare-and-swap and revoke the session when reuse is detected.
- Bind browser OAuth callbacks to one-time state and an initiating-browser `HttpOnly` cookie. Use PKCE and nonce when supported by the provider.
- Build browser callback redirects from a configured trusted origin, never an unvalidated request `Host` header.
- Never expose browser refresh tokens in response bodies or browser-readable storage.
- Never use a client-provided device identifier as a guest credential.
- Return the same public password-reset request response whether an account exists or not.
- Consume password-reset attempts atomically with the password update and refresh-session revocation.
- Never auto-link accounts solely because provider and local email addresses match.
- Require HTTP adapters to mark authentication and credential-bearing responses
  with `Cache-Control: no-store`.
- Encrypt recoverable provider refresh tokens at rest.

## Errors and Observability

- Use `gw-result` for expected failures and throwing boundaries.
- Preserve infrastructure failures and their causes through core services.
- Convert errors to sanitized HTTP responses only in HTTP adapters.
- Do not use `instanceof` across package boundaries to recognize public error contracts; use stable structural discriminants.

## Documentation and Tests

- Add JSDoc to every function, method, class, interface, and exported type. Document security-sensitive assumptions and repository atomicity requirements.
- Test success, malformed input, expected failures, concurrency, replay, transport secrecy, ESM/CJS exports, and packaged artifacts.
- Update `README.md`, `MIGRATION.md`, and `CHANGELOG.md` whenever a public contract or security invariant changes.
- Review the complete diff and run build, type checks, tests, audit, and a dry-run package before release.

## Release

- Do not run `npm publish` manually.
- Commit release changes and push `main`; the repository workflow publishes the package.
- Verify the publish workflow and registry version before updating consuming services.

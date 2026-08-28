# Changelog

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

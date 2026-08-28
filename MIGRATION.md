# Migrating from gw-auth 0.1 to 0.2

## Version boundary

Version 0.2 introduces a recommended mobile authentication path while keeping
the 0.1 browser handlers and `AuthService` available. Existing applications can
stay on `0.1.x`; applications adopting mobile sessions should upgrade
deliberately to `0.2.x`.

`gw-result` is upgraded to 0.3. Caught boundary errors are now typed as
`unknown`. Narrow them before reading error-specific fields.

## Mobile migration

1. Add a refresh-session table with a unique session id, user id, SHA-256 token
   hash, expiration time, and timestamps.
2. Implement `SessionRepository`. Make `rotateRefreshSession` a single
   compare-and-swap database update using both the session id and previous hash.
3. Construct separate `JWTManager` instances for access and refresh tokens.
   Use different secrets, a stable issuer, 30-minute access expiry, and 30-day
   refresh expiry unless the product has a stricter policy.
4. Exchange Google ID tokens, Kakao access tokens, or Apple authorization codes
   with the matching mobile verifier.
5. Find or create the local account from the verified `SocialIdentity`, then
   call `SessionAuthService.issueTokenPair`.
6. Keep the access token in app memory. Store only the refresh token in the
   platform Keychain or Keystore.
7. On refresh, replace both stored tokens. On logout, call `revokeSession`. On
   account deletion, call `revokeUserSessions` and revoke any stored Apple
   provider refresh token.

## Security notes

- Never accept provider claims decoded without signature verification.
- Never use a social provider token as a long-lived application bearer token.
- Never store a plaintext application refresh token in the database.
- Never implement rotation as an unconditional update; it must reject a stale
  previous hash.
- Encrypt Apple provider refresh tokens at rest because they must remain
  recoverable for Apple's revocation endpoint.

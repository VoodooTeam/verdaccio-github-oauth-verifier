# verdaccio-github-oauth-verifier
[![npm version](https://img.shields.io/npm/v/verdaccio-github-oauth-verifier.svg)](https://www.npmjs.com/package/verdaccio-github-oauth-verifier)

A [Verdaccio](https://verdaccio.org/) auth plugin that verifies JWT tokens issued by [verdaccio-github-oauth-ui](https://github.com/n4bb12/verdaccio-github-oauth-ui) (or compatible OAuth UI) against GitHub organization membership, with optional JWT tracking and blacklisting for security.

## Features

- **Organization membership check**: Validates that the user in the JWT is still a member of a configured GitHub organization via the GitHub API.
- **In-memory cache**: Caches verification results to reduce GitHub API calls (configurable TTL).
- **Optional JWT tracking**: When enabled, only the most recent JWT per user is accepted; older tokens are rejected (e.g. after re-login or token rotation).
- **Revocation**: Admin endpoints to invalidate a user’s JWT or clear cache entries.
- **Scheduled cleanup**: Cron-based cleanup of expired JWT tracking entries in the SQLite database.

## Requirements

- Verdaccio 3.x
- An auth plugin that issues JWTs with a `name` claim (e.g. **verdaccio-github-oauth-ui**). This plugin does not issue tokens; it only verifies them.

## Installation

```bash
npm install verdaccio-github-oauth-verifier
```

or 

```bash
yarn install verdaccio-github-oauth-verifier
```

## Configuration

Add the plugin to your Verdaccio config (e.g. `config.yaml`):

```yaml
middlewares:
  github-oauth-verifier:
    enabled: true
    org: your-github-org-name
    auth:
      github-oauth-ui:
        token: your-github-personal-access-token-or-app-token
    # Optional: cache TTL in minutes (default: 8 hours = 480)
    cacheTTLMinutes: 480
    # Optional: JWT tracking (single token per user)
    jwtTrackingDbPath: ./jwt-tracking.db
    # Optional: cron for cleaning expired JWT tracking rows (default: daily at midnight)
    jwtCleanupSchedule: "0 0 * * *"
```

### Configuration options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `enabled` | boolean | No | Enable the plugin. Default: `true` if the plugin block is present. |
| `org` | string | Yes* | GitHub organization name. Users must be members of this org. |
| `auth.github-oauth-ui.token` | string | Yes* | GitHub token (Personal Access Token or GitHub App token) with `read:org` to check org membership. |
| `cacheTTLMinutes` | number | No | How long to cache verification results (minutes). Default: `480` (8 hours). |
| `jwtTrackingDbPath` | string | No | Path to SQLite DB for JWT tracking. When set, only the most recent JWT per user is valid. Example: `./jwt-tracking.db`. |
| `jwtCleanupSchedule` | string | No | Cron expression for cleanup of expired JWT tracking rows. Default: `0 0 * * *` (daily at midnight). Format: 5 fields `minute hour day month weekday` or 6 with seconds. |

\* Required when the plugin is enabled. If `token` or `org` is missing, the plugin disables itself and logs an error.

### GitHub token

Create a Personal Access Token (or use a GitHub App token) with **read:org** and configure it under `auth.github-oauth-ui.token`. The same token is often shared with the OAuth UI plugin for consistency. Keep it secret and restrict scope.

## JWT tracking (single token per user)

When `jwtTrackingDbPath` is set:

- The plugin stores the latest JWT per user (by hash and `iat`) in a SQLite database.
- Only that latest token is accepted; any older token for the same user returns `401` with “JWT token has been superseded by a newer login”.
- Expired tokens are rejected and the user’s row is removed when the token is seen as expired.
- You can revoke a user’s token via the admin endpoint (see below); the plugin marks them as revoked and rejects that token.
- A cron job (or the configured `jwtCleanupSchedule`) deletes rows whose `exp` is in the past.

This helps enforce “one active session per user” and allows revoking access without waiting for token expiry.

## Admin API endpoints

Both endpoints require the **Bearer** token equal to `auth.github-oauth-ui.token` in the `Authorization` header.

### Invalidate JWT for a user

```http
POST /-/github-oauth-verifier/invalidate-jwt?username=<username>
Authorization: Bearer <your-admin-token>
```

Marks the user’s token as revoked (when JWT tracking is enabled) and removes them from the in-memory cache. Subsequent requests with that user’s JWT will receive `401` with “GitHub authorization revoked”.

### Clear cache

```http
POST /-/github-oauth-verifier/clear-cache?username=<username>
Authorization: Bearer <your-admin-token>
```

- With `username`: clears the cache entry for that user only.
- Without `username`: clears the entire verification cache.

Use this to force re-validation against GitHub on the next request (e.g. after org membership changes).

## Behavior summary

1. **No `Authorization` header**: Request passes through; no verification.
2. **Invalid or non-JWT `Authorization`**: Request passes through (plugin only validates JWTs it can parse).
3. **Valid JWT**:
   - If JWT tracking is enabled: check single-token-per-user and revocation; reject if superseded or revoked.
   - If the username is in the cache and allowed → allow request.
   - If the username is in the cache and disallowed → `401` “GitHub authorization revoked”.
   - Otherwise: call GitHub API `GET /orgs/{org}/members/{username}`. If `204` → allow and cache; if `404` (or other failure) → deny, cache denial, and optionally mark as revoked in JWT tracking.

Errors talking to GitHub or invalid tokens are treated as “fail closed”: access is denied.

## License

MIT

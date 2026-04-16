# verdaccio-github-oauth-verifier

[![npm version](https://img.shields.io/npm/v/verdaccio-github-oauth-verifier.svg)](https://www.npmjs.com/package/verdaccio-github-oauth-verifier)

A [Verdaccio](https://verdaccio.org/) auth plugin that verifies JWT tokens issued by [verdaccio-github-oauth-ui](https://github.com/n4bb12/verdaccio-github-oauth-ui) (or compatible OAuth UI) against GitHub organization membership, with optional JWT tracking and blacklisting for security.

## Features

- **Organization membership check**: Validates that the user in the JWT is still a member of a configured GitHub organization via the GitHub API.
- **In-memory cache**: Caches verification results to reduce GitHub API calls (configurable TTL).
- **Optional JWT tracking**: When enabled, only the most recent JWT per user is accepted; older tokens are rejected (e.g. after re-login or token rotation).
- **Revocation**: Admin endpoints to invalidate a user’s JWT or clear cache entries.
- **Scheduled cleanup**: Cron-based cleanup of expired JWT tracking entries in the SQLite database.
- **Allow list**: Optional GitHub logins that skip this plugin’s JWT tracking and org checks after decoding `name`; Verdaccio still validates the JWT (e.g. CI or generated tokens).

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
    # Option A: use a Personal Access Token (or GitHub App token) with read:org
    token: your-github-token
    # Option B: use a GitHub App (clientId + pem); if both are set, GitHub App is used for org checks
    # githubApp:
    #   clientId: "123456"
    #   pem: "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
    #   installationId: 12345  # optional; resolved from org if omitted
    # adminToken: "optional-token-for-admin-endpoints-when-using-github-app-only"
    adminToken: "super-secret-token-for-admin-endpoints"
    cacheTTLMinutes: 480
    jwtTrackingEnabled: true
    jwtCleanupSchedule: "0 0 * * *"
    # Optional: these logins skip JWT tracking + org checks here; Verdaccio validates the JWT (case-insensitive).
    # allowList:
    #   - my-ci-bot
    #   - github-actions
```

### Configuration options

| Option                       | Type    | Required | Description                                                                                                                                                             |
| ---------------------------- | ------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `enabled`                    | boolean | No       | Enable the plugin. Default: `true` if the plugin block is present.                                                                                                      |
| `org`                        | string  | Yes      | GitHub organization name. Users must be members of this org.                                                                                                            |
| `token`                      | string  | Yes*     | GitHub token (PAT or GitHub App token) with `read:org`. Required unless `githubApp` is configured.                                                                      |
| `githubApp`                  | object  | Yes*     | GitHub App credentials. Required unless `auth.github-oauth-ui.token` is set. If both are set, GitHub App is used for org membership checks.                             |
| `githubApp.clientId`         | string  | Yes**    | GitHub App ID (numeric, from app settings). Required when using `githubApp`.                                                                                            |
| `githubApp.pem`              | string  | Yes**    | Private key: PEM content (multi-line string) or path to a `.pem` file. Required when using `githubApp`.                                                                 |
| `githubApp.installationId`   | number  | No       | Installation ID for the org. If omitted, the plugin resolves it via `GET /orgs/{org}/installation`.                                                                     |
| `adminToken`                 | string  | No       | Token for admin endpoints. When using GitHub App only (no `auth.github-oauth-ui.token`), set this to protect admin routes. Otherwise admin uses the same token.         |
| `cacheTTLMinutes`            | number  | No       | How long to cache verification results (minutes). Default: `480` (8 hours).                                                                                             |
| `jwtTrackingEnabled`         | boolean | No       | When `true`, enable JWT tracking (only the most recent JWT per user). DB is stored at `~/.verdaccio/jwt-tracking.db`.                                                   |
| `jwtCleanupSchedule`         | string  | No       | Cron expression for cleanup of expired JWT tracking rows. Default: `0 0 * * *` (daily at midnight). Format: 5 fields `minute hour day month weekday` or 6 with seconds. |
| `allowList`                  | string[] | No       | GitHub usernames (logins) that bypass JWT tracking and org membership in this plugin. Matching is case-insensitive; invalid entries are skipped with a warning. Verdaccio remains responsible for JWT integrity and expiry. |

\* At least one of `auth.github-oauth-ui.token` or `githubApp` (with `clientId` and `pem`) is required when the plugin is enabled.  
\** Required when `githubApp` is used.

### Token (Personal Access Token or GitHub App token)

Create a Personal Access Token (or use a GitHub App token) with **read:org** and configure it under `auth.github-oauth-ui.token`. The same token is often shared with the OAuth UI plugin for consistency. Keep it secret and restrict scope.

### GitHub App

You can use a **GitHub App** instead of a single token for org membership checks. The plugin will:

1. Sign a JWT with your App ID and private key (PEM).
2. Resolve the installation ID for your org (from config or via `GET /orgs/{org}/installation`).
3. Exchange the JWT for an installation access token (cached until ~5 minutes before expiry).
4. Call `GET /orgs/{org}/members/{username}` with that token.

**Setup:** Create a GitHub App, install it on your organization, and grant **Members** read permission (or the scope needed for org membership). Then set `githubApp.clientId` (your App ID from the app settings page) and `githubApp.pem` (private key content or path to the `.pem` file). Optionally set `githubApp.installationId` to skip the installation lookup. If you do not set `auth.github-oauth-ui.token`, you must set `adminToken` to protect the admin endpoints (invalidate JWT, clear cache).

**If you see "GitHub org installation lookup failed: 404":** The app is not installed on the organization named in `org`, or the org name is wrong. Install the app on that org (e.g. **Organization settings → GitHub Apps → Install App** or the link in the error message), or set `githubApp.installationId` to the installation ID (see below).

#### Finding the installation ID (custom / developer app)

If your app was created in **Developer settings** (not from the marketplace) and is only for your org:

- **Organization-owned app:**  
  1. Go to **Organization** → **Settings** (or `https://github.com/organizations/<your-org>/settings`).  
  2. In the left sidebar, under **Third-party access** or **Integrations**, open **GitHub Apps**.  
  3. Click your app, then **Configure** (or open the installation you use).  
  4. The URL in the browser will look like:  
     `https://github.com/organizations/<org-name>/settings/installations/<ID>`  
     The number at the end is the **installation ID**. Use it as `githubApp.installationId` in config.

- **User-owned app (your personal account):**  
  **Profile** → **Settings** → **Applications** → your app → **Configure**. The installation ID is the number at the end of that page’s URL.

Setting `installationId` avoids the automatic org lookup and works even when the API lookup returns 404 (e.g. for some org-only or private setups).

### Allow list (`allowList`)

Use `allowList` when some accounts should use the registry without this plugin enforcing org membership or single-token JWT tracking—common for **CI**, **machine users**, or **generated JWTs** where Verdaccio’s own JWT verification is enough.

- After a minimal decode of the JWT payload (three segments, Base64 payload, `name` claim), if `name` is allow-listed, the plugin calls `next()` immediately: **no** JWT tracking DB updates, **no** expiry/revocation/superseded checks in this plugin, **no** org API or org cache.
- The plugin still requires a parseable JWT and a valid `name` string. **Verdaccio** (and your auth plugin) should verify signature, `exp`, and any other claims as usual.
- Admin “invalidate JWT” in this plugin does not apply to traffic that never enters JWT tracking; use Verdaccio/auth mechanisms to revoke those users if needed.

## JWT tracking (single token per user)

When `jwtTrackingEnabled` is `true` (and the user is **not** on `allowList`):

- The plugin stores the latest JWT per user (by hash and `iat`) in a SQLite database at `~/.verdaccio/jwt-tracking.db`.
- Only that latest token is accepted; any older token for the same user returns `401` with “JWT token has been superseded by a newer login”.
- Expired tokens are rejected and the user’s row is removed when the token is seen as expired.
- You can revoke a user’s token via the admin endpoint (see below); the plugin marks them as revoked and rejects that token.
- A cron job (or the configured `jwtCleanupSchedule`) deletes rows whose `exp` is in the past.

This helps enforce “one active session per user” and allows revoking access without waiting for token expiry.

## Admin API endpoints

Both endpoints require a **Bearer** token in the `Authorization` header. The accepted token is `adminToken` if set, otherwise `auth.github-oauth-ui.token`. When using GitHub App only (no OAuth token), set `adminToken` to protect these routes.

### Invalidate JWT

```http
POST /-/github-oauth-verifier/invalidate-jwt?username=<username>
Authorization: Bearer <your-admin-token>
```

- With `username`: marks that user’s token as revoked (when JWT tracking is enabled) and removes them from the in-memory cache.
- Without `username`: marks all users’ tokens as revoked and clears the entire cache.

Subsequent requests with a revoked user’s JWT will receive `401` with “GitHub authorization revoked”.

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
3. **Valid JWT** (three segments, decodable payload, valid `name`):
  - If the username is in `allowList` → `next()` immediately (no JWT tracking or org logic in this plugin; Verdaccio validates the token).
  - If JWT tracking is enabled: check single-token-per-user and revocation; reject if superseded or revoked.
  - If the username is in the cache and allowed → allow request.
  - If the username is in the cache and disallowed → `401` “GitHub authorization revoked”.
  - Otherwise: call GitHub API `GET /orgs/{org}/members/{username}`. If `204` → allow and cache; if `404` (or other failure) → deny, cache denial, and optionally mark as revoked in JWT tracking.

Errors talking to GitHub or invalid tokens are treated as “fail closed”: access is denied.

## License

MIT
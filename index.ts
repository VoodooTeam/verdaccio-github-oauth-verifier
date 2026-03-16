import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import { LRUCache } from 'lru-cache';
import cron, { type ScheduledTask } from 'node-cron';
import os from 'os';
import path from 'path';
import githubAppJwt from 'universal-github-app-jwt';
import { JwtTrackingDb } from './jwt-tracking';

/** Reusable tag for plugin log messages (e.g. for filtering in log aggregation). */
const LOG_TAG = '[verdaccio-github-oauth-verifier]';

/** Max length for username (used in DB and cache); avoids abuse and aligns with common limits. */
const MAX_USERNAME_LENGTH = 256;

/** Control characters and null byte – must not appear in usernames passed to DB/cache. */
const CONTROL_CHARS = /[\x00-\x1f\x7f]/;

/**
 * Returns true if the value is a safe username for use in DB/cache (defense in depth against injection).
 * Call this for any user-supplied username before passing to jwtTracking or cache.
 */
function isValidUsername(value: string | null): value is string {
  if (value === null || typeof value !== 'string') return false;
  const s = value.trim();
  return s.length > 0 && s.length <= MAX_USERNAME_LENGTH && !CONTROL_CHARS.test(s);
}

/** If value looks like PEM content (contains -----BEGIN), return as-is; else read from file path. */
function loadPem(value: string): string {
  const trimmed = value.trim();
  if (trimmed.includes('-----BEGIN')) {
    return trimmed;
  }
  return fs.readFileSync(trimmed, 'utf8');
}

/** GitHub App credentials for installation-based API auth (optional alternative to token). */
interface GithubAppConfig {
  /** GitHub App ID (numeric, from app settings). */
  clientId: string;
  /** Private key PEM content, or path to a .pem file. */
  pem: string;
  /** Installation ID for the org. If omitted, resolved via GET /orgs/{org}/installation. */
  installationId?: number;
}

interface PluginConfig {
  enabled?: boolean;
  token?: string;
  org?: string;
  /** Optional: use GitHub App (clientId + pem) instead of token for org membership checks. */
  githubApp?: GithubAppConfig;
  /** Optional: token for admin endpoints. */
  adminToken?: string;
  cacheTTLMinutes?: number;
  /** When true, enable JWT tracking (only the most recent JWT per user). DB is stored at ~/.verdaccio/jwt-tracking.db. */
  jwtTrackingEnabled?: boolean;
  /**
   * Cron expression for JWT tracking cleanup. Default: '0 0 * * *' (daily at midnight).
   * Format: minute hour day-of-month month day-of-week (5 fields), or second + those 5 (6 fields).
   * Examples: '0 0 * * *' midnight daily, '0 0 * * * *' every minute at 0 sec, every N seconds use 6-field cron.
   */
  jwtCleanupSchedule?: string;
}

interface PluginStuff {
  logger: {
    info: (msg: string) => void;
    warn: (msg: string) => void;
    error: (msg: string) => void;
    /** Bunyan-style debug; only emitted when Verdaccio log level is debug or lower. */
    debug?: (msg: string) => void;
  };
}

/** Normalized GitHub App config with PEM content loaded (not a path). */
interface GithubAppConfigLoaded {
  clientId: string;
  pem: string;
  installationId?: number;
}

class GithubOAuthVerifierMiddleware {
  private readonly stuff: PluginStuff;
  private readonly enabled: boolean;
  /** OAuth/token for API when not using GitHub App; also used for admin when adminToken not set. */
  private readonly token: string;
  private readonly org: string;
  /** When true, use GitHub App installation token for verifyUserInGitHubApp. */
  private readonly useGitHubApp: boolean;
  /** Set when useGitHubApp; PEM content already loaded. */
  private readonly githubApp: GithubAppConfigLoaded | null;
  /** Token for admin endpoints; falls back to token when not set. */
  private readonly adminToken: string;
  /** Resolved installation ID when not in config (cached after first resolution). */
  private installationIdCache: number | null = null;
  /** Cached installation access token and expiry (reused until ~5 min before expiry). */
  private installationTokenCache: { token: string; expiresAt: number } | null = null;
  private readonly cache: LRUCache<string, boolean>;
  private readonly jwtTracking: JwtTrackingDb | null;
  /** Cron expression for cleanup. Default '0 0 * * *'. */
  private readonly jwtCleanupSchedule: string;
  private cleanupTask: ScheduledTask | null = null;

  constructor(config: PluginConfig | undefined, stuff: PluginStuff) {
    this.stuff = stuff;
    this.stuff.logger.info(`${LOG_TAG} Configuring`);

    this.enabled = config != null && config.enabled !== false;
    this.cache = new LRUCache({ max: 1000, ttl: config?.cacheTTLMinutes ? config.cacheTTLMinutes * 60 * 1000 : 1000 * 60 * 60 * 8 });

    if (config?.jwtTrackingEnabled === true) {
      try {
        const verdaccioDir = path.join(os.homedir(), '.verdaccio');
        fs.mkdirSync(verdaccioDir, { recursive: true });
        const dbPath = path.join(verdaccioDir, 'jwt-tracking.db');
        this.jwtTracking = new JwtTrackingDb(dbPath);
      } catch (err) {
        this.stuff.logger.warn(`${LOG_TAG} JWT tracking disabled: could not init DB at ~/.verdaccio/jwt-tracking.db: ${err}`);
        this.jwtTracking = null;
      }
    } else {
      this.jwtTracking = null;
    }
    const raw = config?.jwtCleanupSchedule?.trim();
    this.jwtCleanupSchedule = raw && raw.length > 0 ? raw : '0 0 * * *';
    if (this.jwtTracking) {
      this.stuff.logger.info(`${LOG_TAG} JWT tracking DB enabled (only most recent token per user)`);
      this.scheduleCleanup();
    }

    if (!this.enabled) {
      this.stuff.logger.info(`${LOG_TAG} Disabled`);
      this.token = '';
      this.org = '';
      this.useGitHubApp = false;
      this.githubApp = null;
      this.adminToken = '';
      return;
    }

    this.org = config?.org ?? '';
    if (!this.org) {
      this.stuff.logger.error(`${LOG_TAG} org is missing, disabling plugin`);
      this.token = '';
      this.useGitHubApp = false;
      this.githubApp = null;
      this.adminToken = '';
      return;
    }

    const oauthToken = config?.token ?? '';
    const githubAppConfig = config?.githubApp;
    const hasToken = Boolean(oauthToken?.trim());
    const hasGitHubApp =
      Boolean(githubAppConfig?.clientId?.trim() && githubAppConfig?.pem?.trim());

    if (!hasToken && !hasGitHubApp) {
      this.stuff.logger.error(
        `${LOG_TAG} Neither token (auth.github-oauth-ui.token) nor GitHub App (githubApp.clientId + githubApp.pem) is configured, disabling plugin`
      );
      this.token = '';
      this.useGitHubApp = false;
      this.githubApp = null;
      this.adminToken = '';
      return;
    }

    this.adminToken = config?.adminToken?.trim() ?? '';
    if (hasGitHubApp && githubAppConfig) {
      try {
        const pem = loadPem(githubAppConfig.pem);
        this.githubApp = {
          clientId: githubAppConfig.clientId.trim(),
          pem,
          installationId: githubAppConfig.installationId
        };
        this.useGitHubApp = true;
        this.token = oauthToken?.trim() ?? '';
        this.stuff.logger.info(`${LOG_TAG} Using GitHub App for org membership checks`);
      } catch (err) {
        this.stuff.logger.error(`${LOG_TAG} Failed to load GitHub App PEM: ${err}`);
        this.token = '';
        this.useGitHubApp = false;
        this.githubApp = null;
        this.adminToken = '';
        return;
      }
    } else {
      this.token = oauthToken?.trim() ?? '';
      this.useGitHubApp = false;
      this.githubApp = null;
      this.stuff.logger.info(`${LOG_TAG} Using token for org membership checks`);
    }
  }

  /** Log at debug level; no-op if logger has no debug (e.g. in tests). Only emitted when Verdaccio log level is debug. */
  private logDebug(msg: string): void {
    if (typeof this.stuff.logger.debug === 'function') {
      this.stuff.logger.debug(`${LOG_TAG} ${msg}`);
    }
  }

  /** Schedules JWT cleanup using cron expression (jwtCleanupSchedule). */
  private scheduleCleanup(): void {
    const runCleanup = (): void => {
      try {
        this.jwtTracking?.deleteExpired();
        this.stuff.logger.info(`${LOG_TAG} JWT tracking: expired entries cleaned up`);
      } catch (err) {
        this.stuff.logger.error(`${LOG_TAG} JWT tracking cleanup failed: ${err}`);
      }
    };

    let expression = this.jwtCleanupSchedule;
    if (!cron.validate(expression)) {
      this.stuff.logger.warn(
        `${LOG_TAG} Invalid jwtCleanupSchedule "${expression}", using default "0 0 * * *"`
      );
      expression = '0 0 * * *';
    }
    this.cleanupTask = cron.schedule(expression, runCleanup);
  }

  /** Create a JWT for the GitHub App (used to get installation token). */
  private async createAppJwt(): Promise<string> {
    if (!this.githubApp) throw new Error('GitHub App not configured');
    const { token } = await githubAppJwt({
      id: this.githubApp.clientId,
      privateKey: this.githubApp.pem
    });
    return token;
  }

  /** Resolve installation ID from config or via GET /orgs/{org}/installation (with user fallback on 404). */
  private async getInstallationId(): Promise<number> {
    if (this.githubApp?.installationId != null) {
      return this.githubApp.installationId;
    }
    if (this.installationIdCache != null) {
      return this.installationIdCache;
    }
    const jwt = await this.createAppJwt();
    const headers = {
      Authorization: `Bearer ${jwt}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28'
    };

    // Try org installation first (required for org membership checks)
    let response = await fetch(`https://api.github.com/orgs/${encodeURIComponent(this.org)}/installation`, {
      method: 'GET',
      headers
    });

    // If 404, try user installation (app may be installed on a user account with same slug)
    if (response.status === 404) {
      const userResponse = await fetch(`https://api.github.com/users/${encodeURIComponent(this.org)}/installation`, {
        method: 'GET',
        headers
      });
      if (userResponse.ok) {
        response = userResponse;
      }
    }

    if (!response.ok) {
      const text = await response.text();
      if (response.status === 404) {
        throw new Error(
          `GitHub App is not installed on organization (or user) "${this.org}". ` +
            `Install the app on the org at https://github.com/organizations/${encodeURIComponent(this.org)}/settings/installations, ` +
            `or set githubApp.installationId in config to the installation ID from your app's installation URL. Original: ${response.status} ${text}`
        );
      }
      throw new Error(`GitHub org installation lookup failed: ${response.status} ${text}`);
    }
    const data = (await response.json()) as { id: number };
    this.installationIdCache = data.id;
    return data.id;
  }

  /** Cached installation access token (reused until ~5 min before expiry). */
  private async getInstallationAccessToken(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const margin = 5 * 60; // 5 minutes
    if (
      this.installationTokenCache != null &&
      this.installationTokenCache.expiresAt > now + margin
    ) {
      return this.installationTokenCache.token;
    }
    const jwt = await this.createAppJwt();
    const installationId = await this.getInstallationId();
    const response = await fetch(
      `https://api.github.com/app/installations/${installationId}/access_tokens`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${jwt}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28'
        }
      }
    );
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`GitHub installation token request failed: ${response.status} ${text}`);
    }
    const data = (await response.json()) as { token: string; expires_at: string };
    const expiresAt = new Date(data.expires_at).getTime() / 1000;
    this.installationTokenCache = { token: data.token, expiresAt };
    return data.token;
  }

  // eslint-disable-next-line camelcase
  register_middlewares(
    app: {
      use: (fn: (req: Request, res: Response, next: NextFunction) => void) => void;
      post?: (path: string, ...handlers: Array<(req: Request, res: Response, next: NextFunction) => void>) => void;
    },
    _authInstance: unknown,
    storageInstance: unknown
  ): void {
    if (!this.enabled) {
      return;
    }

    if (!this.org || (!this.token && !this.useGitHubApp)) {
      this.stuff.logger.error(
        `${LOG_TAG} org or auth (token or GitHub App) is missing, skipping middleware setup`
      );
      return;
    }

    this.stuff.logger.info(
      `${LOG_TAG} register_middlewares loaded`
    );

    if (app.post) {
      app.post(
        '/-/github-oauth-verifier/invalidate-jwt',
        (req: Request, res: Response, next: NextFunction) => this.requireAdminToken(req, res, next),
        (req: Request, res: Response) => {
          const raw = typeof req.query?.username === 'string' ? req.query.username.trim() : null;
          if (raw !== null && raw !== '') {
            if (!isValidUsername(raw)) {
              res.status(400).json({ error: 'Invalid username' });
              return;
            }
            this.jwtTracking?.setRevoked(raw);
            this.cache.delete(raw);
            this.stuff.logger.info(`${LOG_TAG} JWT invalidated for user: ${raw}`);
            res.status(200).json({ ok: true, message: `JWT invalidated for user: ${raw}` });
          } else {
            this.jwtTracking?.setRevokedAll();
            this.cache.clear();
            this.stuff.logger.info(`${LOG_TAG} JWT invalidated for all users`);
            res.status(200).json({ ok: true, message: 'JWT invalidated for all users' });
          }
        }
      );
      app.post(
        '/-/github-oauth-verifier/clear-cache',
        (req: Request, res: Response, next: NextFunction) => this.requireAdminToken(req, res, next),
        (req: Request, res: Response) => {
          const raw = typeof req.query?.username === 'string' ? req.query.username.trim() : null;
          if (raw !== null && raw !== '') {
            if (!isValidUsername(raw)) {
              res.status(400).json({ error: 'Invalid username' });
              return;
            }
            this.cache.delete(raw);
            this.stuff.logger.info(`${LOG_TAG} Cache cleared for user: ${raw}`);
            res.status(200).json({ ok: true, message: `Cache cleared for user: ${raw}` });
          } else {
            this.cache.clear();
            this.stuff.logger.info(`${LOG_TAG} Entire cache cleared`);
            res.status(200).json({ ok: true, message: 'Entire cache cleared' });
          }
        }
      );
    }

    app.use(async (req: Request, res: Response, next: NextFunction) => {
      if (!req.headers?.authorization) {
        return next();
      }

      const token = req.headers.authorization.split(' ')[1];

      try {
        const tokenParts = token.split('.');
        if (tokenParts.length !== 3) return next();

        const payloadBase64 = tokenParts[1];
        const decodedPayload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf8'));
        const usernameRaw = typeof decodedPayload.name === 'string' ? decodedPayload.name.trim() : '';
        const iat = typeof decodedPayload.iat === 'number' ? decodedPayload.iat : 0;
        const exp = typeof decodedPayload.exp === 'number' ? decodedPayload.exp : null;

        if (!isValidUsername(usernameRaw)) {
          this.logDebug(`Rejecting token: invalid or missing username in payload`);
          return res.status(401).json({ error: 'Invalid token' });
        }
        const username = usernameRaw;

        this.logDebug(`JWT payload: ${JSON.stringify(decodedPayload)}`);
        this.logDebug(`Verifying user="${username}" iat=${iat} exp=${exp}`);

        if (this.jwtTracking) {
          const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
          const latest = this.jwtTracking.getLatest(username);

          this.logDebug(
            `JWT tracking: latest=${latest === null ? 'null' : `{ revoked=${!!latest.revoked}, iat=${latest.iat} }`}`
          );

          if (latest !== null && latest.revoked) {
            const isSameToken = latest.token_hash === tokenHash && latest.iat === iat;
            this.logDebug(
              `User "${username}" has revoked token in DB; isSameToken=${isSameToken} (token_hash match, iat match)`
            );
            if (isSameToken) {
              this.logDebug('Denying: GitHub authorization revoked (same token was revoked)');
              return res.status(401).json({ error: 'GitHub authorization revoked' });
            }
          }

          if (exp !== null && exp < Math.floor(Date.now() / 1000)) {
            this.logDebug(`Denying: JWT token has expired for user "${username}"`);
            this.jwtTracking.deleteUser(username);
            return res.status(401).json({ error: 'JWT token has expired' });
          }

          if (latest !== null && !latest.revoked && iat < latest.iat) {
            this.logDebug(
              `Denying: token superseded (iat=${iat} < latest.iat=${latest.iat}) for user "${username}"`
            );
            return res.status(401).json({ error: 'JWT token has been superseded by a newer login' });
          }

          const expForDb = exp !== null ? exp : 2147483647; // no expiry → far future for cleanup
          this.jwtTracking.setLatest(username, tokenHash, iat, expForDb, 0);
        }

        if (this.cache.has(username)) {
          const cached = this.cache.get(username);
          this.logDebug(`Cache hit for "${username}": allowed=${cached}`);
          if (cached === false) {
            this.logDebug(`Denying: cached denial (GitHub authorization revoked) for user "${username}"`);
            return res.status(401).json({ error: 'GitHub authorization revoked' });
          }
          return next();
        }

        this.logDebug(`Cache miss for "${username}"; checking GitHub org membership`);
        const isUserInGitHubApp = await this.verifyUserInGitHubApp(username);
        this.logDebug(`GitHub org check for "${username}": isMember=${isUserInGitHubApp}`);
        if (!isUserInGitHubApp) {
          this.cache.set(username, false);
          this.jwtTracking?.setRevoked(username);
          this.logDebug(`Denying: user "${username}" not in org "${this.org}" or API error (GitHub authorization revoked)`);
          return res.status(401).json({ error: 'GitHub authorization revoked' });
        }

        this.cache.set(username, true);
        this.logDebug(`Allowed user "${username}"`);
      } catch (error) {
        this.stuff.logger.error(`${LOG_TAG} Error verifying token: ${error}`);
      }

      next();
    });
  }

  private async verifyUserInGitHubApp(username: string): Promise<boolean> {
    const orgName = this.org;
    let token: string;
    if (this.useGitHubApp) {
      try {
        token = await this.getInstallationAccessToken();
      } catch (err) {
        this.stuff.logger.error(`${LOG_TAG} Failed to get GitHub App installation token: ${err}`);
        return false;
      }
    } else {
      token = this.token;
    }

    try {
      const response = await fetch(`https://api.github.com/orgs/${orgName}/members/${username}`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github.v3+json',
          'X-GitHub-Api-Version': '2022-11-28'
        }
      });

      // 204 means the user is confirmed as a member
      if (response.status === 204) {
        return true; 
      }
      
      // 404 means they were removed or never existed
      if (response.status === 404) {
        this.stuff.logger.warn(`${LOG_TAG} User ${username} is no longer in the ${orgName} organization.`);
        return false;
      }

      // Log unexpected statuses (e.g., 401 Unauthorized if your token expires, or 403 Rate Limit)
      this.stuff.logger.error(`${LOG_TAG} GitHub API returned status ${response.status} when checking ${username}`);
      return false;

    } catch (error) {
      this.stuff.logger.error(`${LOG_TAG} Failed to communicate with GitHub API: ${error}`);
      // Fail closed: if we can't verify them, assume they don't have access
      return false; 
    }
  }

  private requireAdminToken(req: Request, res: Response, next: NextFunction): void {
    const auth = req.headers?.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Missing or invalid Authorization header (Bearer token required)' });
      return;
    }
    const token = auth.slice(7);
    const adminToken = this.adminToken;
    if (!adminToken || token !== adminToken) {
      res.status(403).json({ error: 'Invalid admin token' });
      return;
    }
    next();
  }
}

function plugin(config: PluginConfig | undefined, stuff: PluginStuff): GithubOAuthVerifierMiddleware {
  return new GithubOAuthVerifierMiddleware(config, stuff);
}

export = plugin;

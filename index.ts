import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import { LRUCache } from 'lru-cache';
import cron, { type ScheduledTask } from 'node-cron';
import os from 'os';
import path from 'path';
import { JwtTrackingDb } from './jwt-tracking';

/** Reusable tag for plugin log messages (e.g. for filtering in log aggregation). */
const LOG_TAG = '[verdaccio-github-oauth-verifier]';
/** Prefix for debug logs (filter e.g. with grep). */
const DEBUG_TAG = `${LOG_TAG} [debug]`;

interface AuthConfig {
  "github-oauth-ui"?: {
    token?: string;
  };
}

interface PluginConfig {
  auth?: AuthConfig;
  enabled?: boolean;
  token?: string;
  org?: string;
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
  };
}

class GithubOAuthVerifierMiddleware {
  private readonly stuff: PluginStuff;
  private readonly enabled: boolean;
  private readonly token: string;
  private readonly org: string;
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
      return;
    }
    
    this.token = config?.auth?.['github-oauth-ui']?.token ?? '';
    this.org = config?.org ?? '';
    if (!this.token || !this.org) {
      this.stuff.logger.error(`${LOG_TAG} Token or org is missing, disabling plugin`);
      return;
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

    if (!this.token || !this.org) {
      this.stuff.logger.error(`${LOG_TAG} Token or org is missing, skipping middleware setup`);
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
          const username = typeof req.query?.username === 'string' ? req.query.username.trim() : null;
          if (!username) {
            res.status(400).json({ error: 'Missing query parameter: username' });
            return;
          }
          this.jwtTracking?.setRevoked(username);
          this.cache.delete(username);
          this.stuff.logger.info(`${LOG_TAG} JWT invalidated for user: ${username}`);
          res.status(200).json({ ok: true, message: `JWT invalidated for user: ${username}` });
        }
      );
      app.post(
        '/-/github-oauth-verifier/clear-cache',
        (req: Request, res: Response, next: NextFunction) => this.requireAdminToken(req, res, next),
        (req: Request, res: Response) => {
          const username = typeof req.query?.username === 'string' ? req.query.username.trim() : null;
          if (username) {
            this.cache.delete(username);
            this.stuff.logger.info(`${LOG_TAG} Cache cleared for user: ${username}`);
            res.status(200).json({ ok: true, message: `Cache cleared for user: ${username}` });
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
        const username = decodedPayload.name;
        const iat = typeof decodedPayload.iat === 'number' ? decodedPayload.iat : 0;
        const exp = typeof decodedPayload.exp === 'number' ? decodedPayload.exp : null;

        this.stuff.logger.info(`${DEBUG_TAG} JWT payload: ${JSON.stringify(decodedPayload)}`);
        this.stuff.logger.info(`${DEBUG_TAG} Verifying user="${username}" iat=${iat} exp=${exp}`);

        if (this.jwtTracking) {
          const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
          const latest = this.jwtTracking.getLatest(username);

          this.stuff.logger.info(
            `${DEBUG_TAG} JWT tracking: latest=${latest === null ? 'null' : `{ revoked=${!!latest.revoked}, iat=${latest.iat} }`}`
          );

          if (latest !== null && latest.revoked) {
            const isSameToken = latest.token_hash === tokenHash && latest.iat === iat;
            this.stuff.logger.info(
              `${DEBUG_TAG} User "${username}" has revoked token in DB; isSameToken=${isSameToken} (token_hash match, iat match)`
            );
            if (isSameToken) {
              this.stuff.logger.info(`${DEBUG_TAG} Denying: GitHub authorization revoked (same token was revoked)`);
              return res.status(401).json({ error: 'GitHub authorization revoked' });
            }
          }

          if (exp !== null && exp < Math.floor(Date.now() / 1000)) {
            this.stuff.logger.info(`${DEBUG_TAG} Denying: JWT token has expired for user "${username}"`);
            this.jwtTracking.deleteUser(username);
            return res.status(401).json({ error: 'JWT token has expired' });
          }

          if (latest !== null && !latest.revoked && iat < latest.iat) {
            this.stuff.logger.info(
              `${DEBUG_TAG} Denying: token superseded (iat=${iat} < latest.iat=${latest.iat}) for user "${username}"`
            );
            return res.status(401).json({ error: 'JWT token has been superseded by a newer login' });
          }

          const expForDb = exp !== null ? exp : 2147483647; // no expiry → far future for cleanup
          this.jwtTracking.setLatest(username, tokenHash, iat, expForDb, 0);
        }

        if (this.cache.has(username)) {
          const cached = this.cache.get(username);
          this.stuff.logger.info(`${DEBUG_TAG} Cache hit for "${username}": allowed=${cached}`);
          if (cached === false) {
            this.stuff.logger.info(`${DEBUG_TAG} Denying: cached denial (GitHub authorization revoked) for user "${username}"`);
            return res.status(401).json({ error: 'GitHub authorization revoked' });
          }
          return next();
        }

        this.stuff.logger.info(`${DEBUG_TAG} Cache miss for "${username}"; checking GitHub org membership`);
        const isUserInGitHubApp = await this.verifyUserInGitHubApp(username);
        this.stuff.logger.info(`${DEBUG_TAG} GitHub org check for "${username}": isMember=${isUserInGitHubApp}`);
        if (!isUserInGitHubApp) {
          this.cache.set(username, false);
          this.jwtTracking?.setRevoked(username);
          this.stuff.logger.info(`${DEBUG_TAG} Denying: user "${username}" not in org "${this.org}" or API error (GitHub authorization revoked)`);
          return res.status(401).json({ error: 'GitHub authorization revoked' });
        }

        this.cache.set(username, true);
        this.stuff.logger.info(`${DEBUG_TAG} Allowed user "${username}"`);
      } catch (error) {
        this.stuff.logger.error(`${LOG_TAG} Error verifying token: ${error}`);
      }

      next();
    });
  }

  private async verifyUserInGitHubApp(username: string): Promise<boolean> {
    const orgName = this.org; // e.g., 'my-company-org'
    const token = this.token; // Your configured admin token
    
    try {
      const response = await fetch(`https://api.github.com/orgs/${orgName}/members/${username}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github.v3+json',
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
    if (token !== this.token) {
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

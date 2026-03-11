import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import { LRUCache } from 'lru-cache';
import { JwtTrackingDb } from './jwt-tracking';

interface PluginConfig {
  enabled?: boolean;
  token?: string;
  org?: string;
  cacheTTLMinutes?: number;
  /** Path to SQLite DB for JWT tracking (e.g. ./jwt-tracking.db). When set, only the most recent JWT per user is allowed. */
  jwtTrackingDbPath?: string;
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

  constructor(config: PluginConfig | undefined, stuff: PluginStuff) {
    this.stuff = stuff;
    this.stuff.logger.info('[verdaccio-github-oauth-verifier] Configuring');

    this.enabled = config != null && config.enabled !== false;
    this.cache = new LRUCache({ max: 1000, ttl: config?.cacheTTLMinutes ? config.cacheTTLMinutes * 60 * 1000 : 1000 * 60 * 60 * 8 });

    const dbPath = config?.jwtTrackingDbPath;
    this.jwtTracking = dbPath ? new JwtTrackingDb(dbPath) : null;
    if (this.jwtTracking) {
      this.stuff.logger.info('[verdaccio-github-oauth-verifier] JWT tracking DB enabled (only most recent token per user)');
    }

    if (!this.enabled) {
      this.stuff.logger.info('[verdaccio-github-oauth-verifier] Disabled');
      this.token = '';
      this.org = '';
      return;
    }

    this.token = config?.token ?? '';
    this.org = config?.org ?? '';
    if (!this.token || !this.org) {
      this.stuff.logger.error('[verdaccio-github-oauth-verifier] Token or org is missing, disabling plugin');
      return;
    }
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
      this.stuff.logger.error('[verdaccio-github-oauth-verifier] Token or org is missing, skipping middleware setup');
      return;
    }

    this.stuff.logger.info(
      `[verdaccio-github-oauth-verifier] register_middlewares loaded`
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
          this.stuff.logger.info(`[verdaccio-github-oauth-verifier] JWT invalidated for user: ${username}`);
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
            this.stuff.logger.info(`[verdaccio-github-oauth-verifier] Cache cleared for user: ${username}`);
            res.status(200).json({ ok: true, message: `Cache cleared for user: ${username}` });
          } else {
            this.cache.clear();
            this.stuff.logger.info('[verdaccio-github-oauth-verifier] Entire cache cleared');
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

        if (this.jwtTracking) {
          this.jwtTracking.deleteExpired();

          const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
          const latest = this.jwtTracking.getLatest(username);

          if (latest !== null && latest.revoked) {
            const isSameToken = latest.token_hash === tokenHash && latest.iat === iat;
            if (isSameToken) {
              return res.status(401).json({ error: 'GitHub authorization revoked' });
            }
          }

          if (exp !== null && exp < Math.floor(Date.now() / 1000)) {
            this.jwtTracking.deleteUser(username);
            return res.status(401).json({ error: 'JWT token has expired' });
          }

          if (latest !== null && !latest.revoked && iat < latest.iat) {
            return res.status(401).json({ error: 'JWT token has been superseded by a newer login' });
          }

          const expForDb = exp !== null ? exp : 2147483647; // no expiry → far future for cleanup
          this.jwtTracking.setLatest(username, tokenHash, iat, expForDb, 0);
        }

        if (this.cache.has(username)) {
          if (this.cache.get(username) === false) {
            return res.status(401).json({ error: 'GitHub authorization revoked' });
          }
          return next();
        }

        const isUserInGitHubApp = await this.verifyUserInGitHubApp(username);
        if (!isUserInGitHubApp) {
          this.cache.set(username, false);
          this.jwtTracking?.setRevoked(username);
          return res.status(401).json({ error: 'GitHub authorization revoked' });
        }

        this.cache.set(username, true);
      } catch (error) {
        this.stuff.logger.error(`[verdaccio-github-oauth-verifier] Error verifying token: ${error}`);
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
        console.warn(`User ${username} is no longer in the ${orgName} organization.`);
        return false;
      }

      // Log unexpected statuses (e.g., 401 Unauthorized if your token expires, or 403 Rate Limit)
      console.error(`GitHub API returned status ${response.status} when checking ${username}`);
      return false;

    } catch (error) {
      console.error('Failed to communicate with GitHub API', error);
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

import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import { LRUCache } from 'lru-cache'

interface PluginConfig {
  enabled?: boolean;
  token?: string;
  org?: string;
  cacheTTLMinutes?: number;
}

interface PluginStuff {
  logger: {
    info: (msg: string) => void;
    warn: (msg: string) => void;
    error: (msg: string) => void;
  };
}

interface StorageConfig {
  config: {
    secret?: string;
    security?: {
      api?: {
        jwt?: {
          secret?: string;
        };
      };
    };
  };
}

class GithubOAuthVerifierMiddleware {
  private readonly stuff: PluginStuff;
  private readonly enabled: boolean;
  private readonly token: string;
  private readonly org: string;
  private readonly cache: LRUCache<string, boolean>;

  constructor(config: PluginConfig | undefined, stuff: PluginStuff) {
    this.stuff = stuff;
    this.stuff.logger.info('[verdaccio-github-oauth-verifier] Configuring');

    this.enabled = config != null && config.enabled !== false;
    this.cache = new LRUCache({ max: 1000, ttl: config?.cacheTTLMinutes ? config.cacheTTLMinutes * 60 * 1000 : 1000 * 60 * 60 * 8 });

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
    app: { use: (fn: (req: Request, res: Response, next: NextFunction) => void) => void },
    _authInstance: unknown,
    storageInstance: StorageConfig
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

    const globalConfig = storageInstance.config;
    const verdaccioSecret =
      globalConfig.security?.api?.jwt?.secret ?? globalConfig.secret;

    app.use(async (req: Request, res: Response, next: NextFunction) => {
      if (!req.headers?.authorization) {
        return next();
      }

      const token = req.headers.authorization.split(' ')[1];      

      try
      {
        const tokenParts = token.split('.');
        if (tokenParts.length !== 3) return next();

        const payloadBase64 = tokenParts[1];
        const decodedPayload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf8'));
        const username = decodedPayload.name;

        if (this.cache.has(username)) {
          if (this.cache.get(username) === false) {
            return res.status(401).json({ error: 'GitHub authorization revoked' });
          }
          return next();
        }

        const isUserInGitHubApp = await this.verifyUserInGitHubApp(username);
        if (!isUserInGitHubApp) {
          this.cache.set(username, false);
          return res.status(401).json({ error: 'GitHub authorization revoked' });
        }

        this.cache.set(username, true);

        console.log(
          '[verdaccio-github-oauth-ui] Plugin initialized. Full JWT:', 
          JSON.stringify(decodedPayload, null, 2)
        );

        this.stuff.logger.info(`[verdaccio-github-oauth-verifier] ${username}`)

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
}

function plugin(config: PluginConfig | undefined, stuff: PluginStuff): GithubOAuthVerifierMiddleware {
  return new GithubOAuthVerifierMiddleware(config, stuff);
}

export = plugin;

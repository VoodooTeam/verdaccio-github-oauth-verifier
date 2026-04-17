import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

const TABLE = `CREATE TABLE IF NOT EXISTS jwt_tracking (
  username TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL,
  iat INTEGER NOT NULL,
  exp INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
)`;

const INDEX_EXP = `CREATE INDEX IF NOT EXISTS idx_jwt_tracking_exp ON jwt_tracking(exp)`;

export interface JwtTrackingRow {
  username: string;
  token_hash: string;
  iat: number;
  exp: number;
  revoked: number;
}

export class JwtTrackingDb {
  private db: Database.Database;

  constructor(dbPath: string) {
    // Callers (see index.ts) always pass an absolute path under ~/.verdaccio. The
    // process.cwd() branch is a defensive fallback for any hypothetical direct use of
    // this class with a relative path; do not rely on it from plugin code.
    const resolved = path.isAbsolute(dbPath) ? dbPath : path.resolve(process.cwd(), dbPath);
    this.db = new Database(resolved);
    // Token hashes + usernames — restrict to owner (read/write). Called every init so
    // perms are corrected if the file was created with a laxer umask previously.
    try {
      fs.chmodSync(resolved, 0o600);
    } catch {
      /* non-fatal: filesystem may not support chmod (e.g. some network FS) */
    }
    this.db.pragma('journal_mode = WAL');
    this.db.exec(TABLE);
    this.db.exec(INDEX_EXP);
    try {
      this.db.exec(`ALTER TABLE jwt_tracking ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0`);
    } catch (err) {
      // Only swallow the "column already exists" case from an older schema. Anything
      // else (disk error, corruption, locked DB) must surface.
      const msg = err instanceof Error ? err.message : String(err);
      if (!/duplicate column name/i.test(msg)) {
        throw err;
      }
    }
  }

  getLatest(username: string): JwtTrackingRow | null {
    const row = this.db.prepare(
      'SELECT username, token_hash, iat, exp, COALESCE(revoked, 0) AS revoked FROM jwt_tracking WHERE username = ?'
    ).get(username) as JwtTrackingRow | undefined;
    return row ?? null;
  }

  setLatest(username: string, tokenHash: string, iat: number, exp: number, revoked = 0): void {
    this.db.prepare(
      `INSERT INTO jwt_tracking (username, token_hash, iat, exp, revoked) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(username) DO UPDATE SET token_hash = excluded.token_hash, iat = excluded.iat, exp = excluded.exp, revoked = excluded.revoked`
    ).run(username, tokenHash, iat, exp, revoked);
  }

  setRevoked(username: string): void {
    this.db.prepare(
      `INSERT INTO jwt_tracking (username, token_hash, iat, exp, revoked) VALUES (?, 'revoked', 0, 0, 1)
       ON CONFLICT(username) DO UPDATE SET revoked = 1`
    ).run(username);
  }

  setRevokedAll(): void {
    this.db.prepare('UPDATE jwt_tracking SET revoked = 1').run();
  }

  deleteUser(username: string): void {
    this.db.prepare('DELETE FROM jwt_tracking WHERE username = ?').run(username);
  }

  deleteExpired(): void {
    const now = Math.floor(Date.now() / 1000);
    this.db.prepare('DELETE FROM jwt_tracking WHERE exp < ?').run(now);
  }

  close(): void {
    this.db.close();
  }
}

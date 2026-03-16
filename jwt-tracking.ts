import Database from 'better-sqlite3';
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
    const resolved = path.isAbsolute(dbPath) ? dbPath : path.resolve(process.cwd(), dbPath);
    this.db = new Database(resolved);
    this.db.pragma('journal_mode = WAL');
    this.db.exec(TABLE);
    this.db.exec(INDEX_EXP);
    try {
      this.db.exec(`ALTER TABLE jwt_tracking ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0`);
    } catch {
      /* column already exists (e.g. after upgrade) */
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

import { now } from './util';

export interface KeyRow {
  fingerprint: string;
  armored: string;
  primary_uid: string | null;
  algo: string | null;
  created_at: number;
  verified_at: number | null;
  last_active: number;
}

export interface ChallengeRow {
  fingerprint: string;
  exercise: string;
  secret_hash: string | null;
  data: string | null;
  created_at: number;
  expires_at: number;
}

export class Store {
  constructor(private db: D1Database) {}

  getKey(fpr: string) {
    return this.db.prepare('SELECT * FROM keys WHERE fingerprint = ?').bind(fpr).first<KeyRow>();
  }

  insertKey(fpr: string, armored: string, uid: string, algo: string) {
    const t = now();
    return this.db
      .prepare(
        `INSERT INTO keys (fingerprint, armored, primary_uid, algo, created_at, last_active) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(fingerprint) DO UPDATE SET armored = excluded.armored, primary_uid = excluded.primary_uid,
           algo = excluded.algo, last_active = excluded.last_active`,
      )
      .bind(fpr, armored, uid, algo, t, t)
      .run();
  }

  updateKeyMaterial(fpr: string, armored: string, uid: string, algo: string) {
    return this.db
      .prepare('UPDATE keys SET armored = ?, primary_uid = ?, algo = ?, last_active = ? WHERE fingerprint = ?')
      .bind(armored, uid, algo, now(), fpr)
      .run();
  }

  touch(fpr: string) {
    return this.db.prepare('UPDATE keys SET last_active = ? WHERE fingerprint = ?').bind(now(), fpr).run();
  }

  markVerified(fpr: string) {
    const t = now();
    return this.db.prepare('UPDATE keys SET verified_at = COALESCE(verified_at, ?), last_active = ? WHERE fingerprint = ?').bind(t, t, fpr).run();
  }

  setChallenge(fpr: string, exercise: string, secretHash: string | null, data: unknown, ttlSeconds: number) {
    const t = now();
    return this.db
      .prepare(
        `INSERT OR REPLACE INTO challenges (fingerprint, exercise, secret_hash, data, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(fpr, exercise, secretHash, data === undefined ? null : JSON.stringify(data), t, t + ttlSeconds)
      .run();
  }

  getChallenge(fpr: string, exercise: string) {
    return this.db
      .prepare('SELECT * FROM challenges WHERE fingerprint = ? AND exercise = ? AND expires_at > ?')
      .bind(fpr, exercise, now())
      .first<ChallengeRow>();
  }

  deleteChallenge(fpr: string, exercise: string) {
    return this.db.prepare('DELETE FROM challenges WHERE fingerprint = ? AND exercise = ?').bind(fpr, exercise).run();
  }

  async complete(fpr: string, ...exercises: string[]) {
    const t = now();
    await this.db.batch([
      ...exercises.map((ex) =>
        this.db.prepare('INSERT OR IGNORE INTO progress (fingerprint, exercise, completed_at) VALUES (?, ?, ?)').bind(fpr, ex, t),
      ),
      this.db.prepare('UPDATE keys SET last_active = ? WHERE fingerprint = ?').bind(t, fpr),
    ]);
  }

  async progress(fpr: string): Promise<Record<string, number>> {
    const { results } = await this.db
      .prepare('SELECT exercise, completed_at FROM progress WHERE fingerprint = ?')
      .bind(fpr)
      .all<{ exercise: string; completed_at: number }>();
    return Object.fromEntries(results.map((r) => [r.exercise, r.completed_at]));
  }

  async deleteUser(fpr: string) {
    await this.db.batch(
      ['keys', 'challenges', 'progress'].map((t) => this.db.prepare(`DELETE FROM ${t} WHERE fingerprint = ?`).bind(fpr)),
    );
  }

  /** Remove everything older than the retention window. */
  async purge(retentionDays: number) {
    const cutoff = now() - retentionDays * 86400;
    const t = now();
    const res = await this.db.batch([
      this.db.prepare('DELETE FROM progress WHERE fingerprint IN (SELECT fingerprint FROM keys WHERE last_active < ?)').bind(cutoff),
      this.db.prepare('DELETE FROM challenges WHERE expires_at < ? OR fingerprint IN (SELECT fingerprint FROM keys WHERE last_active < ?)').bind(t, cutoff),
      this.db.prepare('DELETE FROM keys WHERE last_active < ?').bind(cutoff),
      this.db.prepare('DELETE FROM progress WHERE fingerprint NOT IN (SELECT fingerprint FROM keys)'),
      this.db.prepare('DELETE FROM rate WHERE window_start < ?').bind(t - 86400),
    ]);
    return res.map((r) => r.meta.changes);
  }

  /** Fixed-window counter. Returns true if the request is allowed. */
  async rateLimit(bucket: string, limit: number, windowSeconds: number): Promise<boolean> {
    const t = now();
    const windowStart = t - (t % windowSeconds);
    const row = await this.db
      .prepare(
        `INSERT INTO rate (bucket, window_start, count) VALUES (?, ?, 1)
         ON CONFLICT(bucket) DO UPDATE SET
           count = CASE WHEN rate.window_start = excluded.window_start THEN rate.count + 1 ELSE 1 END,
           window_start = excluded.window_start
         RETURNING count`,
      )
      .bind(bucket, windowStart)
      .first<{ count: number }>();
    return (row?.count ?? 0) <= limit;
  }
}

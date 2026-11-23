export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  SERVER_PRIVATE_KEY: string;
  SESSION_SECRET: string;
  SERVER_EMAIL: string;
  RETENTION_DAYS: string;
}

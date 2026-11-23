-- Users are identified by their OpenPGP key fingerprint (uppercase hex).
CREATE TABLE keys (
  fingerprint TEXT PRIMARY KEY,
  armored     TEXT NOT NULL,
  primary_uid TEXT,
  algo        TEXT,
  created_at  INTEGER NOT NULL,
  verified_at INTEGER,
  last_active INTEGER NOT NULL
);
CREATE INDEX idx_keys_last_active ON keys(last_active);

-- One active challenge per (fingerprint, exercise); replaced when an exercise is (re)started.
CREATE TABLE challenges (
  fingerprint TEXT NOT NULL,
  exercise    TEXT NOT NULL,
  secret_hash TEXT,
  data        TEXT,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  PRIMARY KEY (fingerprint, exercise)
);
CREATE INDEX idx_challenges_expires ON challenges(expires_at);

CREATE TABLE progress (
  fingerprint  TEXT NOT NULL,
  exercise     TEXT NOT NULL,
  completed_at INTEGER NOT NULL,
  PRIMARY KEY (fingerprint, exercise)
);

-- Fixed-window rate limiting counters.
CREATE TABLE rate (
  bucket       TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL
);

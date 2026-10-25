"use strict";

const { DatabaseSync } = require("node:sqlite");

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('admin','owner','viewer')),
  password_hash TEXT NOT NULL,
  active        INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at    TEXT NOT NULL
);

-- Server-side sessions: logout and deactivation take effect immediately.
-- Only a SHA-256 of the session token is stored.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
  id            TEXT PRIMARY KEY,
  owner_id      TEXT NOT NULL REFERENCES users(id),
  title         TEXT NOT NULL,
  category      TEXT NOT NULL,
  original_name TEXT NOT NULL,
  stored_name   TEXT NOT NULL UNIQUE,   -- random name on disk, never user input
  mime          TEXT NOT NULL,          -- chosen by the server from the validated type
  size          INTEGER NOT NULL,
  sha256        TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL,
  deleted_at    TEXT                    -- soft delete, restorable by the owner
);

-- Per-document grants. A user has at most one active grant per document.
CREATE TABLE IF NOT EXISTS grants (
  id          TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id),
  user_id     TEXT NOT NULL REFERENCES users(id),
  permission  TEXT NOT NULL CHECK (permission IN ('read','edit')),
  granted_by  TEXT NOT NULL REFERENCES users(id),
  created_at  TEXT NOT NULL,
  revoked_at  TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_grant
  ON grants(document_id, user_id) WHERE revoked_at IS NULL;

-- External share links. The token is a bearer secret (stored hashed).
-- The optional passcode is a second factor the owner gives out of band (stored hashed).
CREATE TABLE IF NOT EXISTS share_links (
  id             TEXT PRIMARY KEY,
  document_id    TEXT NOT NULL REFERENCES documents(id),
  token_hash     TEXT NOT NULL UNIQUE,
  passcode_hash  TEXT NOT NULL,
  label          TEXT NOT NULL,
  created_by     TEXT NOT NULL REFERENCES users(id),
  created_at     TEXT NOT NULL,
  expires_at     TEXT NOT NULL,
  max_downloads  INTEGER NOT NULL,
  download_count INTEGER NOT NULL DEFAULT 0,
  revoked_at     TEXT
);

-- Append-only, hash-chained audit log. Triggers block UPDATE and DELETE.
CREATE TABLE IF NOT EXISTS audit (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  id          TEXT NOT NULL UNIQUE,
  ts          TEXT NOT NULL,
  actor_id    TEXT,
  actor_email TEXT NOT NULL,
  action      TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id   TEXT,
  outcome     TEXT NOT NULL CHECK (outcome IN ('allowed','denied','failed')),
  details     TEXT NOT NULL DEFAULT '{}',
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
`;

function open(path) {
  const db = new DatabaseSync(path);
  db.exec("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  if (path !== ":memory:") db.exec("PRAGMA journal_mode = WAL;");
  db.exec(SCHEMA);
  return db;
}

// Runs fn inside a transaction; rolls back if it throws.
function tx(db, fn) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = fn();
    db.exec("COMMIT");
    return result;
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}

module.exports = { open, tx };

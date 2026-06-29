import { DatabaseSync } from 'node:sqlite';
import fs from 'fs';
import path from 'path';
import { config } from './config.js';

// Ensure data directory exists
const dir = path.dirname(config.dbPath);
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

// node:sqlite (built-in since Node 22, stable in Node 24+)
export const db = new DatabaseSync(config.dbPath);
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

// ---------- Helpers to normalize null-prototype rows to plain objects ----------
function toPlain(row) {
  if (row === undefined || row === null) return row;
  if (typeof row !== 'object') return row;
  const out = {};
  for (const k of Object.keys(row)) out[k] = row[k];
  return out;
}
const origGet = db.prepare.bind(db);
const origAll = db.prepare.bind(db);
// Wrap StatementSync to convert rows; we keep API close to better-sqlite3
class Stmt {
  constructor(stmt) { this._s = stmt; }
  run(...args) { return this._s.run(...args); }
  get(...args) { return toPlain(this._s.get(...args)); }
  all(...args) { return this._s.all(...args).map(toPlain); }
  iterate(...args) {
    const arr = this._s.all(...args).map(toPlain);
    return arr[Symbol.iterator]();
  }
}
db._prepareRaw = db.prepare;
db.prepare = (sql) => new Stmt(db._prepareRaw(sql));

// Transaction helper (mirrors better-sqlite3's db.transaction(fn))
db.transaction = function (fn) {
  return function (...args) {
    db.exec('BEGIN');
    try {
      const result = fn(...args);
      db.exec('COMMIT');
      return result;
    } catch (e) {
      try { db.exec('ROLLBACK'); } catch (_) {}
      throw e;
    }
  };
};

// ---------- Schema ----------
const migrations = [
  // v1: users + refresh tokens
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','banned','disabled')),
    display_name TEXT DEFAULT '',
    avatar TEXT DEFAULT '',
    api_key TEXT DEFAULT '',
    created_at INTEGER NOT NULL,
    last_login_at INTEGER,
    banned_reason TEXT DEFAULT ''
  );`,
  `CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );`,

  // v1: per-user KV store (mirror of frontend IndexedDB)
  `CREATE TABLE IF NOT EXISTS user_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    scope TEXT NOT NULL DEFAULT 'global',
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(user_id, scope, name),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );`,

  // v1: public character library
  `CREATE TABLE IF NOT EXISTS library_cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    author_id INTEGER,
    author_name TEXT DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    card_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','offline')),
    review_note TEXT DEFAULT '',
    reviewer_id INTEGER,
    reviewed_at INTEGER,
    download_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY(reviewer_id) REFERENCES users(id) ON DELETE SET NULL
  );`,
  `CREATE INDEX IF NOT EXISTS idx_library_cards_status ON library_cards(status);
   CREATE INDEX IF NOT EXISTS idx_library_cards_author ON library_cards(author_id);`,

  // v1: announcements
  `CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'info' CHECK(type IN ('info','notice','maintenance')),
    pinned INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    author_id INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER,
    FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE SET NULL
  );`,

  // v1: audit log
  `CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    target TEXT DEFAULT '',
    detail TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    created_at INTEGER NOT NULL
  );`,

  // v1: api usage (for new-api integration / analytics)
  `CREATE TABLE IF NOT EXISTS api_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    endpoint TEXT DEFAULT '',
    model TEXT DEFAULT '',
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );`,
  `CREATE INDEX IF NOT EXISTS idx_api_usage_user ON api_usage(user_id);
   CREATE INDEX IF NOT EXISTS idx_api_usage_created ON api_usage(created_at);`,
  `ALTER TABLE user_data ADD COLUMN value_hash TEXT DEFAULT '';`,
  `ALTER TABLE refresh_tokens ADD COLUMN ip TEXT DEFAULT '';`,
  `ALTER TABLE refresh_tokens ADD COLUMN user_agent TEXT DEFAULT '';`,
  `ALTER TABLE refresh_tokens ADD COLUMN last_seen_at INTEGER;`,
  `CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_expires ON refresh_tokens(user_id, expires_at);
   CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
   CREATE INDEX IF NOT EXISTS idx_api_usage_user_created ON api_usage(user_id, created_at);
   CREATE INDEX IF NOT EXISTS idx_audit_logs_action_created ON audit_logs(action, created_at);
   CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created ON audit_logs(user_id, created_at);`,
];

// Simple migration runner based on PRAGMA user_version
export function runMigrations() {
  const current = db.prepare('PRAGMA user_version').get().user_version;
  for (let i = current; i < migrations.length; i++) {
    db.exec(migrations[i]);
    db.exec(`PRAGMA user_version = ${i + 1}`);
  }
}

runMigrations();

// ---------- Helpers ----------
export const now = () => Date.now();

export function audit(userId, action, target = '', detail = '', ip = '') {
  try {
    db.prepare(
      `INSERT INTO audit_logs (user_id, action, target, detail, ip, created_at) VALUES (?, ?, ?, ?, ?, ?)`
    ).run(userId ?? null, action, target, detail, ip, now());
  } catch (e) {
    console.error('audit log failed:', e);
  }
}

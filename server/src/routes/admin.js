import { Router } from 'express';
import bcrypt from 'bcryptjs';
import fs from 'fs/promises';
import path from 'path';
import { config } from '../config.js';
import { db, now, audit } from '../db.js';
import { adminRequired } from '../middleware/auth.js';
import { hashRefreshToken } from '../utils/jwt.js';

const router = Router();

router.use(adminRequired);

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    username: u.username,
    role: u.role,
    status: u.status,
    displayName: u.display_name,
    avatar: u.avatar,
    activeSessions: Number(u.active_sessions || 0),
    createdAt: u.created_at,
    lastLoginAt: u.last_login_at,
    bannedReason: u.banned_reason,
  };
}

const IMAGE_CACHE_ROOT = path.resolve(path.dirname(config.dbPath), 'image-cache');
const IMAGE_CACHE_TEMP_MAX_AGE = 60 * 60 * 1000;
const DB_VACUUM_FREE_BYTES_THRESHOLD = 8 * 1024 * 1024;
const DB_VACUUM_FREE_RATIO_THRESHOLD = 0.2;

function hashSerializedValue(text) {
  let hash = 2166136261;
  const value = String(text || '');
  for (let i = 0; i < value.length; i++) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

function splitScopedName(name = '') {
  const idx = String(name).indexOf(':');
  if (idx < 0) return { key: name, id: '' };
  return { key: name.slice(0, idx), id: name.slice(idx + 1) };
}

function getSyncStorageStats() {
  const rows = db.prepare(
    `SELECT d.user_id, u.username, d.scope, d.name, d.value_hash, d.updated_at,
            LENGTH(CAST(d.value AS BLOB)) AS bytes
     FROM user_data d LEFT JOIN users u ON u.id = d.user_id`
  ).all();
  const byNameMap = new Map();
  const byUserMap = new Map();
  let totalBytes = 0;
  let globalRecords = 0;
  let scopedRecords = 0;
  let chatRecords = 0;
  let missingHashes = 0;

  const entries = rows.map((r) => {
    const size = Number(r.bytes || 0);
    totalBytes += size;
    if (r.scope === 'global') globalRecords += 1;
    if (r.scope === 'scoped') scopedRecords += 1;
    if (!r.value_hash) missingHashes += 1;

    const scoped = r.scope === 'scoped' ? splitScopedName(r.name) : { key: r.name, id: '' };
    const nameKey = r.scope === 'scoped' ? scoped.key : r.name;
    if (nameKey === 'chat') chatRecords += 1;

    const nameStat = byNameMap.get(nameKey) || { name: nameKey, records: 0, bytes: 0 };
    nameStat.records += 1;
    nameStat.bytes += size;
    byNameMap.set(nameKey, nameStat);

    const userKey = String(r.user_id || 0);
    const userStat = byUserMap.get(userKey) || { userId: r.user_id, username: r.username || '', records: 0, bytes: 0 };
    userStat.records += 1;
    userStat.bytes += size;
    byUserMap.set(userKey, userStat);

    return {
      userId: r.user_id,
      username: r.username || '',
      scope: r.scope,
      name: nameKey,
      id: scoped.id,
      bytes: size,
      updatedAt: r.updated_at,
      hasHash: !!r.value_hash,
    };
  });

  return {
    records: rows.length,
    totalBytes,
    globalRecords,
    scopedRecords,
    chatRecords,
    missingHashes,
    byName: Array.from(byNameMap.values()).sort((a, b) => b.bytes - a.bytes).slice(0, 12),
    byUser: Array.from(byUserMap.values()).sort((a, b) => b.bytes - a.bytes).slice(0, 12),
    largest: entries.sort((a, b) => b.bytes - a.bytes).slice(0, 12),
  };
}

async function scanImageCache({ cleanupTemps = false } = {}) {
  const result = {
    exists: false,
    images: 0,
    metaFiles: 0,
    tempFiles: 0,
    users: 0,
    bytes: 0,
    imageBytes: 0,
    tempBytes: 0,
    removedTempFiles: 0,
    removedTempBytes: 0,
    byUser: [],
    largest: [],
  };

  let dirs;
  try {
    dirs = await fs.readdir(IMAGE_CACHE_ROOT, { withFileTypes: true });
    result.exists = true;
  } catch (e) {
    if (e.code === 'ENOENT') return result;
    throw e;
  }

  const userStats = new Map();
  const cutoff = Date.now() - IMAGE_CACHE_TEMP_MAX_AGE;
  for (const dirent of dirs) {
    if (!dirent.isDirectory()) continue;
    const userId = Number(dirent.name) || 0;
    const userDir = path.join(IMAGE_CACHE_ROOT, dirent.name);
    let files;
    try {
      files = await fs.readdir(userDir, { withFileTypes: true });
    } catch (_) {
      continue;
    }
    if (files.length) result.users += 1;
    const userStat = userStats.get(dirent.name) || { userId, files: 0, images: 0, bytes: 0 };
    for (const file of files) {
      if (!file.isFile()) continue;
      const filePath = path.join(userDir, file.name);
      let stat;
      try {
        stat = await fs.stat(filePath);
      } catch (_) {
        continue;
      }
      const size = stat.size || 0;
      result.bytes += size;
      userStat.files += 1;
      userStat.bytes += size;

      if (file.name.endsWith('.bin')) {
        result.images += 1;
        result.imageBytes += size;
        userStat.images += 1;
        result.largest.push({ userId, name: file.name.replace(/\.bin$/, ''), bytes: size, updatedAt: stat.mtimeMs });
      } else if (file.name.endsWith('.json')) {
        result.metaFiles += 1;
      } else if (file.name.includes('.tmp')) {
        result.tempFiles += 1;
        result.tempBytes += size;
        if (cleanupTemps && stat.mtimeMs < cutoff) {
          try {
            await fs.rm(filePath, { force: true });
            result.removedTempFiles += 1;
            result.removedTempBytes += size;
          } catch (_) {}
        }
      }
    }
    userStats.set(dirent.name, userStat);
  }

  result.byUser = Array.from(userStats.values()).sort((a, b) => b.bytes - a.bytes).slice(0, 12);
  result.largest = result.largest.sort((a, b) => b.bytes - a.bytes).slice(0, 12);
  return result;
}

async function fileSize(filePath) {
  try {
    const stat = await fs.stat(filePath);
    return stat.size || 0;
  } catch (e) {
    if (e.code === 'ENOENT') return 0;
    throw e;
  }
}

function pragmaFirstValue(sql, fallback = 0) {
  try {
    const row = db.prepare(sql).get();
    const value = row ? Object.values(row)[0] : fallback;
    return value ?? fallback;
  } catch (_) {
    return fallback;
  }
}

async function getDatabaseStats() {
  const dbPath = config.dbPath;
  const walPath = `${dbPath}-wal`;
  const shmPath = `${dbPath}-shm`;
  const [dbBytes, walBytes, shmBytes] = await Promise.all([
    fileSize(dbPath),
    fileSize(walPath),
    fileSize(shmPath),
  ]);
  const pageSize = Number(pragmaFirstValue('PRAGMA page_size', 0)) || 0;
  const pageCount = Number(pragmaFirstValue('PRAGMA page_count', 0)) || 0;
  const freelistCount = Number(pragmaFirstValue('PRAGMA freelist_count', 0)) || 0;
  const journalMode = String(pragmaFirstValue('PRAGMA journal_mode', '') || '');
  const freelistBytes = freelistCount * pageSize;
  const pageBytes = pageCount * pageSize;
  return {
    file: path.basename(dbPath),
    dbBytes,
    walBytes,
    shmBytes,
    totalBytes: dbBytes + walBytes + shmBytes,
    pageSize,
    pageCount,
    freelistCount,
    freelistBytes,
    freeRatio: pageBytes ? Math.round((freelistBytes / pageBytes) * 1000) / 1000 : 0,
    journalMode,
  };
}

async function optimizeDatabase() {
  const before = await getDatabaseStats();
  const warnings = [];
  let checkpoint = null;
  let vacuumed = false;

  try {
    db.exec('PRAGMA optimize');
  } catch (e) {
    warnings.push(`optimize:${e.message || e}`);
  }

  try {
    checkpoint = db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get();
  } catch (e) {
    warnings.push(`checkpoint:${e.message || e}`);
  }

  const shouldVacuum = before.freelistBytes >= DB_VACUUM_FREE_BYTES_THRESHOLD
    || before.freeRatio >= DB_VACUUM_FREE_RATIO_THRESHOLD;
  if (shouldVacuum) {
    try {
      db.exec('VACUUM');
      vacuumed = true;
      try { db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get(); } catch (_) {}
    } catch (e) {
      warnings.push(`vacuum:${e.message || e}`);
    }
  }

  const after = await getDatabaseStats();
  return {
    ok: warnings.length === 0,
    vacuumed,
    checkpoint,
    before,
    after,
    savedBytes: Math.max(0, Number(before.totalBytes || 0) - Number(after.totalBytes || 0)),
    warnings,
  };
}

function sessionDeviceLabel(userAgent = '') {
  const ua = String(userAgent || '');
  const browser = /Edg\//.test(ua) ? 'Edge'
    : /Firefox\//.test(ua) ? 'Firefox'
      : /CriOS\//.test(ua) ? 'Chrome iOS'
        : /Chrome\//.test(ua) ? 'Chrome'
          : /Safari\//.test(ua) ? 'Safari'
            : ua ? 'Other' : 'Unknown';
  const os = /Windows/.test(ua) ? 'Windows'
    : /Android/.test(ua) ? 'Android'
      : /iPhone|iPad|iPod/.test(ua) ? 'iOS'
        : /Mac OS X/.test(ua) ? 'macOS'
          : /Linux/.test(ua) ? 'Linux' : '';
  return os ? `${browser} · ${os}` : browser;
}

function currentRefreshHash(req) {
  const token = String(req.headers['x-refresh-token'] || '');
  return token ? hashRefreshToken(token) : '';
}

function publicSession(row, nowTs, currentUserId, currentTokenHash = '') {
  const expiresAt = Number(row.expires_at || 0);
  const isSelf = row.user_id === currentUserId;
  const isCurrent = !!currentTokenHash && row.token_hash === currentTokenHash;
  return {
    id: row.id,
    userId: row.user_id,
    username: row.username || '',
    displayName: row.display_name || '',
    role: row.role || 'user',
    userStatus: row.status || '',
    ip: row.ip || '',
    userAgent: row.user_agent || '',
    device: sessionDeviceLabel(row.user_agent),
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at || row.created_at,
    expiresAt,
    state: expiresAt > nowTs ? 'active' : 'expired',
    isSelf,
    isCurrent,
  };
}

function getSessionStats(nowTs = now()) {
  const stats = db.prepare(
    `SELECT
       COALESCE(SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END), 0) AS active_sessions,
       COALESCE(SUM(CASE WHEN expires_at <= ? THEN 1 ELSE 0 END), 0) AS expired_sessions,
       COUNT(DISTINCT CASE WHEN expires_at > ? THEN user_id END) AS online_users
     FROM refresh_tokens`
  ).get(nowTs, nowTs, nowTs);
  return {
    activeSessions: Number(stats.active_sessions || 0),
    expiredSessions: Number(stats.expired_sessions || 0),
    onlineUsers: Number(stats.online_users || 0),
  };
}

function getUserWithUsage(id) {
  return db.prepare(
    `SELECT u.*
     FROM users u
     WHERE u.id = ?`
  ).get(id);
}

// ---------- User management ----------
router.get('/users', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize || '50', 10)));
  const q = (req.query.q || '').toString().trim();
  const status = (req.query.status || '').toString();
  const role = (req.query.role || '').toString();
  let where = 'WHERE 1=1';
  const params = [];
  if (q) { where += ` AND (u.username LIKE ? OR u.display_name LIKE ?)`; params.push(`%${q}%`, `%${q}%`); }
  if (status) { where += ` AND u.status = ?`; params.push(status); }
  if (role) { where += ` AND u.role = ?`; params.push(role); }

  const total = db.prepare(`SELECT COUNT(*) as c FROM users u ${where}`).get(...params).c;
  const rows = db.prepare(
    `SELECT u.*, (
     SELECT COUNT(*) FROM refresh_tokens rt WHERE rt.user_id = u.id AND rt.expires_at > ?
     ) AS active_sessions
     FROM users u
     ${where} ORDER BY u.created_at DESC LIMIT ? OFFSET ?`
  ).all(now(), ...params, pageSize, (page - 1) * pageSize);

  res.json({ total, page, pageSize, users: rows.map(publicUser) });
});

router.get('/users/:id', (req, res) => {
  const u = getUserWithUsage(parseInt(req.params.id, 10));
  if (!u) return res.status(404).json({ error: '用户不存在' });
  res.json({ user: publicUser(u) });
});

router.patch('/users/:id', (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!target) return res.status(404).json({ error: '用户不存在' });

    const { role, status, displayName, bannedReason, password } = req.body || {};
    const sets = [];
    const vals = [];

    if (role === 'admin' || role === 'user') {
      // Prevent self-demotion when you're the last admin
      if (role === 'user' && target.role === 'admin' && req.user.id === id) {
        const adminCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'admin' AND status = 'active'").get().c;
        if (adminCount <= 1) return res.status(400).json({ error: '至少保留一名管理员，无法降级自己' });
      }
      sets.push('role = ?'); vals.push(role);
    }
    if (['active', 'banned', 'disabled'].includes(status)) {
      sets.push('status = ?'); vals.push(status);
      if (status === 'banned') sets.push('banned_reason = ?'), vals.push((bannedReason || '').toString().slice(0, 256));
      // Banning/disabling user invalidates their refresh tokens
      if (status !== 'active') db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').run(id);
    }
    if (typeof displayName === 'string' && displayName.length <= 64) {
      sets.push('display_name = ?'); vals.push(displayName);
    }
    if (typeof password === 'string' && password.length >= 6 && password.length <= 128) {
      sets.push('password_hash = ?'); vals.push(bcrypt.hashSync(password, 10));
      db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').run(id);
    }

    if (!sets.length) return res.json({ ok: true, user: publicUser(target) });
    vals.push(id);
    db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
    audit(req.user.id, 'admin_update_user', target.username, sets.join(','), req.ip);
    const updated = getUserWithUsage(id);
    res.json({ ok: true, user: publicUser(updated) });
  } catch (e) { next(e); }
});

router.delete('/users/:id', (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (id === req.user.id) return res.status(400).json({ error: '不能删除自己' });
    const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!target) return res.status(404).json({ error: '用户不存在' });
    if (target.role === 'admin') {
      const adminCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'admin' AND status = 'active'").get().c;
      if (adminCount <= 1) return res.status(400).json({ error: '至少保留一名管理员，无法删除最后一个管理员' });
    }
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    audit(req.user.id, 'admin_delete_user', target.username, '', req.ip);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.post('/users/:id/logout', (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (id === req.user.id) return res.status(400).json({ error: '不能强制下线自己' });
    const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!target) return res.status(404).json({ error: '用户不存在' });
    const info = db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').run(id);
    audit(req.user.id, 'admin_logout_user', target.username, String(info.changes || 0), req.ip);
    res.json({ ok: true, revoked: info.changes || 0 });
  } catch (e) { next(e); }
});

router.post('/users', (req, res, next) => {
  try {
    const { username, password, role, displayName } = req.body || {};
    const u = String(username || '').trim().replace(/\s+/g, '_').slice(0, 32);
    if (!u || u.length < 2) return res.status(400).json({ error: '用户名至少 2 个字符' });
    if (typeof password !== 'string' || password.length < 6 || password.length > 128) {
      return res.status(400).json({ error: '密码长度需在 6-128 之间' });
    }
    if (db.prepare('SELECT id FROM users WHERE username = ?').get(u)) {
      return res.status(409).json({ error: '用户名已被占用' });
    }
    const info = db.prepare(
      `INSERT INTO users (username, password_hash, role, status, display_name, created_at)
       VALUES (?, ?, ?, 'active', ?, ?)`
    ).run(u, bcrypt.hashSync(password, 10), role === 'admin' ? 'admin' : 'user', (displayName || '').toString().slice(0, 64), now());
    audit(req.user.id, 'admin_create_user', u, role || 'user', req.ip);
    const user = getUserWithUsage(info.lastInsertRowid);
    res.json({ ok: true, user: publicUser(user) });
  } catch (e) { next(e); }
});

// ---------- Session management ----------
router.get('/sessions', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize || '50', 10)));
  const q = (req.query.q || '').toString().trim();
  const status = (req.query.status || 'active').toString();
  const userId = parseInt(req.query.userId || '0', 10);
  const nowTs = now();
  const refreshHash = currentRefreshHash(req);
  const whereParts = ['1=1'];
  const params = [];
  if (status === 'active') { whereParts.push('rt.expires_at > ?'); params.push(nowTs); }
  if (status === 'expired') { whereParts.push('rt.expires_at <= ?'); params.push(nowTs); }
  if (Number.isFinite(userId) && userId > 0) { whereParts.push('rt.user_id = ?'); params.push(userId); }
  if (q) {
    const like = `%${q}%`;
    whereParts.push('(u.username LIKE ? OR u.display_name LIKE ? OR rt.ip LIKE ? OR rt.user_agent LIKE ?)');
    params.push(like, like, like, like);
  }
  const where = `WHERE ${whereParts.join(' AND ')}`;
  const baseSql = `FROM refresh_tokens rt LEFT JOIN users u ON u.id = rt.user_id ${where}`;
  const total = db.prepare(`SELECT COUNT(*) AS c ${baseSql}`).get(...params).c;
  const rows = db.prepare(
    `SELECT rt.*, u.username, u.display_name, u.role, u.status
     ${baseSql}
     ORDER BY rt.last_seen_at DESC, rt.created_at DESC
     LIMIT ? OFFSET ?`
  ).all(...params, pageSize, (page - 1) * pageSize);
  res.json({
    total,
    page,
    pageSize,
    stats: getSessionStats(nowTs),
    sessions: rows.map(row => publicSession(row, nowTs, req.user.id, refreshHash)),
  });
});

router.delete('/sessions/:id', (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    const session = db.prepare(
      `SELECT rt.*, u.username FROM refresh_tokens rt LEFT JOIN users u ON u.id = rt.user_id WHERE rt.id = ?`
    ).get(id);
    if (!session) return res.status(404).json({ error: '会话不存在' });
    const refreshHash = currentRefreshHash(req);
    if (session.user_id === req.user.id && (!refreshHash || session.token_hash === refreshHash)) {
      return res.status(400).json({ error: '不能在后台强制下线当前会话' });
    }
    const info = db.prepare('DELETE FROM refresh_tokens WHERE id = ?').run(id);
    audit(req.user.id, 'admin_logout_session', session.username || String(session.user_id), `${id}:${session.ip || ''}`, req.ip);
    res.json({ ok: true, revoked: info.changes || 0 });
  } catch (e) { next(e); }
});

router.post('/sessions/cleanup-expired', (req, res, next) => {
  try {
    const info = db.prepare('DELETE FROM refresh_tokens WHERE expires_at <= ?').run(now());
    audit(req.user.id, 'admin_cleanup_sessions', 'refresh_tokens', String(info.changes || 0), req.ip);
    res.json({ ok: true, removed: info.changes || 0 });
  } catch (e) { next(e); }
});

// ---------- Statistics ----------
router.get('/stats', async (req, res, next) => {
  try {
  const range = (req.query.range || '7d').toString();
  const nowTs = now();
  const ranges = { '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3, 'all': Infinity };
  const span = ranges[range] || ranges['7d'];
  const since = span === Infinity ? 0 : nowTs - span;

  const users = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const activeUsers = db.prepare("SELECT COUNT(*) as c FROM users WHERE status = 'active'").get().c;
  const admins = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'admin'").get().c;
  const banned = db.prepare("SELECT COUNT(*) as c FROM users WHERE status = 'banned'").get().c;
  const newUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE created_at >= ?').get(since).c;
  const activeInRange = db.prepare('SELECT COUNT(DISTINCT user_id) as c FROM audit_logs WHERE action = ? AND created_at >= ?').get('login', since).c;
  const sessionStats = getSessionStats(nowTs);

  const cards = db.prepare('SELECT COUNT(*) as c FROM library_cards').get().c;
  const pendingCards = db.prepare("SELECT COUNT(*) as c FROM library_cards WHERE status = 'pending'").get().c;
  const approvedCards = db.prepare("SELECT COUNT(*) as c FROM library_cards WHERE status = 'approved'").get().c;
  const totalDownloads = db.prepare('SELECT COALESCE(SUM(download_count),0) as s FROM library_cards').get().s;

  const announcements = db.prepare('SELECT COUNT(*) as c FROM announcements WHERE active = 1').get().c;
  const apiTotals = db.prepare(
    `SELECT COALESCE(SUM(prompt_tokens),0) as prompt,
            COALESCE(SUM(completion_tokens),0) as completion,
            COALESCE(SUM(total_tokens),0) as total,
            COUNT(*) as requests,
            COUNT(DISTINCT user_id) as users,
            COUNT(DISTINCT NULLIF(model, '')) as models
     FROM api_usage WHERE created_at >= ?`
  ).get(since);

  // Time series is bucketed in SQL to keep the dashboard light.
  const dayMs = 86400000;
  const bucketMs = range === '24h' ? 3600000 : dayMs;
  const bucketCount = range === '24h'
    ? 24
    : Math.min(span === Infinity ? 30 : Math.ceil(span / dayMs), 90);
  const seriesStart = Math.floor((nowTs - (bucketCount - 1) * bucketMs) / bucketMs) * bucketMs;
  const seriesEndExclusive = Math.floor(nowTs / bucketMs) * bucketMs + bucketMs;

  const newUsersByBucket = db.prepare(
    `SELECT (CAST(created_at / ? AS INTEGER) * ?) AS bucket, COUNT(*) AS c
     FROM users WHERE created_at >= ? AND created_at < ?
     GROUP BY bucket`
  ).all(bucketMs, bucketMs, seriesStart, seriesEndExclusive);
  const loginsByBucket = db.prepare(
    `SELECT (CAST(created_at / ? AS INTEGER) * ?) AS bucket, COUNT(DISTINCT user_id) AS c
     FROM audit_logs WHERE action = 'login' AND created_at >= ? AND created_at < ?
     GROUP BY bucket`
  ).all(bucketMs, bucketMs, seriesStart, seriesEndExclusive);
  const apiUsageByBucket = db.prepare(
    `SELECT (CAST(created_at / ? AS INTEGER) * ?) AS bucket,
            COALESCE(SUM(total_tokens), 0) AS tokens,
            COUNT(*) AS requests
     FROM api_usage WHERE created_at >= ? AND created_at < ?
     GROUP BY bucket`
  ).all(bucketMs, bucketMs, seriesStart, seriesEndExclusive);

  const newUsersMap = Object.fromEntries(newUsersByBucket.map(r => [r.bucket, r.c]));
  const loginsMap = Object.fromEntries(loginsByBucket.map(r => [r.bucket, r.c]));
  const apiMap = Object.fromEntries(apiUsageByBucket.map(r => [r.bucket, r]));
  const series = [];
  for (let i = bucketCount - 1; i >= 0; i--) {
    const bucketStart = Math.floor((nowTs - i * bucketMs) / bucketMs) * bucketMs;
    const apiBucket = apiMap[bucketStart] || {};
    series.push({
      date: bucketStart,
      newUsers: newUsersMap[bucketStart] || 0,
      logins: loginsMap[bucketStart] || 0,
      apiTokens: Number(apiBucket.tokens || 0),
      apiRequests: Number(apiBucket.requests || 0),
    });
  }

  const [database, imageCache] = await Promise.all([
    getDatabaseStats(),
    scanImageCache(),
  ]);
  const syncStorage = getSyncStorageStats();

  res.json({
    range,
    bucketMs,
    users: { total: users, active: activeUsers, admins, banned, newUsers, activeInRange, ...sessionStats },
    cards: { total: cards, pending: pendingCards, approved: approvedCards, totalDownloads },
    apiUsage: {
      promptTokens: Number(apiTotals.prompt || 0),
      completionTokens: Number(apiTotals.completion || 0),
      totalTokens: Number(apiTotals.total || 0),
      requests: Number(apiTotals.requests || 0),
      activeUsers: Number(apiTotals.users || 0),
      activeModels: Number(apiTotals.models || 0),
    },
    storage: {
      database: {
        totalBytes: database.totalBytes,
        dbBytes: database.dbBytes,
        walBytes: database.walBytes,
        freelistBytes: database.freelistBytes,
        freeRatio: database.freeRatio,
        journalMode: database.journalMode,
      },
      imageCache: {
        images: imageCache.images,
        users: imageCache.users,
        bytes: imageCache.bytes,
        tempFiles: imageCache.tempFiles,
        tempBytes: imageCache.tempBytes,
      },
      syncStorage: {
        records: syncStorage.records,
        totalBytes: syncStorage.totalBytes,
        missingHashes: syncStorage.missingHashes,
      },
    },
    announcements,
    series,
  });
  } catch (e) { next(e); }
});

// ---------- Maintenance / storage overview ----------
router.get('/maintenance/overview', async (req, res, next) => {
  try {
    const syncStorage = getSyncStorageStats();
    const [imageCache, database] = await Promise.all([
      scanImageCache(),
      getDatabaseStats(),
    ]);
    res.json({
      generatedAt: now(),
      syncStorage,
      imageCache,
      database,
    });
  } catch (e) { next(e); }
});

router.post('/maintenance/rebuild-sync-hashes', (req, res, next) => {
  try {
    const rows = db.prepare(
      `SELECT id, value FROM user_data WHERE value_hash IS NULL OR value_hash = ''`
    ).all();
    if (rows.length) {
      const tx = db.transaction(() => {
        const update = db.prepare('UPDATE user_data SET value_hash = ? WHERE id = ?');
        for (const row of rows) update.run(hashSerializedValue(row.value), row.id);
      });
      tx();
    }
    audit(req.user.id, 'admin_rebuild_sync_hashes', 'user_data', String(rows.length), req.ip);
    res.json({ ok: true, updated: rows.length });
  } catch (e) { next(e); }
});

router.post('/maintenance/cleanup-image-cache-temp', async (req, res, next) => {
  try {
    const result = await scanImageCache({ cleanupTemps: true });
    audit(
      req.user.id,
      'admin_cleanup_image_cache_temp',
      'image-cache',
      `${result.removedTempFiles}:${result.removedTempBytes}`,
      req.ip
    );
    res.json({
      ok: true,
      removedFiles: result.removedTempFiles,
      removedBytes: result.removedTempBytes,
      imageCache: result,
    });
  } catch (e) { next(e); }
});

router.post('/maintenance/optimize-database', async (req, res, next) => {
  try {
    const result = await optimizeDatabase();
    audit(
      req.user.id,
      'admin_optimize_database',
      'sqlite',
      `${result.savedBytes}:${result.vacuumed ? 'vacuum' : 'checkpoint'}`,
      req.ip
    );
    res.json(result);
  } catch (e) { next(e); }
});

// ---------- Audit logs ----------
router.get('/audit', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize || '50', 10)));
  const action = (req.query.action || '').toString();
  const q = (req.query.q || '').toString().trim();
  const userId = parseInt(req.query.userId || '0', 10);
  const whereParts = [];
  const params = [];
  if (action) { whereParts.push('a.action = ?'); params.push(action); }
  if (Number.isFinite(userId) && userId > 0) { whereParts.push('a.user_id = ?'); params.push(userId); }
  if (q) {
    const like = `%${q}%`;
    whereParts.push('(u.username LIKE ? OR a.action LIKE ? OR a.target LIKE ? OR a.detail LIKE ? OR a.ip LIKE ?)');
    params.push(like, like, like, like, like);
  }
  const where = whereParts.length ? `WHERE ${whereParts.join(' AND ')}` : '';
  const total = db.prepare(
    `SELECT COUNT(*) as c FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id ${where}`
  ).get(...params).c;
  const rows = db.prepare(
    `SELECT a.*, u.username FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id
     ${where} ORDER BY a.created_at DESC LIMIT ? OFFSET ?`
  ).all(...params, pageSize, (page - 1) * pageSize);
  res.json({
    total, page, pageSize,
    logs: rows.map(r => ({
      id: r.id, userId: r.user_id, username: r.username, action: r.action,
      target: r.target, detail: r.detail, ip: r.ip, createdAt: r.created_at,
    })),
  });
});

// ---------- Announcements management ----------
router.get('/announcements', (req, res) => {
  const rows = db.prepare('SELECT * FROM announcements ORDER BY created_at DESC').all();
  res.json({ announcements: rows });
});

router.post('/announcements', (req, res, next) => {
  try {
    const { title, content, type, pinned, active, expiresAt } = req.body || {};
    if (!title || !content) return res.status(400).json({ error: '标题和内容必填' });
    const info = db.prepare(
      `INSERT INTO announcements (title, content, type, pinned, active, author_id, created_at, updated_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      String(title).slice(0, 128),
      String(content).slice(0, 16384),
      ['info', 'notice', 'maintenance'].includes(type) ? type : 'info',
      pinned ? 1 : 0,
      active === false ? 0 : 1,
      req.user.id,
      now(), now(),
      typeof expiresAt === 'number' && expiresAt > now() ? expiresAt : null
    );
    audit(req.user.id, 'announcement_create', String(title), '', req.ip);
    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (e) { next(e); }
});

router.patch('/announcements/:id', (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    const a = db.prepare('SELECT * FROM announcements WHERE id = ?').get(id);
    if (!a) return res.status(404).json({ error: '公告不存在' });
    const { title, content, type, pinned, active, expiresAt } = req.body || {};
    const sets = []; const vals = [];
    if (typeof title === 'string') { sets.push('title = ?'); vals.push(title.slice(0, 128)); }
    if (typeof content === 'string') { sets.push('content = ?'); vals.push(content.slice(0, 16384)); }
    if (['info', 'notice', 'maintenance'].includes(type)) { sets.push('type = ?'); vals.push(type); }
    if (typeof pinned === 'boolean') { sets.push('pinned = ?'); vals.push(pinned ? 1 : 0); }
    if (typeof active === 'boolean') { sets.push('active = ?'); vals.push(active ? 1 : 0); }
    if (expiresAt === null || (typeof expiresAt === 'number' && expiresAt > now())) {
      sets.push('expires_at = ?'); vals.push(expiresAt);
    }
    if (!sets.length) return res.json({ ok: true });
    sets.push('updated_at = ?'); vals.push(now()); vals.push(id);
    db.prepare(`UPDATE announcements SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
    audit(req.user.id, 'announcement_update', String(a.title), sets.join(','), req.ip);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

router.delete('/announcements/:id', (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    const a = db.prepare('SELECT * FROM announcements WHERE id = ?').get(id);
    if (!a) return res.status(404).json({ error: '公告不存在' });
    db.prepare('DELETE FROM announcements WHERE id = ?').run(id);
    audit(req.user.id, 'announcement_delete', String(a.title), '', req.ip);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ---------- API usage ----------
router.get('/api-usage', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize || '50', 10)));
  const userId = parseInt(req.query.userId || '0', 10);
  let where = ''; const params = [];
  if (userId) { where = 'WHERE user_id = ?'; params.push(userId); }
  const total = db.prepare(`SELECT COUNT(*) as c FROM api_usage ${where}`).get(...params).c;
  const rows = db.prepare(
    `SELECT u.*, us.username FROM api_usage u LEFT JOIN users us ON us.id = u.user_id
     ${where} ORDER BY u.created_at DESC LIMIT ? OFFSET ?`
  ).all(...params, pageSize, (page - 1) * pageSize);
  res.json({
    total, page, pageSize,
    usage: rows.map(r => ({
      id: r.id, userId: r.user_id, username: r.username, endpoint: r.endpoint,
      model: r.model, promptTokens: r.prompt_tokens, completionTokens: r.completion_tokens,
      totalTokens: r.total_tokens, createdAt: r.created_at,
    })),
  });
});

router.get('/api-usage/summary', (req, res) => {
  const range = (req.query.range || '7d').toString();
  const spans = { '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3 };
  const span = spans[range] || spans['7d'];
  const end = now();
  const since = end - span;
  const bucketMs = range === '24h' ? 3600e3 : 86400e3;
  const bucketStart = Math.floor(since / bucketMs) * bucketMs;
  const bucketCount = Math.floor((end - bucketStart) / bucketMs) + 1;
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({
    index,
    start: bucketStart + index * bucketMs,
    promptTokens: 0,
    completionTokens: 0,
    totalTokens: 0,
    requests: 0,
  }));
  const totals = db.prepare(
    `SELECT COALESCE(SUM(prompt_tokens),0) as p, COALESCE(SUM(completion_tokens),0) as c,
            COALESCE(SUM(total_tokens),0) as t, COUNT(*) as n,
            COUNT(DISTINCT user_id) as users, COUNT(DISTINCT NULLIF(model, '')) as models
     FROM api_usage WHERE created_at >= ?`
  ).get(since);
  const seriesRows = db.prepare(
    `SELECT CAST((created_at - ?) / ? AS INTEGER) as bucket,
            COALESCE(SUM(prompt_tokens),0) as p, COALESCE(SUM(completion_tokens),0) as c,
            COALESCE(SUM(total_tokens),0) as t, COUNT(*) as n
     FROM api_usage
     WHERE created_at >= ?
     GROUP BY bucket
     ORDER BY bucket ASC`
  ).all(bucketStart, bucketMs, since);
  for (const row of seriesRows) {
    const target = buckets[row.bucket];
    if (!target) continue;
    target.promptTokens = row.p;
    target.completionTokens = row.c;
    target.totalTokens = row.t;
    target.requests = row.n;
  }
  const byUser = db.prepare(
    `SELECT u.user_id, us.username,
            COALESCE(SUM(u.prompt_tokens),0) as prompt,
            COALESCE(SUM(u.completion_tokens),0) as completion,
            COALESCE(SUM(u.total_tokens),0) as total,
            COUNT(*) as count
     FROM api_usage u LEFT JOIN users us ON us.id = u.user_id
     WHERE u.created_at >= ? GROUP BY u.user_id ORDER BY total DESC LIMIT 20`
  ).all(since);
  const byModel = db.prepare(
    `SELECT COALESCE(NULLIF(model, ''), 'unknown') as model,
            COALESCE(SUM(prompt_tokens),0) as prompt,
            COALESCE(SUM(completion_tokens),0) as completion,
            COALESCE(SUM(total_tokens),0) as total,
            COUNT(*) as count
     FROM api_usage
     WHERE created_at >= ?
     GROUP BY COALESCE(NULLIF(model, ''), 'unknown')
     ORDER BY total DESC LIMIT 12`
  ).all(since);
  const byEndpoint = db.prepare(
    `SELECT COALESCE(NULLIF(endpoint, ''), 'unknown') as endpoint,
            COALESCE(SUM(total_tokens),0) as total,
            COUNT(*) as count
     FROM api_usage
     WHERE created_at >= ?
     GROUP BY COALESCE(NULLIF(endpoint, ''), 'unknown')
     ORDER BY total DESC LIMIT 8`
  ).all(since);
  const recent = db.prepare(
    `SELECT u.*, us.username FROM api_usage u LEFT JOIN users us ON us.id = u.user_id
     WHERE u.created_at >= ?
     ORDER BY u.created_at DESC LIMIT 12`
  ).all(since);
  res.json({
    range,
    bucketMs,
    since,
    end,
    totals: {
      promptTokens: totals.p,
      completionTokens: totals.c,
      totalTokens: totals.t,
      requests: totals.n,
      activeUsers: totals.users,
      activeModels: totals.models,
      avgTokens: totals.n ? Math.round(totals.t / totals.n) : 0,
    },
    series: buckets.map(b => ({
      start: b.start,
      promptTokens: b.promptTokens,
      completionTokens: b.completionTokens,
      totalTokens: b.totalTokens,
      requests: b.requests,
    })),
    byUser: byUser.map(r => ({
      userId: r.user_id,
      username: r.username,
      promptTokens: r.prompt,
      completionTokens: r.completion,
      totalTokens: r.total,
      requests: r.count,
    })),
    byModel: byModel.map(r => ({
      model: r.model,
      promptTokens: r.prompt,
      completionTokens: r.completion,
      totalTokens: r.total,
      requests: r.count,
    })),
    byEndpoint: byEndpoint.map(r => ({ endpoint: r.endpoint, totalTokens: r.total, requests: r.count })),
    recent: recent.map(r => ({
      id: r.id,
      userId: r.user_id,
      username: r.username,
      endpoint: r.endpoint,
      model: r.model,
      promptTokens: r.prompt_tokens,
      completionTokens: r.completion_tokens,
      totalTokens: r.total_tokens,
      createdAt: r.created_at,
    })),
  });
});

export default router;

import { Router } from 'express';
import bcrypt from 'bcryptjs';
import fs from 'fs/promises';
import path from 'path';
import { config } from '../config.js';
import { db, now, audit } from '../db.js';
import { adminRequired } from '../middleware/auth.js';

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
    apiQuota: u.api_quota,
    apiKey: u.api_key ? u.api_key.slice(0, 4) + '****' : '',
    createdAt: u.created_at,
    lastLoginAt: u.last_login_at,
    bannedReason: u.banned_reason,
  };
}

const IMAGE_CACHE_ROOT = path.resolve(path.dirname(config.dbPath), 'image-cache');
const IMAGE_CACHE_TEMP_MAX_AGE = 60 * 60 * 1000;

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

// ---------- User management ----------
router.get('/users', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize || '50', 10)));
  const q = (req.query.q || '').toString().trim();
  const status = (req.query.status || '').toString();
  const role = (req.query.role || '').toString();
  let where = 'WHERE 1=1';
  const params = [];
  if (q) { where += ` AND (username LIKE ? OR display_name LIKE ?)`; params.push(`%${q}%`, `%${q}%`); }
  if (status) { where += ` AND status = ?`; params.push(status); }
  if (role) { where += ` AND role = ?`; params.push(role); }

  const total = db.prepare(`SELECT COUNT(*) as c FROM users ${where}`).get(...params).c;
  const rows = db.prepare(
    `SELECT * FROM users ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
  ).all(...params, pageSize, (page - 1) * pageSize);

  res.json({ total, page, pageSize, users: rows.map(publicUser) });
});

router.get('/users/:id', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(parseInt(req.params.id, 10));
  if (!u) return res.status(404).json({ error: '用户不存在' });
  res.json({ user: publicUser(u) });
});

router.patch('/users/:id', (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (!target) return res.status(404).json({ error: '用户不存在' });

    const { role, status, displayName, apiQuota, apiKey, bannedReason, password } = req.body || {};
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
    if (typeof apiQuota === 'number' && apiQuota >= 0 && apiQuota <= 1e12) {
      sets.push('api_quota = ?'); vals.push(apiQuota);
    }
    if (typeof apiKey === 'string' && apiKey.length <= 256) {
      sets.push('api_key = ?'); vals.push(apiKey);
    }
    if (typeof password === 'string' && password.length >= 6 && password.length <= 128) {
      sets.push('password_hash = ?'); vals.push(bcrypt.hashSync(password, 10));
      db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').run(id);
    }

    if (!sets.length) return res.json({ ok: true, user: publicUser(target) });
    vals.push(id);
    db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
    audit(req.user.id, 'admin_update_user', target.username, sets.join(','), req.ip);
    const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
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
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    res.json({ ok: true, user: publicUser(user) });
  } catch (e) { next(e); }
});

// ---------- Statistics ----------
router.get('/stats', (req, res) => {
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

  const cards = db.prepare('SELECT COUNT(*) as c FROM library_cards').get().c;
  const pendingCards = db.prepare("SELECT COUNT(*) as c FROM library_cards WHERE status = 'pending'").get().c;
  const approvedCards = db.prepare("SELECT COUNT(*) as c FROM library_cards WHERE status = 'approved'").get().c;
  const totalDownloads = db.prepare('SELECT COALESCE(SUM(download_count),0) as s FROM library_cards').get().s;

  const announcements = db.prepare('SELECT COUNT(*) as c FROM announcements WHERE active = 1').get().c;

  // Daily series (login + new users) — aggregated instead of per-day queries
  const dayMs = 86400000;
  const days = Math.min(span === Infinity ? 30 : Math.ceil(span / dayMs), 90);
  const seriesStart = Math.floor((nowTs - (days - 1) * dayMs) / dayMs) * dayMs;
  const seriesEndExclusive = Math.floor(nowTs / dayMs) * dayMs + dayMs;

  const newUsersByDay = db.prepare(
    `SELECT (CAST(created_at / ? AS INTEGER) * ?) AS day, COUNT(*) AS c
     FROM users WHERE created_at >= ? AND created_at < ?
     GROUP BY day`
  ).all(dayMs, dayMs, seriesStart, seriesEndExclusive);
  const loginsByDay = db.prepare(
    `SELECT (CAST(created_at / ? AS INTEGER) * ?) AS day, COUNT(DISTINCT user_id) AS c
     FROM audit_logs WHERE action = 'login' AND created_at >= ? AND created_at < ?
     GROUP BY day`
  ).all(dayMs, dayMs, seriesStart, seriesEndExclusive);

  const newUsersMap = Object.fromEntries(newUsersByDay.map(r => [r.day, r.c]));
  const loginsMap = Object.fromEntries(loginsByDay.map(r => [r.day, r.c]));
  const series = [];
  for (let i = days - 1; i >= 0; i--) {
    const dayStartDay = Math.floor((nowTs - i * dayMs) / dayMs) * dayMs;
    series.push({
      date: dayStartDay,
      newUsers: newUsersMap[dayStartDay] || 0,
      logins: loginsMap[dayStartDay] || 0,
    });
  }

  res.json({
    range,
    users: { total: users, active: activeUsers, admins, banned, newUsers, activeInRange },
    cards: { total: cards, pending: pendingCards, approved: approvedCards, totalDownloads },
    announcements,
    series,
  });
});

// ---------- Maintenance / storage overview ----------
router.get('/maintenance/overview', async (req, res, next) => {
  try {
    const syncStorage = getSyncStorageStats();
    const imageCache = await scanImageCache();
    res.json({
      generatedAt: now(),
      syncStorage,
      imageCache,
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

// ---------- Audit logs ----------
router.get('/audit', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize || '50', 10)));
  const action = (req.query.action || '').toString();
  let where = '';
  const params = [];
  if (action) { where = 'WHERE action = ?'; params.push(action); }
  const total = db.prepare(`SELECT COUNT(*) as c FROM audit_logs ${where}`).get(...params).c;
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

// ---------- API quota / usage ----------
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

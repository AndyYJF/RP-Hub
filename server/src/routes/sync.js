import { Router } from 'express';
import { db, now, audit } from '../db.js';
import { authRequired } from '../middleware/auth.js';

const router = Router();

// All sync endpoints require authentication
router.use(authRequired);

// Names allowed to be synced. Everything else is rejected to avoid abuse.
// Maps to the frontend storage keys (without prefix).
const GLOBAL_KEYS = new Set([
  'characters',
  'settings',
  'presets',
  'regex',
  'global_regex',
  'worldinfo',
  'global_worldinfo',
  'worldinfo_settings',
  'global_ui_templates',
  'active_tools',
  'user',
  'user_profiles',
  'active_profile_id',
  'last_active_char',
  'last_active_char_uuid',
  'memory_settings',
]);
const SCOPED_KEYS = new Set(['chat', 'memories']);
const MAX_VALUE_SIZE = 50 * 1024 * 1024; // 50MB per value (角色卡含 avatar base64 可能很大)

function hashSerializedValue(text) {
  let hash = 2166136261;
  const value = String(text || '');
  for (let i = 0; i < value.length; i++) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

function checkKey(name, scoped) {
  const allowed = scoped ? SCOPED_KEYS : GLOBAL_KEYS;
  if (!allowed.has(name)) {
    const err = new Error('不支持的同步字段: ' + name);
    err.status = 400;
    throw err;
  }
}

function checkSize(value) {
  if (typeof value === 'string' && value.length > MAX_VALUE_SIZE) {
    const err = new Error('单条数据过大（超过 8MB），请精简后重试');
    err.status = 413;
    throw err;
  }
}

function serialize(value) {
  if (value === undefined || value === null) return null;
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function makeStoredValue(value) {
  const serialized = serialize(value);
  return { serialized, valueHash: hashSerializedValue(serialized) };
}

function deserialize(text) {
  if (text === null || text === undefined) return undefined;
  try { return JSON.parse(text); } catch (_) { return text; }
}

// ---------- GET /sync/all : bulk fetch everything ----------
router.get('/all', (req, res, next) => {
  try {
    const rows = db.prepare(
      'SELECT scope, name, value, value_hash, updated_at FROM user_data WHERE user_id = ?'
    ).all(req.user.id);
    const data = { global: {}, scoped: {}, updatedAt: {}, hashes: {} };
    for (const r of rows) {
      const metaKey = `${r.scope}:${r.name}`;
      data.updatedAt[metaKey] = r.updated_at;
      data.hashes[metaKey] = r.value_hash || hashSerializedValue(r.value);
      if (r.scope === 'global') data.global[r.name] = deserialize(r.value);
      else {
        // scoped name format: <name>:<id>
        const [name, id] = r.name.split(':');
        if (!data.scoped[name]) data.scoped[name] = {};
        data.scoped[name][id] = deserialize(r.value);
      }
    }
    res.json(data);
  } catch (e) { next(e); }
});

// ---------- GET /sync/bootstrap : global values + scoped timestamps ----------
router.get('/bootstrap', (req, res, next) => {
  try {
    const rows = db.prepare(
      'SELECT scope, name, value, value_hash, updated_at FROM user_data WHERE user_id = ?'
    ).all(req.user.id);
    const data = { global: {}, scoped: {}, scopedMeta: {}, updatedAt: {}, hashes: {} };
    for (const r of rows) {
      const metaKey = `${r.scope}:${r.name}`;
      data.updatedAt[metaKey] = r.updated_at;
      data.hashes[metaKey] = r.value_hash || hashSerializedValue(r.value);
      if (r.scope === 'global') {
        data.global[r.name] = deserialize(r.value);
      } else {
        const [name, id] = r.name.split(':');
        if (!data.scopedMeta[name]) data.scopedMeta[name] = {};
        data.scopedMeta[name][id] = r.updated_at;
      }
    }
    res.json(data);
  } catch (e) { next(e); }
});

// ---------- POST /sync/bootstrap-diff : global values only when client meta is stale ----------
router.post('/bootstrap-diff', (req, res, next) => {
  try {
    const known = req.body?.known && typeof req.body.known === 'object' ? req.body.known : {};
    const rows = db.prepare(
      'SELECT scope, name, value_hash, updated_at FROM user_data WHERE user_id = ?'
    ).all(req.user.id);
    const data = { global: {}, scoped: {}, scopedMeta: {}, updatedAt: {}, hashes: {} };
    const valueStmt = db.prepare(
      'SELECT value, value_hash FROM user_data WHERE user_id = ? AND scope = ? AND name = ?'
    );
    for (const r of rows) {
      const metaKey = `${r.scope}:${r.name}`;
      data.updatedAt[metaKey] = r.updated_at;
      if (r.value_hash) data.hashes[metaKey] = r.value_hash;
      if (r.scope === 'global') {
        const knownTs = Number(known[metaKey] || 0);
        if (!knownTs || r.updated_at > knownTs) {
          const valueRow = valueStmt.get(req.user.id, r.scope, r.name);
          data.global[r.name] = deserialize(valueRow?.value);
          data.hashes[metaKey] = valueRow?.value_hash || hashSerializedValue(valueRow?.value);
        }
      } else {
        const [name, id] = r.name.split(':');
        if (!data.scopedMeta[name]) data.scopedMeta[name] = {};
        data.scopedMeta[name][id] = r.updated_at;
      }
    }
    res.json(data);
  } catch (e) { next(e); }
});

// ---------- GET /sync/global/:name ----------
router.get('/global/:name', (req, res, next) => {
  try {
    checkKey(req.params.name, false);
    const row = db.prepare(
      'SELECT value, updated_at FROM user_data WHERE user_id = ? AND scope = ? AND name = ?'
    ).get(req.user.id, 'global', req.params.name);
    res.json({ value: row ? deserialize(row.value) : undefined, updatedAt: row?.updated_at || 0 });
  } catch (e) { next(e); }
});

// ---------- PUT /sync/global/:name ----------
router.put('/global/:name', (req, res, next) => {
  try {
    const name = req.params.name;
    checkKey(name, false);
    const value = req.body?.value;
    const { serialized, valueHash } = makeStoredValue(value);
    checkSize(serialized);
    db.prepare(
      `INSERT INTO user_data (user_id, scope, name, value, value_hash, updated_at) VALUES (?, 'global', ?, ?, ?, ?)
       ON CONFLICT(user_id, scope, name) DO UPDATE SET value = excluded.value, value_hash = excluded.value_hash, updated_at = excluded.updated_at`
    ).run(req.user.id, name, serialized, valueHash, now());
    res.json({ ok: true, updatedAt: now() });
  } catch (e) { next(e); }
});

// ---------- DELETE /sync/global/:name ----------
router.delete('/global/:name', (req, res, next) => {
  try {
    checkKey(req.params.name, false);
    db.prepare('DELETE FROM user_data WHERE user_id = ? AND scope = ? AND name = ?')
      .run(req.user.id, 'global', req.params.name);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ---------- GET /sync/scoped/:name/:id ----------
router.get('/scoped/:name/:id', (req, res, next) => {
  try {
    const { name, id } = req.params;
    checkKey(name, true);
    const scopedName = `${name}:${id}`;
    const row = db.prepare(
      'SELECT value, updated_at FROM user_data WHERE user_id = ? AND scope = ? AND name = ?'
    ).get(req.user.id, 'scoped', scopedName);
    res.json({ value: row ? deserialize(row.value) : undefined, updatedAt: row?.updated_at || 0 });
  } catch (e) { next(e); }
});

// ---------- PUT /sync/scoped/:name/:id ----------
router.put('/scoped/:name/:id', (req, res, next) => {
  try {
    const { name, id } = req.params;
    checkKey(name, true);
    const value = req.body?.value;
    const { serialized, valueHash } = makeStoredValue(value);
    checkSize(serialized);
    const scopedName = `${name}:${id}`;
    db.prepare(
      `INSERT INTO user_data (user_id, scope, name, value, value_hash, updated_at) VALUES (?, 'scoped', ?, ?, ?, ?)
       ON CONFLICT(user_id, scope, name) DO UPDATE SET value = excluded.value, value_hash = excluded.value_hash, updated_at = excluded.updated_at`
    ).run(req.user.id, scopedName, serialized, valueHash, now());
    res.json({ ok: true, updatedAt: now() });
  } catch (e) { next(e); }
});

// ---------- DELETE /sync/scoped/:name/:id ----------
router.delete('/scoped/:name/:id', (req, res, next) => {
  try {
    const { name, id } = req.params;
    checkKey(name, true);
    const scopedName = `${name}:${id}`;
    db.prepare('DELETE FROM user_data WHERE user_id = ? AND scope = ? AND name = ?')
      .run(req.user.id, 'scoped', scopedName);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ---------- POST /sync/bulk : batch upsert (reduces requests) ----------
router.post('/bulk', (req, res, next) => {
  try {
    const { global = {}, scoped = {}, deletes = { global: [], scoped: [] } } = req.body || {};
    const tx = db.transaction(() => {
      const upsert = db.prepare(
        `INSERT INTO user_data (user_id, scope, name, value, value_hash, updated_at) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, scope, name) DO UPDATE SET value = excluded.value, value_hash = excluded.value_hash, updated_at = excluded.updated_at`
      );
      const del = db.prepare('DELETE FROM user_data WHERE user_id = ? AND scope = ? AND name = ?');
      for (const [name, value] of Object.entries(global)) {
        checkKey(name, false);
        const { serialized, valueHash } = makeStoredValue(value);
        checkSize(serialized);
        upsert.run(req.user.id, 'global', name, serialized, valueHash, now());
      }
      for (const [name, scopedMap] of Object.entries(scoped)) {
        checkKey(name, true);
        for (const [id, value] of Object.entries(scopedMap)) {
          const { serialized, valueHash } = makeStoredValue(value);
          checkSize(serialized);
          upsert.run(req.user.id, 'scoped', `${name}:${id}`, serialized, valueHash, now());
        }
      }
      for (const name of (deletes.global || [])) {
        checkKey(name, false);
        del.run(req.user.id, 'global', name);
      }
      for (const entry of (deletes.scoped || [])) {
        checkKey(entry.name, true);
        del.run(req.user.id, 'scoped', `${entry.name}:${entry.id}`);
      }
    });
    tx();
    res.json({ ok: true, updatedAt: now() });
  } catch (e) { next(e); }
});

// ---------- Wipe account data (keep user) ----------
router.delete('/wipe', (req, res) => {
  db.prepare('DELETE FROM user_data WHERE user_id = ?').run(req.user.id);
  audit(req.user.id, 'wipe_data', req.user.username, '', req.ip);
  res.json({ ok: true });
});

export default router;

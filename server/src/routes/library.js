import { Router } from 'express';
import { db, now, audit } from '../db.js';
import { authRequired, authOptional, adminRequired } from '../middleware/auth.js';

const router = Router();

const MAX_CARD_SIZE = 4 * 1024 * 1024;

function parseTags(tags) {
  if (Array.isArray(tags)) return tags.map(t => String(t).trim()).filter(Boolean).join(',');
  if (typeof tags === 'string') return tags.split(',').map(t => t.trim()).filter(Boolean).join(',');
  return '';
}

function publicCard(c) {
  if (!c) return null;
  return {
    id: c.id,
    uuid: c.uuid,
    authorId: c.author_id,
    authorName: c.author_name,
    name: c.name,
    description: c.description,
    tags: c.tags ? c.tags.split(',').filter(Boolean) : [],
    status: c.status,
    reviewNote: c.review_note,
    downloadCount: c.download_count,
    createdAt: c.created_at,
    updatedAt: c.updated_at,
    reviewedAt: c.reviewed_at,
  };
}

function buildAdminLibraryWhere({ status = '', q = '' } = {}) {
  const parts = [];
  const params = [];
  if (status) {
    parts.push('status = ?');
    params.push(status);
  }
  const query = String(q || '').trim().slice(0, 120);
  if (query) {
    const like = `%${query}%`;
    parts.push(`(
      name LIKE ? OR description LIKE ? OR tags LIKE ? OR author_name LIKE ? OR uuid LIKE ? OR CAST(id AS TEXT) LIKE ?
    )`);
    params.push(like, like, like, like, like, like);
  }
  return {
    where: parts.length ? `WHERE ${parts.join(' AND ')}` : '',
    params,
  };
}

// ---------- Public: list approved cards ----------
router.get('/', (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const pageSize = Math.min(50, Math.max(1, parseInt(req.query.pageSize || '20', 10)));
    const q = (req.query.q || '').toString().trim();
    const tag = (req.query.tag || '').toString().trim();
    const sort = (req.query.sort || 'newest').toString();

    let where = "WHERE status = 'approved'";
    const params = [];
    if (q) {
      where += ` AND (name LIKE ? OR description LIKE ?)`;
      params.push(`%${q}%`, `%${q}%`);
    }
    if (tag) {
      where += ` AND tags LIKE ?`;
      params.push(`%${tag}%`);
    }
    const orderBy = sort === 'downloads' ? 'download_count DESC' : 'created_at DESC';

    const total = db.prepare(`SELECT COUNT(*) as c FROM library_cards ${where}`).get(...params).c;
    const rows = db.prepare(
      `SELECT * FROM library_cards ${where} ORDER BY ${orderBy} LIMIT ? OFFSET ?`
    ).all(...params, pageSize, (page - 1) * pageSize);

    res.json({
      total, page, pageSize,
      cards: rows.map(publicCard),
    });
  } catch (e) { next(e); }
});

// ---------- Public: get tags list ----------
router.get('/tags', (_req, res) => {
  const rows = db.prepare("SELECT tags FROM library_cards WHERE status = 'approved' AND tags != ''").all();
  const counts = {};
  for (const r of rows) {
    for (const t of r.tags.split(',').map(s => s.trim()).filter(Boolean)) {
      counts[t] = (counts[t] || 0) + 1;
    }
  }
  const tags = Object.entries(counts).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
  res.json({ tags });
});

// ---------- Public: download a card (returns full card_json) ----------
router.get('/:uuid', authOptional, (req, res, next) => {
  try {
    const c = db.prepare('SELECT * FROM library_cards WHERE uuid = ?').get(req.params.uuid);
    if (!c) return res.status(404).json({ error: '角色卡不存在' });
    if (c.status !== 'approved' && (!req.user || req.user.role !== 'admin')) {
      return res.status(403).json({ error: '该角色卡暂不可访问' });
    }
    // Increment download count (only for approved cards, don't count admin preview)
    if (c.status === 'approved') {
      db.prepare('UPDATE library_cards SET download_count = download_count + 1 WHERE id = ?').run(c.id);
    }
    audit(req.user?.id, 'library_download', c.uuid, c.name, req.ip);
    res.json({ card: publicCard(c), data: JSON.parse(c.card_json) });
  } catch (e) { next(e); }
});

// ---------- Auth required: submit a card ----------
router.post('/submit', authRequired, (req, res, next) => {
  try {
    const { uuid, name, description, tags, card } = req.body || {};
    if (!card) return res.status(400).json({ error: '缺少角色卡数据' });
    const cardStr = typeof card === 'string' ? card : JSON.stringify(card);
    if (cardStr.length > MAX_CARD_SIZE) return res.status(413).json({ error: '角色卡过大（超过 4MB）' });

    const finalUuid = (uuid || card.uuid || '').toString();
    if (!finalUuid) return res.status(400).json({ error: '缺少角色卡 UUID' });

    const dup = db.prepare('SELECT id, status, author_id FROM library_cards WHERE uuid = ?').get(finalUuid);
    if (dup) {
      // Same author can resubmit to update pending/rejected card
      if (dup.author_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(409).json({ error: '该 UUID 已存在角色卡' });
      }
      db.prepare(
        `UPDATE library_cards SET name=?, description=?, tags=?, card_json=?, status='pending', review_note='', updated_at=?
         WHERE id=?`
      ).run(
        (name || card.name || '').toString().slice(0, 128),
        (description || card.description || '').toString().slice(0, 1024),
        parseTags(tags || card.tags),
        cardStr,
        now(),
        dup.id
      );
      audit(req.user.id, 'library_resubmit', finalUuid, '', req.ip);
      return res.json({ ok: true, id: dup.id, status: 'pending' });
    }

    const info = db.prepare(
      `INSERT INTO library_cards (uuid, author_id, author_name, name, description, tags, card_json, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`
    ).run(
      finalUuid,
      req.user.id,
      req.user.username,
      (name || card.name || '').toString().slice(0, 128),
      (description || card.description || '').toString().slice(0, 1024),
      parseTags(tags || card.tags),
      cardStr,
      now(),
      now()
    );
    audit(req.user.id, 'library_submit', finalUuid, '', req.ip);
    res.json({ ok: true, id: info.lastInsertRowid, status: 'pending' });
  } catch (e) { next(e); }
});

// ---------- Auth required: my submitted cards ----------
router.get('/my/submissions', authRequired, (req, res) => {
  const rows = db.prepare('SELECT * FROM library_cards WHERE author_id = ? ORDER BY updated_at DESC').all(req.user.id);
  res.json({ cards: rows.map(publicCard) });
});

// ---------- Auth required: take down my own approved card ----------
router.delete('/my/:uuid', authRequired, (req, res, next) => {
  try {
    const c = db.prepare('SELECT * FROM library_cards WHERE uuid = ?').get(req.params.uuid);
    if (!c) return res.status(404).json({ error: '角色卡不存在' });
    if (c.author_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: '无权操作他人角色卡' });
    }
    db.prepare('DELETE FROM library_cards WHERE id = ?').run(c.id);
    audit(req.user.id, 'library_delete', c.uuid, c.name, req.ip);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ---------- Admin: pending list ----------
router.get('/admin/pending', adminRequired, (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize || '20', 10)));
  const q = (req.query.q || '').toString();
  const { where, params } = buildAdminLibraryWhere({ status: 'pending', q });
  const total = db.prepare(`SELECT COUNT(*) as c FROM library_cards ${where}`).get(...params).c;
  const rows = db.prepare(
    `SELECT * FROM library_cards ${where} ORDER BY created_at ASC LIMIT ? OFFSET ?`
  ).all(...params, pageSize, (page - 1) * pageSize);
  res.json({ total, page, pageSize, cards: rows.map(publicCard) });
});

// ---------- Admin: review a card ----------
router.post('/admin/review/:id', adminRequired, (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    const { status, note } = req.body || {};
    if (!['approved', 'rejected', 'offline'].includes(status)) {
      return res.status(400).json({ error: '非法的审核状态' });
    }
    const c = db.prepare('SELECT * FROM library_cards WHERE id = ?').get(id);
    if (!c) return res.status(404).json({ error: '角色卡不存在' });
    db.prepare(
      'UPDATE library_cards SET status=?, review_note=?, reviewer_id=?, reviewed_at=?, updated_at=? WHERE id=?'
    ).run(status, (note || '').toString().slice(0, 512), req.user.id, now(), now(), id);
    audit(req.user.id, 'library_review', c.uuid, `${c.status}->${status}:${note || ''}`, req.ip);
    res.json({ ok: true, card: publicCard(db.prepare('SELECT * FROM library_cards WHERE id = ?').get(id)) });
  } catch (e) { next(e); }
});

// ---------- Admin: full card preview ----------
router.get('/admin/card/:id', adminRequired, (req, res, next) => {
  try {
    const c = db.prepare('SELECT * FROM library_cards WHERE id = ?').get(parseInt(req.params.id, 10));
    if (!c) return res.status(404).json({ error: '角色卡不存在' });
    res.json({ card: publicCard(c), data: JSON.parse(c.card_json) });
  } catch (e) { next(e); }
});

// ---------- Admin: delete a card ----------
router.delete('/admin/card/:id', adminRequired, (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    const c = db.prepare('SELECT * FROM library_cards WHERE id = ?').get(id);
    if (!c) return res.status(404).json({ error: '角色卡不存在' });
    db.prepare('DELETE FROM library_cards WHERE id = ?').run(id);
    audit(req.user.id, 'library_admin_delete', c.uuid, c.name || '', req.ip);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ---------- Admin: list all cards (any status) ----------
router.get('/admin/list', adminRequired, (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize || '20', 10)));
  const status = (req.query.status || '').toString();
  const q = (req.query.q || '').toString();
  const { where, params } = buildAdminLibraryWhere({ status, q });
  const total = db.prepare(`SELECT COUNT(*) as c FROM library_cards ${where}`).get(...params).c;
  const rows = db.prepare(
    `SELECT * FROM library_cards ${where} ORDER BY updated_at DESC LIMIT ? OFFSET ?`
  ).all(...params, pageSize, (page - 1) * pageSize);
  res.json({ total, page, pageSize, cards: rows.map(publicCard) });
});

export default router;

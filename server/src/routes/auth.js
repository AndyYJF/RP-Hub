import { Router } from 'express';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import { db, now, audit } from '../db.js';
import { config } from '../config.js';
import { authRequired, authOptional } from '../middleware/auth.js';
import {
  signAccessToken,
  signRefreshToken,
  hashRefreshToken,
  verifyRefreshToken,
} from '../utils/jwt.js';

const router = Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: '登录尝试过于频繁，请稍后再试' },
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: '注册过于频繁，请稍后再试' },
});

function sanitizeUsername(u) {
  return String(u || '').trim().replace(/\s+/g, '_').slice(0, 32);
}

function validPassword(p) {
  return typeof p === 'string' && p.length >= 6 && p.length <= 128;
}

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
  };
}

// ---------- Register ----------
router.post('/register', registerLimiter, (req, res, next) => {
  try {
    if (!config.allowRegister) {
      return res.status(403).json({ error: '管理员已关闭自由注册' });
    }
    const username = sanitizeUsername(req.body.username);
    const password = req.body.password;
    if (!username || username.length < 2) return res.status(400).json({ error: '用户名至少 2 个字符' });
    if (!validPassword(password)) return res.status(400).json({ error: '密码长度需在 6-128 之间' });

    const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (exists) return res.status(409).json({ error: '用户名已被占用' });

    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare(
      `INSERT INTO users (username, password_hash, role, status, created_at) VALUES (?, ?, 'user', 'active', ?)`
    ).run(username, hash, now());

    audit(info.lastInsertRowid, 'register', username, '', req.ip);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);

    const access = signAccessToken(user);
    const refresh = signRefreshToken(user);
    storeRefresh(user.id, refresh);
    res.json({ token: access, refreshToken: refresh, user: publicUser(user) });
  } catch (e) { next(e); }
});

// ---------- Login ----------
router.post('/login', loginLimiter, (req, res, next) => {
  try {
    const username = sanitizeUsername(req.body.username);
    const password = req.body.password;
    if (!username || !password) return res.status(400).json({ error: '请输入用户名和密码' });

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) return res.status(401).json({ error: '用户名或密码错误' });
    if (user.status === 'banned') return res.status(403).json({ error: '账号已被封禁：' + (user.banned_reason || '无') });
    if (user.status === 'disabled') return res.status(403).json({ error: '账号已停用' });

    if (!bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(now(), user.id);
    audit(user.id, 'login', user.username, '', req.ip);

    const access = signAccessToken(user);
    const refresh = signRefreshToken(user);
    storeRefresh(user.id, refresh);
    res.json({ token: access, refreshToken: refresh, user: publicUser(user) });
  } catch (e) { next(e); }
});

// ---------- Refresh ----------
router.post('/refresh', (req, res, next) => {
  try {
    const refresh = req.body.refreshToken;
    if (!refresh) return res.status(400).json({ error: '缺少 refreshToken' });
    const payload = verifyRefreshToken(refresh);
    if (!payload || payload.type !== 'refresh') return res.status(401).json({ error: 'refreshToken 无效' });

    const hash = hashRefreshToken(refresh);
    const stored = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ? AND expires_at > ?').get(hash, now());
    if (!stored) return res.status(401).json({ error: 'refreshToken 已失效' });

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.sub);
    if (!user || user.status !== 'active') return res.status(403).json({ error: '账号不可用' });

    // Rotate: invalidate old, issue new
    db.prepare('DELETE FROM refresh_tokens WHERE id = ?').run(stored.id);
    const access = signAccessToken(user);
    const newRefresh = signRefreshToken(user);
    storeRefresh(user.id, newRefresh);
    res.json({ token: access, refreshToken: newRefresh, user: publicUser(user) });
  } catch (e) { next(e); }
});

// ---------- Logout ----------
router.post('/logout', (req, res) => {
  const refresh = req.body.refreshToken;
  if (refresh) {
    const hash = hashRefreshToken(refresh);
    db.prepare('DELETE FROM refresh_tokens WHERE token_hash = ?').run(hash);
  }
  res.json({ ok: true });
});

// ---------- Me ----------
router.get('/me', authRequired, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: publicUser(user) });
});

// ---------- Update profile (self) ----------
router.patch('/me', authRequired, (req, res, next) => {
  try {
    const { displayName, avatar, password, oldPassword, apiKey } = req.body || {};
    const sets = [];
    const vals = [];
    if (typeof displayName === 'string' && displayName.length <= 64) {
      sets.push('display_name = ?'); vals.push(displayName);
    }
    if (typeof avatar === 'string' && avatar.length < 2 * 1024 * 1024) {
      sets.push('avatar = ?'); vals.push(avatar);
    }
    if (typeof apiKey === 'string' && apiKey.length <= 256) {
      sets.push('api_key = ?'); vals.push(apiKey);
    }
    if (typeof password === 'string' && validPassword(password)) {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
      if (!oldPassword || !bcrypt.compareSync(oldPassword, user.password_hash)) {
        return res.status(400).json({ error: '原密码不正确' });
      }
      sets.push('password_hash = ?'); vals.push(bcrypt.hashSync(password, 10));
      // Invalidate all refresh tokens on password change
      db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').run(req.user.id);
    }
    if (!sets.length) return res.json({ ok: true });
    vals.push(req.user.id);
    db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
    audit(req.user.id, 'update_profile', req.user.username, sets.join(','), req.ip);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    res.json({ ok: true, user: publicUser(user) });
  } catch (e) { next(e); }
});

// ---------- Helper: store refresh token ----------
function storeRefresh(userId, token) {
  const hash = hashRefreshToken(token);
  const payload = verifyRefreshToken(token);
  const expiresAt = payload ? payload.exp * 1000 : now() + 30 * 24 * 3600 * 1000;
  // Limit to 5 refresh tokens per user
  const count = db.prepare('SELECT COUNT(*) as c FROM refresh_tokens WHERE user_id = ?').get(userId).c;
  if (count >= 5) {
    // node:sqlite doesn't support DELETE ... ORDER BY ... LIMIT, use subquery instead
    const oldIds = db.prepare('SELECT id FROM refresh_tokens WHERE user_id = ? ORDER BY created_at ASC LIMIT ?').all(userId, count - 4);
    for (const row of oldIds) {
      db.prepare('DELETE FROM refresh_tokens WHERE id = ?').run(row.id);
    }
  }
  db.prepare(
    'INSERT INTO refresh_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)'
  ).run(userId, hash, expiresAt, now());
}

export default router;

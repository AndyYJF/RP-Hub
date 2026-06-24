import { verifyAccessToken } from '../utils/jwt.js';
import { db } from '../db.js';

export function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ error: '未登录' });
  const payload = verifyAccessToken(token);
  if (!payload) return res.status(401).json({ error: 'token 无效或已过期' });

  const user = db.prepare('SELECT id, username, role, status FROM users WHERE id = ?').get(payload.sub);
  if (!user) return res.status(401).json({ error: '用户不存在' });
  if (user.status === 'banned') return res.status(403).json({ error: '账号已被封禁' });
  if (user.status === 'disabled') return res.status(403).json({ error: '账号已停用' });

  req.user = { id: user.id, username: user.username, role: user.role };
  next();
}

export function adminRequired(req, res, next) {
  authRequired(req, res, (err) => {
    if (err) return next(err);
    if (req.user.role !== 'admin') return res.status(403).json({ error: '需要管理员权限' });
    next();
  });
}

// Optional auth: attaches req.user if token valid, but does not reject
export function authOptional(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (token) {
    const payload = verifyAccessToken(token);
    if (payload) {
      const user = db.prepare('SELECT id, username, role, status FROM users WHERE id = ?').get(payload.sub);
      if (user && user.status === 'active') {
        req.user = { id: user.id, username: user.username, role: user.role };
      }
    }
  }
  next();
}

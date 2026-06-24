import { Router } from 'express';
import { db, now } from '../db.js';
import { authOptional } from '../middleware/auth.js';

const router = Router();

// Public: list active announcements (newest first)
router.get('/', (req, res) => {
  const rows = db.prepare(
    `SELECT id, title, content, type, pinned, created_at, updated_at, expires_at
     FROM announcements WHERE active = 1 AND (expires_at IS NULL OR expires_at > ?)
     ORDER BY pinned DESC, created_at DESC LIMIT 50`
  ).all(now());
  res.json({ announcements: rows });
});

export default router;

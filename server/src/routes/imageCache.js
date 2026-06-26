import express, { Router } from 'express';
import fs from 'fs/promises';
import path from 'path';
import { config } from '../config.js';
import { authRequired } from '../middleware/auth.js';

const router = Router();
const MAX_IMAGE_CACHE_SIZE = 16 * 1024 * 1024;
const CACHE_KEY_RE = /^[A-Za-z0-9._-]{8,180}$/;
const CACHE_ROOT = path.resolve(path.dirname(config.dbPath), 'image-cache');

router.use(authRequired);

function assertCacheKey(key) {
  if (!CACHE_KEY_RE.test(String(key || ''))) {
    const err = new Error('无效的图片缓存 key');
    err.status = 400;
    throw err;
  }
  return String(key);
}

function userCacheDir(userId) {
  return path.join(CACHE_ROOT, String(userId));
}

function imagePath(userId, key) {
  return path.join(userCacheDir(userId), `${key}.bin`);
}

function metaPath(userId, key) {
  return path.join(userCacheDir(userId), `${key}.json`);
}

function detectImageMime(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 8) return '';
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) return 'image/png';
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return 'image/jpeg';
  if (buffer.slice(0, 4).toString('ascii') === 'RIFF' && buffer.slice(8, 12).toString('ascii') === 'WEBP') return 'image/webp';
  if (buffer.slice(0, 6).toString('ascii') === 'GIF87a' || buffer.slice(0, 6).toString('ascii') === 'GIF89a') return 'image/gif';
  return '';
}

function normalizeImageMime(value) {
  const mime = String(value || '').split(';')[0].trim().toLowerCase();
  return ['image/png', 'image/jpeg', 'image/webp', 'image/gif'].includes(mime) ? mime : '';
}

async function readMeta(userId, key) {
  try {
    return JSON.parse(await fs.readFile(metaPath(userId, key), 'utf8'));
  } catch (_) {
    return null;
  }
}

router.put(
  '/:key',
  express.raw({ type: '*/*', limit: MAX_IMAGE_CACHE_SIZE }),
  async (req, res, next) => {
    try {
      const key = assertCacheKey(req.params.key);
      const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      if (!body.length) return res.status(400).json({ error: '图片缓存内容为空' });
      if (body.length > MAX_IMAGE_CACHE_SIZE) return res.status(413).json({ error: '图片缓存超过 16MB 限制' });

      const detectedMime = detectImageMime(body);
      const mimeType = detectedMime || normalizeImageMime(req.headers['content-type']);
      if (!mimeType) return res.status(400).json({ error: '仅支持 png/jpeg/webp/gif 图片缓存' });

      const dir = userCacheDir(req.user.id);
      await fs.mkdir(dir, { recursive: true });
      const finalImagePath = imagePath(req.user.id, key);
      const finalMetaPath = metaPath(req.user.id, key);
      const tmpImagePath = `${finalImagePath}.${process.pid}.${Date.now()}.tmp`;
      const tmpMetaPath = `${finalMetaPath}.${process.pid}.${Date.now()}.tmp`;
      const now = Date.now();
      const meta = {
        key,
        userId: req.user.id,
        mimeType,
        size: body.length,
        updatedAt: now,
      };

      await fs.writeFile(tmpImagePath, body);
      await fs.writeFile(tmpMetaPath, JSON.stringify(meta));
      await fs.rename(tmpImagePath, finalImagePath);
      await fs.rename(tmpMetaPath, finalMetaPath);

      res.json({ ok: true, key, size: body.length, mimeType, updatedAt: now });
    } catch (e) {
      next(e);
    }
  }
);

router.head('/:key', async (req, res, next) => {
  try {
    const key = assertCacheKey(req.params.key);
    const meta = await readMeta(req.user.id, key);
    if (!meta && req.query.optional === '1') return res.status(204).end();
    if (!meta) return res.status(404).end();
    res.setHeader('Content-Type', meta.mimeType || 'application/octet-stream');
    res.setHeader('Content-Length', String(meta.size || 0));
    res.setHeader('Cache-Control', 'private, max-age=31536000, immutable');
    res.end();
  } catch (e) {
    next(e);
  }
});

router.get('/:key', async (req, res, next) => {
  try {
    const key = assertCacheKey(req.params.key);
    const meta = await readMeta(req.user.id, key);
    if (!meta && req.query.optional === '1') return res.status(204).end();
    if (!meta) return res.status(404).json({ error: '图片缓存不存在' });
    const file = imagePath(req.user.id, key);
    res.setHeader('Content-Type', meta.mimeType || 'application/octet-stream');
    res.setHeader('Content-Length', String(meta.size || 0));
    res.setHeader('Cache-Control', 'private, max-age=31536000, immutable');
    res.sendFile(file);
  } catch (e) {
    next(e);
  }
});

router.delete('/:key', async (req, res, next) => {
  try {
    const key = assertCacheKey(req.params.key);
    await fs.rm(imagePath(req.user.id, key), { force: true });
    await fs.rm(metaPath(req.user.id, key), { force: true });
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

export default router;

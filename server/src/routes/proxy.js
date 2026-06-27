import { Router } from 'express';
import { authRequired } from '../middleware/auth.js';
import { proxyLimiter } from '../middleware/proxyLimiter.js';
import { assertSafeProxyUrl, safeProxyFetch } from '../utils/safeUrl.js';

const router = Router();
router.use(authRequired);
router.use(proxyLimiter);

const normalizeStreamLine = (line) => {
  const trimmed = String(line || '').trim();
  return trimmed.startsWith('data:') ? trimmed.slice(5).trim() : trimmed;
};

const isImageValue = (value) => {
  const trimmed = String(value || '').trim();
  return /^data:image\//i.test(trimmed)
    || /^https?:\/\//i.test(trimmed)
    || /^\/\//.test(trimmed)
    || /^(?:\/(?!\/)|\.{1,2}\/)/.test(trimmed)
    || /^[A-Za-z0-9+/=]{120,}$/.test(trimmed);
};

const findImageValue = (value, seen = new Set()) => {
  if (typeof value === 'string') return isImageValue(value) ? value.trim() : '';
  if (!value || typeof value !== 'object' || seen.has(value)) return '';
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findImageValue(item, seen);
      if (found) return found;
    }
    return '';
  }
  const preferredKeys = ['url', 'urls', 'image', 'images', 'image_url', 'imageUrl', 'download_url', 'downloadUrl', 'file', 'path', 'data', 'output', 'result', 'base64', 'b64_json'];
  for (const key of preferredKeys) {
    if (Object.prototype.hasOwnProperty.call(value, key)) {
      const found = findImageValue(value[key], seen);
      if (found) return found;
    }
  }
  for (const item of Object.values(value)) {
    const found = findImageValue(item, seen);
    if (found) return found;
  }
  return '';
};

const getImageValueFromSuccessPayload = (obj) => {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return '';
  const status = String(obj.status || obj.state || obj.type || '').toLowerCase();
  const isSuccess = obj.success === true || ['success', 'succeeded', 'done', 'completed', 'complete'].includes(status);
  return isSuccess ? findImageValue(obj) : '';
};

const sendImageValue = async ({ imageValue, targetUrl, token, res }) => {
  const trimmed = String(imageValue || '').trim();
  const dataUrlMatch = trimmed.match(/^data:(image\/[^;]+);base64,(.*)$/is);
  if (dataUrlMatch) {
    res.setHeader('Content-Type', dataUrlMatch[1]);
    res.setHeader('Cache-Control', 'no-store');
    return res.send(Buffer.from(dataUrlMatch[2].replace(/\s+/g, ''), 'base64'));
  }

  if (/^[A-Za-z0-9+/=]{120,}$/.test(trimmed)) {
    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'no-store');
    return res.send(Buffer.from(trimmed.replace(/\s+/g, ''), 'base64'));
  }

  const resolved = /^https?:\/\//i.test(trimmed) ? trimmed : new URL(trimmed, targetUrl).href;
  const imgUrl = assertSafeProxyUrl(resolved);

  console.log('[NAI Proxy] downloading image:', imgUrl);
  const imgResp = await safeProxyFetch(imgUrl, {
    headers: { 'Authorization': `Bearer ${token}` },
  });

  if (!imgResp.ok) {
    const errText = await imgResp.text().catch(() => '');
    return res.status(imgResp.status).json({
      error: `下载生图失败 ${imgResp.status}`,
      detail: errText.slice(0, 300),
    });
  }

  const imgContentType = imgResp.headers.get('content-type') || 'image/png';
  const imgBuf = Buffer.from(await imgResp.arrayBuffer());
  res.setHeader('Content-Type', imgContentType);
  res.setHeader('Cache-Control', 'no-store');
  return res.send(imgBuf);
};

// POST /api/proxy/nai-generate
router.post('/nai-generate', async (req, res, next) => {
  try {
    const { targetUrl, token, body } = req.body || {};
    if (!targetUrl || !token || !body) {
      return res.status(400).json({ error: '缺少 targetUrl / token / body' });
    }
    const safeTargetUrl = assertSafeProxyUrl(targetUrl);

    const upstream = await safeProxyFetch(safeTargetUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    const contentType = (upstream.headers.get('content-type') || '').toLowerCase();

    if (!upstream.ok) {
      const errText = await upstream.text().catch(() => '');
      console.error('[NAI Proxy] upstream error:', upstream.status, errText.slice(0, 200));
      return res.status(upstream.status).json({
        error: `生图 API 返回 ${upstream.status}`,
        detail: errText.slice(0, 500),
      });
    }

    if (contentType.startsWith('image/') || contentType.includes('octet-stream') || contentType.includes('zip')) {
      const buf = Buffer.from(await upstream.arrayBuffer());
      res.setHeader('Content-Type', contentType);
      res.setHeader('Cache-Control', 'no-store');
      return res.send(buf);
    }

    const text = await upstream.text();
    const lines = text.split(/\r?\n/)
      .map(normalizeStreamLine)
      .filter(line => line && line !== '[DONE]' && !/^(event|id|retry):/i.test(line));
    let successImageValue = null;

    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        const imageValue = getImageValueFromSuccessPayload(obj);
        if (imageValue) {
          successImageValue = imageValue;
          break;
        }
      } catch (_) {}
    }

    if (successImageValue) {
      return sendImageValue({ imageValue: successImageValue, targetUrl: safeTargetUrl, token, res });
    }
    res.setHeader('Content-Type', 'application/x-ndjson');
    res.setHeader('Cache-Control', 'no-store');
    return res.send(text);
  } catch (e) {
    console.error('NAI proxy error:', e);
    next(e);
  }
});

export default router;

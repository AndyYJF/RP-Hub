import { Router } from 'express';
import { authRequired } from '../middleware/auth.js';
import { audit } from '../db.js';

const router = Router();
router.use(authRequired);

// POST /api/proxy/nai-generate
// 前端把目标 URL、token、请求体发给后端，后端转发到 NovelAI API 并返回结果
// 解决浏览器跨域 CORS 限制
router.post('/nai-generate', async (req, res, next) => {
  try {
    const { targetUrl, token, body } = req.body || {};
    console.log('[NAI Proxy] targetUrl:', targetUrl, 'token:', token ? token.slice(0, 6) + '***' : '(empty)');
    if (!targetUrl || !token || !body) {
      return res.status(400).json({ error: '缺少 targetUrl / token / body' });
    }
    // 安全检查：只允许 http/https URL
    if (!/^https?:\/\//i.test(targetUrl)) {
      return res.status(400).json({ error: '目标 URL 必须是 http/https' });
    }

    const upstream = await fetch(targetUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!upstream.ok) {
      const errText = await upstream.text().catch(() => '');
      return res.status(upstream.status).json({
        error: `生图 API 返回 ${upstream.status}`,
        detail: errText.slice(0, 500),
      });
    }

    // NovelAI 返回 zip（二进制），直接透传
    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    const arrayBuffer = await upstream.arrayBuffer();
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'no-store');
    res.send(Buffer.from(arrayBuffer));
  } catch (e) {
    console.error('NAI proxy error:', e);
    next(e);
  }
});

export default router;

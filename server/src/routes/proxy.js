import { Router } from 'express';
import { authOptional } from '../middleware/auth.js';

const router = Router();
router.use(authOptional);

// POST /api/proxy/nai-generate
// 代理前端到生图 API 的请求，解决浏览器跨域 CORS 限制
// 支持两种响应模式：
//   1. 直接返回图片二进制（标准 NovelAI zip/png）
//   2. NDJSON 流式：排队 → 生成中 → success + url → 再下载图片
router.post('/nai-generate', async (req, res, next) => {
  try {
    const { targetUrl, token, body } = req.body || {};
    if (!targetUrl || !token || !body) {
      return res.status(400).json({ error: '缺少 targetUrl / token / body' });
    }
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

    const contentType = (upstream.headers.get('content-type') || '').toLowerCase();

    if (!upstream.ok) {
      const errText = await upstream.text().catch(() => '');
      console.error('[NAI Proxy] upstream error:', upstream.status, errText.slice(0, 200));
      return res.status(upstream.status).json({
        error: `生图 API 返回 ${upstream.status}`,
        detail: errText.slice(0, 500),
      });
    }

    // 模式 1：直接返回图片二进制（content-type 是 image/* 或 application/zip 等）
    if (contentType.startsWith('image/') || contentType.includes('octet-stream') || contentType.includes('zip')) {
      const buf = Buffer.from(await upstream.arrayBuffer());
      res.setHeader('Content-Type', contentType);
      res.setHeader('Cache-Control', 'no-store');
      return res.send(buf);
    }

    // 模式 2：NDJSON 流式 — 读取全部行，找到 success 行里的 url，再下载图片
    const text = await upstream.text();
    const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
    let successUrl = null;
    let lastStatus = null;

    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        lastStatus = obj;
        if (obj.status === 'success' && obj.url) {
          successUrl = obj.url;
          break;
        }
      } catch (_) {}
    }

    if (successUrl) {
      // 下载图片：url 是相对路径如 /img/xxx.png，需要拼接 origin
      const imgUrl = successUrl.startsWith('http')
        ? successUrl
        : new URL(successUrl, targetUrl).href;

      console.log('[NAI Proxy] downloading image:', imgUrl);
      const imgResp = await fetch(imgUrl, {
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
    }

    // 没有 success，返回最后的 NDJSON 状态（可能是排队/失败）
    res.setHeader('Content-Type', 'application/x-ndjson');
    res.setHeader('Cache-Control', 'no-store');
    return res.send(text);
  } catch (e) {
    console.error('NAI proxy error:', e);
    next(e);
  }
});

export default router;

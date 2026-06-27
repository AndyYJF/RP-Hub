import { Router } from 'express';
import { authRequired } from '../middleware/auth.js';
import { proxyLimiter } from '../middleware/proxyLimiter.js';
import { db, now } from '../db.js';
import { assertSafeProxyUrl } from '../utils/safeUrl.js';
import { assertApiQuota } from '../utils/proxyQuota.js';

const router = Router();
router.use(authRequired);
router.use(proxyLimiter);

const MAX_STREAM_ESTIMATE_CHARS = 500_000;

// POST /api/proxy/chat
router.post('/chat', async (req, res, next) => {
  try {
    const { targetUrl, apiKey, ...chatBody } = req.body || {};
    if (!targetUrl || !apiKey) {
      return res.status(400).json({ error: '缺少 targetUrl / apiKey' });
    }
    assertApiQuota(req.user.id);
    const safeTargetUrl = assertSafeProxyUrl(targetUrl);

    const userId = req.user.id;
    const upstream = await fetch(safeTargetUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(chatBody),
    });

    if (!upstream.ok) {
      const errText = await upstream.text().catch(() => '');
      return res.status(upstream.status).json({
        error: `AI API 返回 ${upstream.status}`,
        detail: errText.slice(0, 1000),
      });
    }

    const contentType = upstream.headers.get('content-type') || '';
    const isStream = contentType.includes('text/event-stream');

    if (isStream) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');

      const reader = upstream.body.getReader();
      const decoder = new TextDecoder();
      let usage = null;
      let totalContent = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value, { stream: true });
        if (totalContent.length < MAX_STREAM_ESTIMATE_CHARS) {
          const remaining = MAX_STREAM_ESTIMATE_CHARS - totalContent.length;
          totalContent += chunk.slice(0, remaining);
        }
        res.write(chunk);
        for (const line of chunk.split('\n')) {
          if (!line.startsWith('data: ') || line.includes('[DONE]')) continue;
          try {
            const data = JSON.parse(line.slice(6));
            if (data.usage) usage = data.usage;
          } catch (_) {}
        }
      }
      res.end();

      if (usage) {
        recordApiUsage(userId, chatBody.model || '', safeTargetUrl, usage);
      } else {
        const estimated = estimateTokens(totalContent, chatBody.messages);
        recordApiUsage(userId, chatBody.model || '', safeTargetUrl, estimated, true);
      }
    } else {
      const text = await upstream.text();
      res.setHeader('Content-Type', contentType || 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.send(text);

      try {
        const data = JSON.parse(text);
        if (data.usage) {
          recordApiUsage(userId, chatBody.model || data.model || '', safeTargetUrl, data.usage);
        }
      } catch (_) {}
    }
  } catch (e) {
    console.error('Chat proxy error:', e);
    next(e);
  }
});

function recordApiUsage(userId, model, endpoint, usage, isEstimated = false) {
  try {
    const promptTokens = Number(usage.prompt_tokens || usage.prompt || 0) || 0;
    const completionTokens = Number(usage.completion_tokens || usage.completion || 0) || 0;
    const totalTokens = Number(usage.total_tokens || (promptTokens + completionTokens)) || 0;
    if (totalTokens === 0) return;
    db.prepare(
      'INSERT INTO api_usage (user_id, endpoint, model, prompt_tokens, completion_tokens, total_tokens, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(userId, String(endpoint).slice(0, 200), String(model).slice(0, 100),
      promptTokens, completionTokens, totalTokens, now());
  } catch (e) {
    console.error('recordApiUsage failed:', e);
  }
}

function estimateTokens(responseText, messages) {
  const outputChars = responseText.length;
  const inputChars = JSON.stringify(messages || []).length;
  return {
    prompt_tokens: Math.max(1, Math.round(inputChars / 4)),
    completion_tokens: Math.max(1, Math.round(outputChars / 4)),
    total_tokens: Math.max(2, Math.round((inputChars + outputChars) / 4)),
  };
}

export default router;

import { Router } from 'express';
import { authRequired } from '../middleware/auth.js';
import { db, now, audit } from '../db.js';

const router = Router();
router.use(authRequired);

// POST /api/proxy/chat
// 代理前端到 AI API 的对话请求，记录 token 用量
// 前端发: { targetUrl, apiKey, model, messages, temperature, stream, ... }
// 后端转发到 targetUrl，解析 usage，记录到 api_usage 表
router.post('/chat', async (req, res, next) => {
  try {
    const { targetUrl, apiKey, ...chatBody } = req.body || {};
    if (!targetUrl || !apiKey) {
      return res.status(400).json({ error: '缺少 targetUrl / apiKey' });
    }
    if (!/^https?:\/\//i.test(targetUrl)) {
      return res.status(400).json({ error: '目标 URL 必须是 http/https' });
    }

    const userId = req.user.id;
    const upstream = await fetch(targetUrl, {
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
      // 流式：透传 SSE，同时解析 usage（在最后一个 data: [DONE] 前的 chunk 里）
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
        totalContent += chunk;
        // 透传给前端
        res.write(chunk);
        // 尝试从 chunk 里提取 usage
        for (const line of chunk.split('\n')) {
          if (!line.startsWith('data: ') || line.includes('[DONE]')) continue;
          try {
            const data = JSON.parse(line.slice(6));
            if (data.usage) usage = data.usage;
          } catch (_) {}
        }
      }
      res.end();

      // 记录用量
      if (usage) {
        recordApiUsage(userId, chatBody.model || '', targetUrl, usage);
      } else {
        // 流式无 usage，估算（粗略：输入字符数/4 + 输出字符数/4）
        const estimated = estimateTokens(totalContent, chatBody.messages);
        recordApiUsage(userId, chatBody.model || '', targetUrl, estimated, true);
      }
    } else {
      // 非流式：读取完整响应，解析 usage，返回给前端
      const text = await upstream.text();
      res.setHeader('Content-Type', contentType || 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.send(text);

      // 解析 usage
      try {
        const data = JSON.parse(text);
        if (data.usage) {
          recordApiUsage(userId, chatBody.model || data.model || '', targetUrl, data.usage);
        }
      } catch (_) {}
    }
  } catch (e) {
    console.error('Chat proxy error:', e);
    next(e);
  }
});

// 写入 api_usage 表
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

// 粗略估算 token 数（无 usage 时的后备）
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

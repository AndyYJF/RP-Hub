import rateLimit from 'express-rate-limit';

export const proxyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: '代理请求过于频繁，请稍后再试' },
});

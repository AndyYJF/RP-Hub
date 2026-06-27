import { config } from '../config.js';

const INSECURE_JWT_SECRETS = new Set([
  'dev-secret-please-change',
  'please-change-to-a-long-random-string-at-least-32-chars',
  'please-change-to-a-long-random-string',
]);

const INSECURE_REFRESH_SECRETS = new Set([
  'dev-refresh-secret-please-change',
  'please-change-this-too',
  'replace-with-another-long-random-string',
]);

const INSECURE_ADMIN_PASSWORDS = new Set([
  'please-change-immediately',
  'ChangeMeOnFirstLogin!',
]);

export function validateProductionConfig() {
  if (process.env.NODE_ENV !== 'production') return;

  const errors = [];
  if (INSECURE_JWT_SECRETS.has(config.jwtSecret) || config.jwtSecret.length < 32) {
    errors.push('JWT_SECRET 必须为至少 32 字符的随机字符串');
  }
  if (INSECURE_REFRESH_SECRETS.has(config.jwtRefreshSecret) || config.jwtRefreshSecret.length < 32) {
    errors.push('JWT_REFRESH_SECRET 必须为至少 32 字符的随机字符串');
  }
  if (INSECURE_ADMIN_PASSWORDS.has(config.adminPassword)) {
    errors.push('ADMIN_PASSWORD 不能使用默认值');
  }
  if (config.corsOrigin === '*') {
    console.warn('[WARN] 生产环境 CORS_ORIGIN 为 *，建议设为具体前端域名');
  }
  if (errors.length) {
    throw new Error(`生产环境配置不安全：\n- ${errors.join('\n- ')}`);
  }
}
